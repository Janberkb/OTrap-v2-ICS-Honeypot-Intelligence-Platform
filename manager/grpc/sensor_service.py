"""
manager/grpc/sensor_service.py — gRPC SensorService implementation.

This is the Manager-side implementation of the SensorService proto.
It handles:
  - Join: token validation, cert issuance, sensor registration
  - EventStream: long-lived bidirectional stream, events → Redis pub/sub
  - Heartbeat: sensor health tracking
  - SyncMemoryWrite: S7 DB memory forensic recording
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator

import grpc
from sqlalchemy.ext.asyncio import AsyncSession

from manager.db.engine import get_db_session
from manager.db import models
from manager.grpc import sensor_pb2, sensor_pb2_grpc
from manager.grpc.ca import CertificateAuthority
from manager.security.hashing import verify_bcrypt, hash_bcrypt

logger = logging.getLogger("otrap.grpc.sensor_service")


class SensorServicer(sensor_pb2_grpc.SensorServiceServicer):
    """
    Implements the SensorService gRPC contract.

    All RPCs are async (using grpc.aio).
    """

    def __init__(
        self,
        ca: CertificateAuthority,
        redis_client,
        db_session_factory,
    ) -> None:
        self._ca = ca
        self._redis = redis_client
        self._db_factory = db_session_factory

    # ── Join ──────────────────────────────────────────────────────────────────

    async def Join(
        self,
        request: sensor_pb2.JoinRequest,
        context: grpc.aio.ServicerContext,
    ) -> sensor_pb2.JoinResponse:
        """
        Validate join token, issue mTLS cert, register sensor.

        Security:
        - Token is bcrypt-hashed in DB; single-use (nulled after join).
        - Token has a time-limited TTL checked here.
        - Cert CN encodes sensor_id for audit traceability.
        """
        if not request.join_token:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "join_token required")
            return sensor_pb2.JoinResponse()

        async with self._db_factory() as session:
            # Find a matching pending sensor
            sensor = await models.Sensor.find_by_token_candidate(
                session, request.join_token
            )
            if sensor is None:
                logger.warning(
                    "Join attempt with unknown token",
                    extra={"token_prefix": request.join_token[:8]},
                )
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid_token")
                return sensor_pb2.JoinResponse()

            # Check TTL
            if sensor.token_expires_at:
                expires_at = sensor.token_expires_at
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                if expires_at < datetime.now(timezone.utc):
                    logger.warning("Join attempt with expired token", extra={"sensor_id": str(sensor.id)})
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "token_expired")
                    return sensor_pb2.JoinResponse()

            # Issue client certificate
            cert_pem, key_pem = self._ca.issue_sensor_cert(str(sensor.id))
            ca_cert_pem = self._ca.get_ca_cert_pem()

            # Update sensor record: consume token, store cert ref, mark active
            sensor.join_token_hash = None
            sensor.token_expires_at = None
            sensor.name = request.sensor_name or sensor.name
            sensor.version = request.version
            sensor.capabilities = list(request.capabilities)
            sensor.status = "active"
            sensor.client_cert_pem = cert_pem.decode()
            sensor.last_seen_at = datetime.now(timezone.utc).isoformat()

            # Attempt to resolve reported IP from gRPC peer
            peer = context.peer()
            if peer:
                try:
                    ip = peer.split(":")[1] if peer.startswith("ipv4:") else peer
                    from ipaddress import ip_address
                    sensor.reported_ip = str(ip_address(ip.split(":")[0]))
                except Exception:
                    pass

            await session.commit()

        # Build default sensor config from Manager settings
        config = self._build_sensor_config()

        logger.info(
            "Sensor joined successfully",
            extra={
                "sensor_id": str(sensor.id),
                "sensor_name": sensor.name,
                "version": sensor.version,
            },
        )

        # Write initial health record so the sensor appears online immediately
        # (before the first Heartbeat RPC arrives ~30s later).
        initial_health = {
            "sensor_id": str(sensor.id),
            "events_buffered": 0,
            "events_sent_total": 0,
            "cpu_percent": 0.0,
            "mem_bytes_rss": 0,
            "port_status": [],
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        }
        await self._redis.setex(
            f"sensor.health:{str(sensor.id)}", 90, json.dumps(initial_health)
        )

        # Publish sensor join event to Redis for SSE broadcast
        await self._redis.publish(
            "sse.broadcast",
            json.dumps({
                "type": "health_update",
                "data": {
                    "sensor_id": str(sensor.id),
                    "name": sensor.name,
                    "status": "active",
                    "event": "joined",
                },
            }),
        )

        return sensor_pb2.JoinResponse(
            sensor_id=str(sensor.id),
            client_cert_pem=cert_pem,
            client_key_pem=key_pem,
            ca_cert_pem=ca_cert_pem,
            config=config,
        )

    # ── EventStream ───────────────────────────────────────────────────────────

    async def EventStream(
        self,
        request_iterator: AsyncIterator[sensor_pb2.SensorEvent],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[sensor_pb2.ManagerCommand]:
        """
        Long-lived bidirectional stream.

        Sensor sends SensorEvent messages continuously.
        Manager sends ManagerCommand messages back (config updates, pings, acks).

        Events are published to Redis pub/sub channel 'sensor.events'
        where the Analyzer worker consumes them.
        """
        sensor_id: str | None = None
        events_received = 0

        # Authenticate at stream-open time using gRPC metadata header.
        # This ensures sensor_id is known even when no events flow (idle sensors).
        sensor_id = await self._authenticate_from_metadata(context)
        if sensor_id is not None:
            logger.info("EventStream opened", extra={"sensor_id": sensor_id})
            asyncio.get_event_loop().create_task(
                self._log_sensor_state(sensor_id, "sensor_online", {})
            )

        try:
            async for event in request_iterator:
                if context.cancelled():
                    break

                if sensor_id is None:
                    # Insecure/no-cert fallback: authenticate from first event
                    sensor_id = await self._authenticate_sensor(
                        context,
                        claimed_sensor_id=event.sensor_id,
                    )
                    if sensor_id is None:
                        return
                    logger.info("EventStream opened (fallback)", extra={"sensor_id": sensor_id})
                    asyncio.get_event_loop().create_task(
                        self._log_sensor_state(sensor_id, "sensor_online", {})
                    )

                # Validate sensor_id matches authenticated identity
                if event.sensor_id != sensor_id:
                    logger.warning(
                        "Sensor sent event with mismatched sensor_id",
                        extra={"authenticated": sensor_id, "claimed": event.sensor_id},
                    )
                    continue

                events_received += 1

                # Serialize and publish to Redis
                event_payload = self._serialize_event(event)
                await self._redis.publish("sensor.events", json.dumps(event_payload))

                # Send ACK back to sensor
                yield sensor_pb2.ManagerCommand(
                    ack=sensor_pb2.AckCommand(event_id=event.event_id)
                )

                # Periodically send ping to keep stream alive
                if events_received % 100 == 0:
                    yield sensor_pb2.ManagerCommand(
                        ping=sensor_pb2.PingCommand(nonce=uuid.uuid4().hex)
                    )
        except Exception:
            pass  # stream closed by peer or cancelled — handled in finally
        finally:
            logger.info(
                "EventStream closed",
                extra={"sensor_id": sensor_id, "events_received": events_received},
            )
            if sensor_id is not None:
                # create_task (not await): finally runs in a cancelled Task context,
                # so any await raises CancelledError before the coroutine body starts.
                # An independent Task is unaffected by the parent's cancellation.
                asyncio.get_event_loop().create_task(
                    self._update_sensor_offline(sensor_id)
                )

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    async def Heartbeat(
        self,
        request: sensor_pb2.HeartbeatRequest,
        context: grpc.aio.ServicerContext,
    ) -> sensor_pb2.HeartbeatResponse:
        """
        Update sensor health state in Redis (TTL = 90s).
        """
        sensor_id = await self._authenticate_sensor(
            context,
            claimed_sensor_id=request.sensor_id,
        )
        if sensor_id is None:
            return sensor_pb2.HeartbeatResponse(ok=False, message="unauthenticated")

        if request.sensor_id != sensor_id:
            return sensor_pb2.HeartbeatResponse(ok=False, message="sensor_id_mismatch")

        # Store health in Redis with TTL
        health_key = f"sensor.health:{sensor_id}"
        health_data = {
            "sensor_id": sensor_id,
            "events_buffered": request.events_buffered,
            "events_sent_total": request.events_sent_total,
            "cpu_percent": request.cpu_percent,
            "mem_bytes_rss": request.mem_bytes_rss,
            "port_status": [
                {
                    "port": ps.port,
                    "listening": ps.listening,
                    "active_conns": ps.active_conns,
                    "total_conns": ps.total_conns,
                }
                for ps in request.port_status
            ],
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        }
        await self._redis.setex(health_key, 45, json.dumps(health_data))

        # Update DB last_seen_at (debounced — once per minute via Redis flag)
        db_update_key = f"sensor.db_update_flag:{sensor_id}"
        if not await self._redis.exists(db_update_key):
            await self._redis.setex(db_update_key, 60, "1")
            asyncio.create_task(self._update_sensor_last_seen(sensor_id))

        # Broadcast health update for SSE
        await self._redis.publish(
            "sse.broadcast",
            json.dumps({
                "type": "health_update",
                "data": {
                    "sensor_id": sensor_id,
                    "cpu_percent": request.cpu_percent,
                    "mem_bytes_rss": request.mem_bytes_rss,
                    "port_status": health_data["port_status"],
                },
            }),
        )

        return sensor_pb2.HeartbeatResponse(
            ok=True,
            server_time_unix=int(time.time()),
        )

    # ── SyncMemoryWrite ───────────────────────────────────────────────────────

    async def SyncMemoryWrite(
        self,
        request: sensor_pb2.MemoryWriteRequest,
        context: grpc.aio.ServicerContext,
    ) -> sensor_pb2.MemoryWriteResponse:
        """
        Record S7 Data Block writes for forensic analysis.
        """
        sensor_id = await self._authenticate_sensor(
            context,
            claimed_sensor_id=request.sensor_id,
        )
        if sensor_id is None:
            return sensor_pb2.MemoryWriteResponse(ok=False)

        async with self._db_factory() as session:
            # Upsert: if same sensor+db+offset was written before, update it
            await models.S7MemoryBlock.upsert(
                session,
                sensor_id=sensor_id,
                session_hint=request.session_id,
                db_number=request.db_number,
                byte_offset=request.byte_offset,
                value_hex=request.value.hex(),
            )
            await session.commit()

        return sensor_pb2.MemoryWriteResponse(ok=True)

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _authenticate_sensor(
        self,
        context: grpc.aio.ServicerContext,
        claimed_sensor_id: str | None = None,
    ) -> str | None:
        """
        Extract and validate sensor_id from the mTLS client certificate.

        The CN of the client cert is "sensor-{uuid}". We verify the sensor
        exists and is active in the DB.

        grpc.aio on Python does not expose the client certificate to the
        application when client auth is disabled. We keep Join on the same
        port by accepting a claimed sensor_id only when the cert is absent,
        then verifying that sensor is already active in storage.
        """
        # Extract cert from gRPC peer metadata
        auth_context = context.auth_context()
        peer_common_name = auth_context.get("x509_common_name", [])
        peer_cert_chain = auth_context.get("x509_pem_cert", [])

        try:
            if peer_common_name:
                raw_cn = peer_common_name[0]
                cn = raw_cn.decode() if isinstance(raw_cn, bytes) else str(raw_cn)
            elif peer_cert_chain:
                from cryptography import x509 as cx509
                cert = cx509.load_pem_x509_certificate(peer_cert_chain[0])
                cn = cert.subject.get_attributes_for_oid(
                    cx509.oid.NameOID.COMMON_NAME
                )[0].value  # e.g. "sensor-550e8400-..."
            elif claimed_sensor_id:
                uuid.UUID(claimed_sensor_id)
                sensor_id = claimed_sensor_id
                logger.warning(
                    "Client certificate missing; falling back to claimed sensor_id",
                    extra={"sensor_id": sensor_id},
                )
                return await self._validate_active_sensor(context, sensor_id)
            else:
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client_cert_required")
                return None

            if not cn.startswith("sensor-"):
                raise ValueError("Invalid CN format")

            sensor_id = cn[len("sensor-"):]
            uuid.UUID(sensor_id)  # Validate UUID format
        except grpc.RpcError:
            return None
        except Exception as e:
            logger.warning("Failed to extract sensor_id from cert", extra={"error": str(e)})
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid_client_cert")
            return None

        if claimed_sensor_id and claimed_sensor_id != sensor_id:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "sensor_id_mismatch")
            return None

        return await self._validate_active_sensor(context, sensor_id)

    async def _validate_active_sensor(
        self,
        context: grpc.aio.ServicerContext,
        sensor_id: str,
    ) -> str | None:
        """Ensure the sensor exists and is currently active."""
        # Check sensor is active in DB (cached in Redis)
        cache_key = f"sensor.active:{sensor_id}"
        if await self._redis.exists(cache_key):
            return sensor_id

        async with self._db_factory() as session:
            sensor = await models.Sensor.get_by_id(session, sensor_id)
            if sensor is None or sensor.status != "active":
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, "sensor_not_active")
                return None

        # Cache active status for 5 minutes
        await self._redis.setex(cache_key, 300, "1")
        return sensor_id

    async def _authenticate_from_metadata(
        self,
        context: grpc.aio.ServicerContext,
    ) -> str | None:
        """
        Extract sensor_id from gRPC invocation metadata ('sensor-id' header).

        The Go sensor sends its sensor_id as metadata at stream-open time so
        the manager knows the sensor identity immediately, even when no events
        flow (idle sensor). Returns sensor_id if valid and active, None if the
        header is absent or the sensor is unknown/inactive.
        Never calls context.abort().
        """
        try:
            meta = dict(context.invocation_metadata())
            sensor_id = meta.get("sensor-id")
            if not sensor_id:
                return None
            uuid.UUID(sensor_id)  # Validate format
        except Exception:
            return None

        # Validate sensor is active (uses Redis cache)
        try:
            cache_key = f"sensor.active:{sensor_id}"
            if await self._redis.exists(cache_key):
                return sensor_id

            async with self._db_factory() as session:
                sensor = await models.Sensor.get_by_id(session, sensor_id)
                if sensor is None or sensor.status != "active":
                    return None

            await self._redis.setex(cache_key, 300, "1")
            return sensor_id
        except Exception as e:
            logger.debug("Could not validate sensor from metadata", extra={"error": str(e)})
            return None

    async def _update_sensor_last_seen(self, sensor_id: str) -> None:
        try:
            async with self._db_factory() as session:
                await models.Sensor.update_last_seen(session, sensor_id)
                await session.commit()
        except Exception as e:
            logger.error("Failed to update sensor last_seen", extra={"error": str(e)})

    async def _log_sensor_state(self, sensor_id: str, action: str, detail: dict) -> None:
        """Write a system-level audit entry for sensor health state changes."""
        try:
            async with self._db_factory() as session:
                await models.AuditLog.write(
                    session,
                    user_id=None,
                    username="system",
                    action=action,
                    target_type="sensor",
                    target_id=sensor_id,
                    detail=detail,
                )
                await session.commit()
        except Exception as e:
            logger.error("Failed to log sensor state", extra={"action": action, "error": str(e)})

    async def _update_sensor_offline(self, sensor_id: str) -> None:
        try:
            # Immediately remove both caches so the next poll reflects offline state.
            await self._redis.delete(f"sensor.active:{sensor_id}")
            await self._redis.delete(f"sensor.health:{sensor_id}")

            await self._redis.publish(
                "sse.broadcast",
                json.dumps({
                    "type": "health_update",
                    "data": {"sensor_id": sensor_id, "status": "offline"},
                }),
            )
        except Exception as e:
            logger.error("Failed to update sensor offline", extra={"error": str(e)})

        # Audit: sensor went offline. Safe to await here — this runs in its own Task.
        await self._log_sensor_state(sensor_id, "sensor_offline", {})

    def _serialize_event(self, event: sensor_pb2.SensorEvent) -> dict:
        """Convert proto SensorEvent to Redis-serializable dict."""
        return {
            "sensor_id":    event.sensor_id,
            "event_id":     event.event_id,
            "timestamp":    event.timestamp.ToDatetime(tzinfo=timezone.utc).isoformat(),
            "source_ip":    event.source_ip,
            "source_port":  event.source_port,
            "dst_port":     event.dst_port,
            "protocol":     sensor_pb2.Protocol.Name(event.protocol),
            "event_type":   sensor_pb2.EventType.Name(event.event_type),
            "severity":     sensor_pb2.Severity.Name(event.severity),
            "raw_summary":  event.raw_summary,
            "raw_payload":  event.raw_payload.hex() if event.raw_payload else "",
            "metadata":     dict(event.metadata),
            "session_hint": event.session_hint,
            "artifacts": [
                {
                    "artifact_type": a.artifact_type,
                    "value":         a.value.hex() if a.encoding == "hex" else a.value.decode("utf-8", errors="replace").replace("\x00", ""),
                    "encoding":      a.encoding,
                }
                for a in event.artifacts
            ],
        }

    def _build_sensor_config(self) -> sensor_pb2.SensorConfig:
        """Build default sensor config from Manager environment."""
        return sensor_pb2.SensorConfig(
            s7_port=102,
            modbus_port=502,
            hmi_http_port=80,
            hmi_https_port=443,
            stateful_s7_memory=True,
            s7_plc_name="S7-300/ET 200M station_1",
            s7_module_type="6ES7 315-2AG10-0AB0",
            s7_serial_number="S C-C2UR28922012",
            brute_force_threshold=5,
            hmi_brand_name="SIMATIC WinCC",
            hmi_plant_name="Water Treatment Plant - Unit 3",
            event_buffer_size=10000,
            heartbeat_interval_s=30,
            stream_flush_interval_ms=500,
        )
