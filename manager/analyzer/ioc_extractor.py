"""
manager/analyzer/ioc_extractor.py — Promote observed evidence to IOCs.
"""

from __future__ import annotations
import re
from typing import Any


# Patterns for automatic IOC extraction
_SQL_RE   = re.compile(r"(select|union|insert|update|delete|drop|exec|xp_)", re.I)
_PATH_RE  = re.compile(r"(\.\./|\.\.\\|/etc/|/windows/)", re.I)


def extract_iocs(ev: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract actionable IOCs from a raw sensor event.

    IOC types produced:
    - ip:          Source IP of attacker
    - username:    Captured login credentials (usernames only)
    - sql_payload: SQLi payloads
    - path_probe:  Path traversal targets
    - url_path:    Accessed URL paths (for HMI scanner detection)
    - modbus_*:    Function/target/write values extracted from Modbus metadata
    """
    iocs = []
    event_type = ev.get("event_type", "")
    source_ip  = ev.get("source_ip", "")

    # Extract source IP as IOC for all non-noise events
    severity = ev.get("severity", "SEVERITY_NOISE")
    if severity != "SEVERITY_NOISE" and source_ip:
        iocs.append({
            "type":       "ip",
            "value":      source_ip,
            "context":    f"Attacker IP observed in {event_type}",
            "confidence": 0.95,
        })

    # Extract artifacts
    for artifact in ev.get("artifacts", []):
        artifact_type = artifact.get("artifact_type", "")
        value = artifact.get("value", "")

        if not value:
            continue

        if artifact_type == "username":
            iocs.append({
                "type":       "username",
                "value":      value[:256],  # Cap length
                "context":    f"Username submitted to HMI login from {source_ip}",
                "confidence": 0.9,
            })

        elif artifact_type == "password":
            iocs.append({
                "type":       "password",
                "value":      value[:256],
                "context":    f"Password attempted against HMI from {source_ip}",
                "confidence": 0.85,
            })

        elif artifact_type in ("s7_cpu_stop_payload", "s7_write_payload"):
            iocs.append({
                "type":       "s7_payload",
                "value":      value[:512],
                "context":    f"S7 exploit payload captured in {event_type}",
                "confidence": 0.99,
            })

        elif artifact_type in ("enip_write_tag", "enip_set_attr"):
            iocs.append({
                "type":       "enip_payload",
                "value":      value[:512],
                "context":    f"EtherNet/IP CIP write payload captured in {event_type} from {source_ip}",
                "confidence": 0.97,
            })

        elif artifact_type == "http_probe":
            if _SQL_RE.search(value):
                iocs.append({
                    "type":       "sql_payload",
                    "value":      value[:512],
                    "context":    f"SQL injection payload from {source_ip}",
                    "confidence": 0.85,
                })
            elif _PATH_RE.search(value):
                iocs.append({
                    "type":       "path_probe",
                    "value":      value[:256],
                    "context":    f"Path traversal probe from {source_ip}",
                    "confidence": 0.85,
                })

    # Extract URL path IOC for scanner detection
    metadata = ev.get("metadata", {})
    if event_type in ("HMI_SENSITIVE_PATH", "HMI_SCANNER_DETECTED"):
        path = metadata.get("path", "")
        if path:
            iocs.append({
                "type":       "url_path",
                "value":      path[:256],
                "context":    f"Sensitive path accessed from {source_ip}",
                "confidence": 0.7,
            })

    # Extract User-Agent as IOC — scanner/tool fingerprinting
    ua = metadata.get("user_agent", "")
    if ua and event_type.startswith("HMI_"):
        iocs.append({
            "type":       "user_agent",
            "value":      ua[:512],
            "context":    f"HTTP User-Agent observed from {source_ip}",
            "confidence": 0.75,
        })

    # Extract Modbus protocol-level IOCs for read/write targeting and writes
    if event_type.startswith("MODBUS_"):
        function_code = metadata.get("function_code", "")
        target_kind = metadata.get("target_kind", "")
        start_address = metadata.get("start_address", "")
        quantity = metadata.get("quantity", "")
        write_value = metadata.get("write_value", "")
        write_values = metadata.get("write_values_preview", "")

        if function_code:
            iocs.append({
                "type":       "modbus_function",
                "value":      function_code[:16],
                "context":    f"Modbus function code observed in {event_type} from {source_ip}",
                "confidence": 0.92,
            })

        if start_address and target_kind:
            target_value = f"{target_kind or 'address'}:{start_address}"
            if quantity:
                target_value = f"{target_value}:{quantity}"
            iocs.append({
                "type":       "modbus_target",
                "value":      target_value[:128],
                "context":    f"Modbus {target_kind or 'data'} target observed in {event_type} from {source_ip}",
                "confidence": 0.9,
            })

        if write_value:
            iocs.append({
                "type":       "modbus_write_value",
                "value":      write_value[:128],
                "context":    f"Modbus write value observed in {event_type} from {source_ip}",
                "confidence": 0.94,
            })

        if write_values:
            iocs.append({
                "type":       "modbus_write_values",
                "value":      write_values[:256],
                "context":    f"Modbus multi-write values observed in {event_type} from {source_ip}",
                "confidence": 0.93,
            })

    # Extract HTTP Host header as domain IOC — C2 domain discovery
    host = metadata.get("host", "")
    if host and host not in ("localhost", "127.0.0.1") and "." in host:
        # Strip port if present
        domain = host.split(":")[0]
        iocs.append({
            "type":       "domain",
            "value":      domain[:253],
            "context":    f"HTTP Host header observed from {source_ip} targeting HMI",
            "confidence": 0.65,
        })

    return iocs
