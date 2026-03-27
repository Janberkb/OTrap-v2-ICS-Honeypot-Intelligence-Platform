from __future__ import annotations

from types import SimpleNamespace

from manager.notifications.siem_forwarder import _build_cef, _build_ecs_payload


def test_build_ecs_payload_includes_structured_context_and_redacts_passwords():
    session = SimpleNamespace(
        id="sess-1",
        signal_tier="impact",
        severity="high",
        attack_phase="impact",
        mitre_techniques=[
            {
                "technique_id": "T0855",
                "technique_name": "Unauthorized Command Message",
                "tactic": "Impair Process Control",
            }
        ],
    )
    ev = {
        "event_id": "evt-1",
        "timestamp": "2026-03-27T00:00:00+00:00",
        "source_ip": "198.51.100.10",
        "source_port": 44444,
        "dst_port": 502,
        "protocol": "modbus",
        "event_type": "MODBUS_WRITE_SINGLE_COIL",
        "severity": "SEVERITY_HIGH",
        "raw_summary": "Write Single Coil — HIGH SEVERITY",
        "sensor_id": "sensor-1",
        "metadata": {
            "function_code": "0x05",
            "function_name": "write_single_coil",
            "start_address": "0",
            "target_kind": "coil",
            "write_value": "on",
            "path": "/coil/0",
            "query": "force=1",
            "method": "POST",
            "user_agent": "curl/8.0",
            "username": "operator1",
        },
        "artifacts": [
            {"artifact_type": "password", "value": "SuperSecret!", "encoding": "utf8"},
            {"artifact_type": "username", "value": "operator1", "encoding": "utf8"},
        ],
    }

    payload = _build_ecs_payload(ev, session)

    assert payload["event"]["action"] == "MODBUS_WRITE_SINGLE_COIL"
    assert payload["event"]["reason"] == "Write Single Coil — HIGH SEVERITY"
    assert payload["user"]["name"] == "operator1"
    assert payload["url"]["path"] == "/coil/0"
    assert payload["url"]["query"] == "force=1"
    assert payload["http"]["request"]["method"] == "POST"
    assert payload["user_agent"]["original"] == "curl/8.0"
    assert payload["threat"]["framework"] == "MITRE ATT&CK for ICS"
    assert payload["threat"]["technique"][0]["id"] == "T0855"
    assert payload["otrap"]["metadata"]["function_code"] == "0x05"
    assert payload["otrap"]["ioc_count"] >= 3
    assert any(i["type"] == "modbus_function" and i["value"] == "0x05" for i in payload["otrap"]["iocs"])
    assert any(a["type"] == "password" and a["value"] == "********" for a in payload["otrap"]["artifacts"])


def test_build_cef_includes_richer_protocol_context():
    payload = {
        "event": {"severity": 5},
        "source": {"ip": "198.51.100.10"},
        "destination": {"port": 502},
        "network": {"protocol": "modbus"},
        "message": "Write Single Coil — HIGH SEVERITY",
        "otrap": {
            "session_id": "sess-1",
            "event_type": "MODBUS_WRITE_SINGLE_COIL",
            "event_family": "ics_modbus",
            "mitre_technique": "T0855",
            "metadata": {
                "function_code": "0x05",
                "start_address": "0",
                "write_value": "on",
            },
        },
    }

    cef = _build_cef(payload)

    assert "cs1=sess-1" in cef
    assert "cs2=ics_modbus" in cef
    assert "cs3=T0855" in cef
    assert "cs4=0x05" in cef
    assert "cn1=0" in cef
    assert "cs5=on" in cef
