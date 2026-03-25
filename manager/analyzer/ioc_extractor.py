"""
manager/analyzer/ioc_extractor.py — Promote observed evidence to IOCs.
"""

from __future__ import annotations
import re
from typing import Any


# Patterns for automatic IOC extraction
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
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

        elif artifact_type in ("s7_cpu_stop_payload", "s7_write_payload"):
            iocs.append({
                "type":       "s7_payload",
                "value":      value[:512],
                "context":    f"S7 exploit payload captured in {event_type}",
                "confidence": 0.99,
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

    return iocs
