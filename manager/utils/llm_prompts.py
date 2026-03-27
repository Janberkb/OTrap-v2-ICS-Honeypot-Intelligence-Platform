"""
manager/utils/llm_prompts.py — LLM prompt builders for OTrap analysis.

Formats honeypot session/attacker data into structured prompts
optimised for local ICS/OT security analysis.
"""

from __future__ import annotations

from datetime import datetime

# ─── System prompts ───────────────────────────────────────────────────────────

_SYSTEM_NARRATIVE = """\
You are an expert ICS/OT (Industrial Control Systems / Operational Technology) \
security analyst with deep knowledge of industrial protocols (Siemens S7comm, \
Modbus/TCP, EtherNet/IP, HMI web interfaces) and ICS-specific attack frameworks \
(MITRE ATT&CK for ICS, CRASHOVERRIDE, Stuxnet, PIPEDREAM/INCONTROLLER).

You are analysing data captured by OTrap — an ICS honeypot platform that emulates \
Siemens S7 PLCs, Modbus RTU/TCP controllers, Allen-Bradley CompactLogix PLCs, and \
SIMATIC WinCC HMI panels.

Produce a concise, professional threat assessment structured in exactly these \
5 markdown sections. Start directly with the first header — no preamble:

## Attack Summary
Chronological narrative of what the attacker did, referencing specific event \
types and timestamps from the timeline.

## Threat Assessment
Severity verdict, confidence level, and potential real-world impact if this \
were a production ICS environment (consider safety, availability, integrity).

## Attacker Profile Inference
Based on tools, timing, event sequences, and IOCs: sophistication level, \
likely tooling (automated scanner vs. manual ICS tool such as PLCInject/snap7), \
geographic/contextual clues.

## MITRE ATT&CK for ICS Context
Explain the observed techniques in context of the ICS kill chain. Reference \
the MITRE technique IDs provided and explain their real-world significance.

## Recommended Actions
Exactly 3 specific, immediately actionable recommendations for a SOC analyst \
handling this session right now."""

_SYSTEM_TRIAGE = """\
You are an ICS security analyst triage assistant. Based on the provided \
honeypot session data, determine the appropriate triage classification.

Respond ONLY with valid JSON — no markdown fences, no explanation outside JSON:
{
  "recommended_status": "new|investigating|reviewed|false_positive|escalated",
  "confidence": 0.85,
  "reasoning": "One or two sentences explaining the classification.",
  "suggested_note": "Short triage note, max 150 characters."
}

Triage status definitions:
- new: Default, not yet reviewed
- investigating: Suspicious — requires active investigation
- reviewed: Examined, confirmed true positive of lower priority
- false_positive: Benign (automated internet scanner, security researcher, internal test)
- escalated: High severity — immediate response needed (CPU STOP, critical tag writes, brute force success)"""

_SYSTEM_ATTACKER = """\
You are an ICS/OT threat intelligence analyst. Based on the provided attacker \
IP profile aggregated from an ICS honeypot, produce a threat intelligence assessment.

Structure your response in exactly these 4 markdown sections. \
Start directly with the first header — no preamble:

## Attribution Assessment
What can we infer about this threat actor? Sophistication, likely motivation \
(espionage, ransomware pre-positioning, hacktivism, opportunistic scanning), \
and whether the TTPs suggest known groups or campaigns.

## Campaign Pattern Analysis
Based on the session history: single scan or sustained campaign? \
Evolution of techniques across sessions? ICS-specific targeting vs. generic?

## Threat Intelligence Synthesis
Combine GeoIP, GreyNoise/AbuseIPDB data, and observed OT behaviour into a \
coherent threat picture. Highlight contradictions or notable findings.

## Defensive Recommendations
3 specific defensive actions directly tied to this attacker's observed behaviour."""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fmt_ts(ts: str | None) -> str:
    """Format ISO timestamp to HH:MM:SS for compact display."""
    if not ts:
        return "??:??:??"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return ts[:8] if len(ts) >= 8 else ts


def _fmt_duration(secs: float | None) -> str:
    if secs is None:
        return "unknown"
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def _sev_abbr(sev: str) -> str:
    return {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}.get(sev, "NOIS")


# ─── Prompt builders ──────────────────────────────────────────────────────────

def build_session_narrative_prompt(
    session: dict,
    events: list[dict],
    iocs: list[dict],
    mitre_techniques: list[dict],
) -> list[dict]:
    """Build threat narrative prompt for a full session analysis."""
    geo = session.get("geo") or {}
    geo_parts = [geo.get("flag", ""), geo.get("country_name", ""), geo.get("city", ""), geo.get("org", "")]
    geo_str = " / ".join(p for p in geo_parts if p)

    cpu_flag = "YES ⚠️ (CRITICAL — attacker halted PLC)" if session.get("cpu_stop_occurred") else "No"

    lines: list[str] = [
        "## Session Data",
        f"Source IP: {session.get('source_ip', 'unknown')}  ({geo_str})" if geo_str else f"Source IP: {session.get('source_ip', 'unknown')}",
        f"Protocol: {session.get('primary_protocol', 'unknown')} | Severity: {(session.get('severity') or 'noise').upper()} | Kill-chain Phase: {session.get('attack_phase', 'unknown')}",
        f"Duration: {_fmt_duration(session.get('duration_seconds'))} | Total Events: {session.get('event_count', 0)} | IOCs Extracted: {session.get('ioc_count', 0)}",
        f"CPU STOP command received: {cpu_flag}",
        f"Current triage status: {session.get('triage_status', 'new')}",
        "",
        f"## Event Timeline (chronological, showing last {min(len(events), 30)} of {len(events)} events)",
    ]

    for e in events[-30:]:
        ts = _fmt_ts(e.get("timestamp"))
        sev = _sev_abbr(e.get("severity", "noise"))
        et = e.get("event_type", "UNKNOWN")
        summary = (e.get("raw_summary") or "")[:120]
        lines.append(f"[{ts}] [{sev}] {et} — {summary}")

    lines.append("")

    if iocs:
        lines.append(f"## Extracted IOCs ({min(len(iocs), 10)} shown)")
        for ioc in iocs[:10]:
            val = (ioc.get("value") or "")[:80]
            ctx = (ioc.get("context") or "")[:60]
            conf = int((ioc.get("confidence") or 0) * 100)
            lines.append(f"- {ioc.get('ioc_type', 'unknown')}: {val}  (confidence {conf}%, context: {ctx})")
        lines.append("")

    if mitre_techniques:
        lines.append("## MITRE ATT&CK for ICS Techniques Observed")
        seen: set[str] = set()
        for t in mitre_techniques:
            tid = t.get("technique_id", "")
            if tid in seen:
                continue
            seen.add(tid)
            name = t.get("technique_name", "")
            tactic = t.get("tactic", "")
            lines.append(f"- {tid} {name} — {tactic}")
        lines.append("")

    return [
        {"role": "system", "content": _SYSTEM_NARRATIVE},
        {"role": "user", "content": "\n".join(lines)},
    ]


def build_triage_prompt(
    session: dict,
    events: list[dict],
    iocs: list[dict],
) -> list[dict]:
    """Build triage classification prompt. Expects JSON-only LLM output."""
    geo = session.get("geo") or {}
    geo_str = f"{geo.get('country_name', '')} / {geo.get('org', '')}" if geo else ""

    # Deduplicated event types from last 20 events
    event_types = list(dict.fromkeys(e.get("event_type", "") for e in events[-20:]))
    event_summary = ", ".join(event_types[:15])

    ioc_summary = ", ".join(
        f"{i.get('ioc_type')}:{(i.get('value') or '')[:30]}"
        for i in iocs[:5]
    ) if iocs else "none"

    user_lines = [
        f"IP: {session.get('source_ip', 'unknown')}" + (f" ({geo_str})" if geo_str else ""),
        f"Protocol: {session.get('primary_protocol')} | Severity: {session.get('severity')} | Phase: {session.get('attack_phase')}",
        f"Events: {session.get('event_count', 0)} | Duration: {_fmt_duration(session.get('duration_seconds'))}",
        f"CPU STOP: {'YES' if session.get('cpu_stop_occurred') else 'No'} | IOCs: {session.get('ioc_count', 0)}",
        f"Event types observed: {event_summary}",
        f"Key IOCs: {ioc_summary}",
    ]

    return [
        {"role": "system", "content": _SYSTEM_TRIAGE},
        {"role": "user", "content": "\n".join(user_lines)},
    ]


def build_attacker_prompt(
    ip: str,
    geo: dict | None,
    threat_intel: dict | None,
    profile: dict,
    sessions: list[dict],
    iocs: list[dict],
) -> list[dict]:
    """Build attacker profile analysis prompt."""
    geo = geo or {}
    threat_intel = threat_intel or {}
    gn = threat_intel.get("greynoise") or {}
    ab = threat_intel.get("abuseipdb") or {}

    geo_str = " / ".join(p for p in [
        geo.get("flag", ""), geo.get("country_name", ""), geo.get("city", ""), geo.get("org", "")
    ] if p)
    network_context = profile.get("network_context") or {}
    ioc_type_dist = profile.get("ioc_type_dist") or []

    lines: list[str] = [
        f"## Attacker IP: {ip}",
        f"GeoIP: {geo_str or 'Unknown'}",
        "",
        "## External Threat Intelligence",
        f"GreyNoise: seen={gn.get('seen', False)}, classification={gn.get('classification', 'N/A')}, "
        f"noise={gn.get('noise', False)}, riot={gn.get('riot', False)}, name={gn.get('name', 'N/A')}",
        f"AbuseIPDB: abuse_score={ab.get('abuse_score', 'N/A')}/100, "
        f"total_reports={ab.get('total_reports', 0)}, whitelisted={ab.get('is_whitelisted', False)}",
        "",
        "## Attack History Summary",
        f"Sessions: {profile.get('session_count', 0)} | Events: {profile.get('event_count', 0)} | "
        f"Observed IOCs: {profile.get('ioc_count', 0)} | Distinct IOCs: {profile.get('distinct_ioc_count', profile.get('ioc_count', 0))}",
        f"First seen: {(profile.get('first_seen') or 'N/A')[:16]} | Last seen: {(profile.get('last_seen') or 'N/A')[:16]}",
        f"CPU STOP ever issued: {'YES ⚠️' if profile.get('cpu_stop_ever') else 'No'}",
        f"Severity distribution: {profile.get('severity_dist', {})}",
        f"Protocols targeted: {[p['protocol'] for p in profile.get('protocol_dist', [])]}",
        f"Kill-chain phases reached: {profile.get('attack_phases', [])}",
        "",
    ]

    if network_context:
        lines.extend([
            "## Network Context",
            f"Scope: {network_context.get('scope', 'unknown')}",
            f"Threat intel applicable: {network_context.get('threat_intel_applicable', False)}",
            f"Summary: {network_context.get('summary', 'N/A')}",
            "",
        ])

    if ioc_type_dist:
        ioc_type_summary = [
            f"{row.get('ioc_type')}×{row.get('count')}"
            for row in ioc_type_dist
        ]
        lines.append(
            f"IOC type distribution: {ioc_type_summary}"
        )
        lines.append("")

    if sessions:
        lines.append(f"## Session History (last {len(sessions)})")
        for s in sessions:
            ts = (s.get("started_at") or "")[:16]
            lines.append(
                f"- {ts} | {s.get('primary_protocol')} | {s.get('severity')} | "
                f"phase={s.get('attack_phase')} | events={s.get('event_count', 0)}"
            )
        lines.append("")

    if iocs:
        lines.append(f"## IOC Summary (first {min(len(iocs), 10)})")
        for i in iocs[:10]:
            lines.append(f"- {i.get('ioc_type')}: {(i.get('value') or '')[:60]}")

    return [
        {"role": "system", "content": _SYSTEM_ATTACKER},
        {"role": "user", "content": "\n".join(lines)},
    ]
