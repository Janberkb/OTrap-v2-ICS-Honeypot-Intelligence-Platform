"""
manager/notifications/rule_engine.py — Alert rule evaluation engine.

Each enabled AlertRule is matched against every incoming event.
Rules with no conditions act as a catch-all.
All conditions within a rule are ANDed together.
"""
from __future__ import annotations

import logging

from manager.db import models

logger = logging.getLogger("otrap.rules")

SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _get_field(field: str, ev: dict) -> str:
    if field == "severity":
        return ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    if field == "protocol":
        return (ev.get("protocol") or "").replace("PROTOCOL_", "").lower()
    if field == "event_type":
        return ev.get("event_type", "")
    if field == "source_ip":
        return ev.get("source_ip", "")
    if field == "sensor_id":
        return str(ev.get("sensor_id", ""))
    return ""


def _eval_condition(cond: dict, ev: dict) -> bool:
    field  = cond.get("field", "")
    op     = cond.get("operator", "eq")
    value  = cond.get("value")
    actual = _get_field(field, ev)

    if op == "eq":
        return actual.lower() == str(value).lower()
    if op == "neq":
        return actual.lower() != str(value).lower()
    if op == "contains":
        return str(value).lower() in actual.lower()
    if op == "in":
        vals = value if isinstance(value, list) else [value]
        return actual.lower() in [str(v).lower() for v in vals]
    if op == "not_in":
        vals = value if isinstance(value, list) else [value]
        return actual.lower() not in [str(v).lower() for v in vals]
    if op == "gte" and field == "severity":
        return SEVERITY_ORDER.get(actual, 0) >= SEVERITY_ORDER.get(str(value).lower(), 0)
    if op == "lte" and field == "severity":
        return SEVERITY_ORDER.get(actual, 0) <= SEVERITY_ORDER.get(str(value).lower(), 0)
    return False


def match_rule(rule: models.AlertRule, ev: dict) -> bool:
    if not rule.enabled:
        return False
    conditions = rule.conditions or []
    if not conditions:
        return True  # No conditions = catch-all rule
    return all(_eval_condition(c, ev) for c in conditions)


async def evaluate_rules(db, ev: dict, db_session: models.Session) -> None:
    """Evaluate all enabled alert rules against an incoming event."""
    try:
        rules = await models.AlertRule.get_enabled(db)
    except Exception as e:
        logger.warning("Failed to load alert rules: %s", e)
        return

    if not rules:
        return

    from manager.notifications.smtp_sender import maybe_send_smtp
    from manager.notifications.siem_forwarder import maybe_forward_siem

    for rule in rules:
        if not match_rule(rule, ev):
            continue

        logger.info(
            "Alert rule matched",
            extra={"rule": rule.name, "event_type": ev.get("event_type"), "source_ip": ev.get("source_ip")},
        )

        if rule.notify_smtp:
            try:
                await maybe_send_smtp(db, ev, db_session, force=True)
            except Exception as e:
                logger.warning("Rule SMTP notify failed: %s (rule=%s)", e, rule.name)

        if rule.notify_siem:
            try:
                await maybe_forward_siem(db, ev, db_session, force=True)
            except Exception as e:
                logger.warning("Rule SIEM notify failed: %s (rule=%s)", e, rule.name)

        if rule.auto_triage and db_session.triage_status == "new":
            db_session.triage_status = rule.auto_triage
            try:
                await db.commit()
            except Exception as e:
                logger.warning("Rule auto-triage failed: %s (rule=%s)", e, rule.name)
