import os
import sqlite3
from datetime import datetime, timedelta
from langchain_core.tools import tool
from log_embedder import embedder

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "firewall.db")


def _db(sql: str, params: tuple = ()) -> list[dict]:
    with sqlite3.connect(_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


@tool
def query_logs(query: str) -> str:
    """Semantic search over firewall security logs. Use for questions about past events, attack patterns, specific IPs, or threat history."""
    logs = embedder.search(query, k=6)
    if not logs:
        return "No matching logs found."
    lines = [
        f"[{log.get('timestamp', 'N/A')}] src={log.get('src_ip', 'N/A')} "
        f"proto={log.get('protocol', 'N/A')} action={log.get('action', 'N/A')} "
        f"severity={log.get('severity', 'N/A')} reason={log.get('reason', 'N/A')}"
        for log in logs
    ]
    return "\n".join(lines)


@tool
def get_threat_stats(hours: int = 1) -> str:
    """Get real-time threat statistics from the database for the last N hours (default 1 hour).
    Returns event counts by decision, severity, and top source IPs."""
    since_ts = (datetime.utcnow() - timedelta(hours=hours)).timestamp()

    sec_rows = _db(
        "SELECT decision, severity, source_ip FROM security_logs WHERE timestamp >= ?",
        (since_ts,),
    )
    det_rows = _db(
        "SELECT rl_action, severity, src_ip, is_malicious FROM detection_logs WHERE timestamp >= ?",
        (since_ts,),
    )

    if not sec_rows and not det_rows:
        return f"No events recorded in the last {hours} hour(s)."

    decision_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    ip_counts: dict[str, int] = {}

    for r in sec_rows:
        decision_counts[r["decision"]] = decision_counts.get(r["decision"], 0) + 1
        severity_counts[r["severity"]] = severity_counts.get(r["severity"], 0) + 1
        if r["source_ip"]:
            ip_counts[r["source_ip"]] = ip_counts.get(r["source_ip"], 0) + 1

    malicious = sum(1 for r in det_rows if r["is_malicious"])

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return "\n".join([
        f"Period: last {hours}h",
        f"Security log events: {len(sec_rows)}",
        f"Detection events: {len(det_rows)} ({malicious} malicious)",
        f"Decisions: {decision_counts}",
        f"Severities: {severity_counts}",
        f"Top source IPs: {top_ips}",
    ])


@tool
def explain_detection(event_id: str) -> str:
    """Explain the reasoning behind a specific detection event by its numeric ID.
    Returns feature values, ML prediction, and stored explanation text."""
    rows = _db("SELECT * FROM detection_logs WHERE id = ? LIMIT 1", (event_id,))
    if not rows:
        rows = _db("SELECT * FROM security_logs WHERE id = ? LIMIT 1", (event_id,))
    if not rows:
        return f"No detection event found with ID '{event_id}'."

    event = rows[0]
    skip = {"entry_hash", "prev_hash"}
    lines = [f"Event ID: {event_id}"]
    for k, v in event.items():
        if k not in skip and v is not None:
            lines.append(f"  {k}: {v}")

    explanation = event.get("explanation") or event.get("reason") or "No detailed explanation stored."
    lines.append(f"\nExplanation: {explanation}")
    return "\n".join(lines)


@tool
def check_ip_reputation(ip_address: str) -> str:
    """Check an IP address's security history: how many times it was seen, what decisions were made, and whether it is currently blocked."""
    logs = _db(
        "SELECT decision, severity, reason, timestamp FROM security_logs "
        "WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 20",
        (ip_address,),
    )
    det_logs = _db(
        "SELECT rl_action, severity, reason, timestamp FROM detection_logs "
        "WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 10",
        (ip_address,),
    )
    responses = _db(
        "SELECT rule_type, reason, reversed, created_at FROM response_actions "
        "WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 5",
        (ip_address,),
    )

    if not logs and not det_logs and not responses:
        return f"IP {ip_address} has no recorded activity. Appears clean or not yet observed."

    decision_counts: dict[str, int] = {}
    for r in logs:
        decision_counts[r["decision"]] = decision_counts.get(r["decision"], 0) + 1

    is_blocked = any(r["reversed"] == 0 for r in responses)
    parts = [
        f"IP: {ip_address}",
        f"Security log entries: {len(logs)} | Decisions: {decision_counts}",
        f"Detection events: {len(det_logs)}",
        f"Response actions taken: {len(responses)}",
        f"Currently blocked: {'YES' if is_blocked else 'NO'}",
    ]
    if responses:
        latest = responses[0]
        parts.append(f"Latest action: {latest['rule_type']} — {latest['reason']} (reversed={bool(latest['reversed'])})")
    return "\n".join(parts)


@tool
def suggest_action(threat_type: str, severity: str, src_ip: str) -> str:
    """Suggest the appropriate firewall response for a threat. Provide the threat type (e.g. port_scan, sql_injection, ddos), severity (low/medium/high/critical), and source IP."""
    sev = severity.lower()
    ttype = threat_type.lower()

    if sev == "critical":
        action = "BLOCK"
        rationale = f"Immediately block {src_ip} at the perimeter. Alert SOC. Add to threat-intel feed."
    elif sev == "high":
        action = "BLOCK"
        rationale = f"Block {src_ip}. Review sessions from this IP in the last 24h. Notify on-call analyst."
    elif sev == "medium":
        action = "RATE_LIMIT"
        rationale = f"Apply rate limiting to {src_ip}. Monitor for 30 min. Escalate to BLOCK if pattern continues."
    else:
        action = "MONITOR"
        rationale = f"Flag {src_ip} for passive monitoring. No immediate action required."

    extras = []
    if "sql" in ttype or "injection" in ttype:
        extras.append("Enable WAF rules for SQL injection patterns on all web-facing services.")
    if "port_scan" in ttype or "scan" in ttype:
        extras.append("Consider honeypot deployment to fingerprint the scanner further.")
    if "ddos" in ttype or "flood" in ttype:
        extras.append("Activate upstream traffic scrubbing if volume exceeds threshold.")
    if "brute" in ttype:
        extras.append("Enforce account lockout and MFA on targeted services.")

    lines = [f"Recommended action: {action}", rationale]
    if extras:
        lines.append("Additional mitigations:")
        lines.extend(f"  • {e}" for e in extras)
    return "\n".join(lines)
