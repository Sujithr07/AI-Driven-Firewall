"""LangChain chain for generating structured security threat reports."""

import os
from collections import Counter
from datetime import datetime, timezone

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

from app.db.client import supabase

_REPORT_SYSTEM = (
    "You are an expert network security analyst producing a formal security incident report.\n\n"
    "Generate a structured markdown security report based on the detection statistics and log "
    "samples provided. Be specific — reference actual IPs, counts, and protocols from the data. "
    "Do not invent data not present in the input.\n\n"
    "Output ONLY valid markdown with no preamble or surrounding code fences. "
    "Use exactly this section structure:\n\n"
    "# Security Threat Report — {date}\n\n"
    "## Executive Summary\n"
    "(2–3 paragraphs: overall security posture, key metrics for the period, most significant events)\n\n"
    "## Top Threats\n"
    "(Subsections per major threat category ranked by frequency. Include event counts, "
    "representative IPs, severity levels, and confidence scores where available.)\n\n"
    "## IP Analysis\n"
    "(Table or structured list of the top suspicious source IPs: event count, protocols used, "
    "actions taken, and risk assessment.)\n\n"
    "## Recommendations\n"
    "(Numbered, prioritized, actionable steps for the security team based on observed threats.)"
)

_REPORT_HUMAN = """\
Report period: last {n} detections analysed
Generated: {timestamp}

=== AGGREGATE STATISTICS ===
Total events:  {total}
Malicious:     {malicious} ({malicious_pct}%)
Benign:        {benign}
Blocked:       {blocked}
Allowed:       {allowed}

Severity breakdown:
{severity_table}

Protocol distribution:
{protocol_table}

Top threat reasons/categories:
{reason_table}

Top source IPs by event count:
{ip_table}

=== RECENT LOG SAMPLES (last 10 events) ===
{log_samples}
"""

_BLOCK_ACTIONS = frozenset({
    "block", "hard_block", "temp_block", "blocked",
    "quarantine", "rate_limit",
})


def _aggregate(detections: list[dict]) -> dict:
    total = len(detections)
    malicious = sum(1 for d in detections if d.get("is_malicious"))
    blocked = sum(
        1 for d in detections
        if str(d.get("rl_action", "")).lower() in _BLOCK_ACTIONS
        or str(d.get("response_action", "")).lower() in _BLOCK_ACTIONS
    )
    allowed = total - blocked

    severity_counts = Counter(d.get("severity", "unknown") for d in detections)
    protocol_counts = Counter(d.get("protocol", "unknown") for d in detections)
    reason_counts = Counter(d.get("reason", "unknown") for d in detections)
    ip_counts = Counter(d.get("src_ip", "unknown") for d in detections)

    def _fmt(c: Counter, top: int = 8) -> str:
        return "\n".join(f"  {k}: {v}" for k, v in c.most_common(top)) or "  (no data)"

    samples = []
    for d in detections[-10:]:
        action = d.get("rl_action") or d.get("response_action") or "unknown"
        samples.append(
            f"  [{d.get('timestamp', '?')}] "
            f"{d.get('src_ip', '?')} → {d.get('dst_ip', '?')} "
            f"proto={d.get('protocol', '?')} "
            f"severity={d.get('severity', '?')} "
            f"action={action} "
            f"reason={d.get('reason', '?')}"
        )

    return {
        "total": total,
        "malicious": malicious,
        "malicious_pct": round(malicious / total * 100, 1) if total else 0,
        "benign": total - malicious,
        "blocked": blocked,
        "allowed": allowed,
        "severity_table": _fmt(severity_counts),
        "protocol_table": _fmt(protocol_counts),
        "reason_table": _fmt(reason_counts),
        "ip_table": _fmt(ip_counts),
        "log_samples": "\n".join(samples) or "  (no samples)",
    }


def _get_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        temperature=0.2,
    )


def generate_report(n: int = 100) -> dict:
    """Fetch last N detections, aggregate stats, and generate a markdown report.

    Returns:
        {"markdown": str, "stats": dict}
    """
    result = (
        supabase.table("detection_logs")
        .select("*")
        .order("timestamp", desc=True)
        .limit(n)
        .execute()
    )
    detections = result.data or []

    if not detections:
        return {
            "markdown": "# Security Threat Report\n\nNo detection data available for the requested period.",
            "stats": {"total": 0, "malicious": 0, "malicious_pct": 0, "benign": 0, "blocked": 0, "allowed": 0},
        }

    stats = _aggregate(detections)
    now = datetime.now(timezone.utc)

    prompt = ChatPromptTemplate.from_messages([
        ("system", _REPORT_SYSTEM),
        ("human", _REPORT_HUMAN),
    ])

    chain = prompt | _get_llm() | StrOutputParser()

    markdown = chain.invoke({
        "date": now.strftime("%Y-%m-%d"),
        "n": n,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        **stats,
    })

    return {"markdown": markdown.strip(), "stats": stats}
