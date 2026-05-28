import re
from langchain_core.prompts import ChatPromptTemplate, FewShotChatMessagePromptTemplate

# ── Input validation / sanitization ──────────────────────────────────────────

_VALID_SEVERITIES = {"low", "medium", "high", "critical", "unknown", "n/a"}
_VALID_ACTIONS = {"blocked", "allowed", "monitored", "rate_limited", "flagged", "unknown"}
_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH", "UNKNOWN"}
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"         # IPv4
    r"|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"  # IPv6
    r"|^unknown$",
    re.IGNORECASE,
)
_MAX_REASON_LEN = 120
_MAX_QUERY_LEN = 500


def sanitize_event(event: dict) -> dict:
    """Validate and clamp an event dict before interpolating into a prompt."""
    out: dict = {}

    for field in ("src_ip", "dst_ip"):
        val = str(event.get(field, "unknown")).strip()
        out[field] = val if _IP_RE.match(val) else "unknown"

    for field in ("sport", "dport"):
        try:
            port = int(event.get(field, -1))
            out[field] = port if 0 <= port <= 65535 else "unknown"
        except (TypeError, ValueError):
            out[field] = "unknown"

    severity = str(event.get("severity", "unknown")).lower().strip()
    out["severity"] = severity if severity in _VALID_SEVERITIES else "unknown"

    action = str(event.get("action", "unknown")).lower().strip()
    out["action"] = action if action in _VALID_ACTIONS else "unknown"

    proto = str(event.get("protocol", "unknown")).strip().upper()[:10]
    out["protocol"] = proto if proto in _VALID_PROTOCOLS else "unknown"

    reason = str(event.get("reason", "unknown")).strip()
    out["reason"] = re.sub(r"[^\w\s\-_./:]", "", reason)[:_MAX_REASON_LEN]

    try:
        conf = float(event.get("rf_confidence", 0))
        out["rf_confidence"] = round(conf, 3) if 0.0 <= conf <= 1.0 else "unknown"
    except (TypeError, ValueError):
        out["rf_confidence"] = "unknown"

    out["is_malicious"] = bool(event.get("is_malicious", False))
    return out


def sanitize_query(query: str) -> str:
    """Truncate and strip prompt-injection patterns from a log query."""
    query = query.strip()[:_MAX_QUERY_LEN]
    query = re.sub(r"(?i)\b(system|assistant|human|user)\s*:", "", query)
    return query.strip()


def sanitize_output(text: str) -> str:
    """Remove code fences and collapse excess blank lines from LLM output."""
    text = re.sub(r"```[\w]*\n?", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ── Threat explanation — JSON (non-streaming) ─────────────────────────────────

THREAT_SYSTEM = (
    "You are a network security analyst assistant specializing in firewall event analysis.\n\n"
    "Context: Events are produced by a zero-trust firewall that uses a RandomForest + XGBoost "
    "ensemble (confidence 0–1) and a DQN reinforcement-learning agent for response decisions.\n\n"
    "Task: Explain the threat event in plain language for a security administrator.\n\n"
    "Constraints:\n"
    "  - Respond in exactly 2–3 sentences total across all fields\n"
    "  - Avoid jargon; use plain, actionable English\n"
    "  - Base your explanation only on the provided event fields\n"
    "  - Do not fabricate details not present in the event\n\n"
    'Output format — respond with valid JSON only:\n'
    '{"summary": "<what the threat is>", '
    '"why_blocked": "<reason for the block decision>", '
    '"admin_action": "<recommended next step>"}'
)

_THREAT_JSON_EXAMPLES = [
    {
        "event": (
            "reason=syn_scan | severity=high | protocol=TCP | "
            "sport=54321 | dport=443 | confidence=0.94 | action=blocked"
        ),
        "explanation": (
            '{"summary": "A SYN scan probed port 443, a technique used to map open services '
            'before launching a targeted attack.", '
            '"why_blocked": "The incomplete TCP handshake pattern across multiple ports matched '
            'port-reconnaissance signatures with 94% confidence.", '
            '"admin_action": "Review the source IP\'s full connection history and permanently '
            'block it if scanning recurs within 24 hours."}'
        ),
    },
    {
        "event": (
            "reason=sql_injection | severity=critical | protocol=TCP | "
            "sport=49152 | dport=3306 | confidence=0.98 | action=blocked"
        ),
        "explanation": (
            '{"summary": "An SQL injection payload targeted the database port, attempting to '
            'manipulate queries and extract or corrupt data.", '
            '"why_blocked": "The payload matched known SQL injection signatures at 98% '
            'confidence — a deliberate database attack.", '
            '"admin_action": "Block the source IP immediately, audit recent DB query logs for '
            'successful injections, and tighten WAF rules for port 3306."}'
        ),
    },
    {
        "event": (
            "reason=brute_force | severity=high | protocol=TCP | "
            "sport=38901 | dport=22 | confidence=0.91 | action=blocked"
        ),
        "explanation": (
            '{"summary": "A brute-force attack targeted SSH on port 22 with rapid repeated '
            'authentication attempts to gain unauthorized access.", '
            '"why_blocked": "Login attempt rate far exceeded normal thresholds with 91% '
            'confidence — a classic credential-stuffing pattern.", '
            '"admin_action": "Block the source IP, enforce key-based SSH auth, and check '
            'auth logs for any successful logins from this address."}'
        ),
    },
]

_threat_json_example_prompt = ChatPromptTemplate.from_messages(
    [("human", "{event}"), ("ai", "{explanation}")]
)

_threat_json_few_shot = FewShotChatMessagePromptTemplate(
    example_prompt=_threat_json_example_prompt,
    examples=_THREAT_JSON_EXAMPLES,
)


def get_threat_prompt() -> ChatPromptTemplate:
    """Prompt for non-streaming threat explanation (JSON output)."""
    return ChatPromptTemplate.from_messages(
        [("system", THREAT_SYSTEM), _threat_json_few_shot, ("human", "{event}")]
    )


# ── Threat explanation — plain text (streaming) ───────────────────────────────

THREAT_SYSTEM_STREAM = (
    "You are a network security analyst assistant specializing in firewall event analysis.\n\n"
    "Context: Events are produced by a zero-trust firewall that uses a RandomForest + XGBoost "
    "ensemble (confidence 0–1) and a DQN reinforcement-learning agent for response decisions.\n\n"
    "Task: Explain the threat event in plain language for a security administrator.\n\n"
    "Constraints:\n"
    "  - Respond in exactly 2–3 sentences\n"
    "  - Cover what the threat is, why it was blocked, and what the admin should do next\n"
    "  - Avoid jargon; use plain, actionable English\n"
    "  - Base your explanation only on the provided event fields"
)

_THREAT_TEXT_EXAMPLES = [
    {
        "event": (
            "reason=syn_scan | severity=high | protocol=TCP | "
            "sport=54321 | dport=443 | confidence=0.94 | action=blocked"
        ),
        "explanation": (
            "A SYN scan probed port 443, a technique attackers use to map open services before "
            "launching a targeted attack. The firewall blocked it because the incomplete TCP "
            "handshake pattern across multiple ports matched port-reconnaissance signatures at "
            "94% confidence. Review the source IP's full history and permanently block it if "
            "scanning recurs within 24 hours."
        ),
    },
    {
        "event": (
            "reason=sql_injection | severity=critical | protocol=TCP | "
            "sport=49152 | dport=3306 | confidence=0.98 | action=blocked"
        ),
        "explanation": (
            "An SQL injection payload targeted the database port, attempting to manipulate "
            "queries and extract or corrupt data. The firewall blocked it because the payload "
            "matched known injection signatures at 98% confidence — a deliberate database attack. "
            "Immediately block the source IP, audit recent DB query logs for successful injections, "
            "and tighten WAF rules for port 3306."
        ),
    },
    {
        "event": (
            "reason=brute_force | severity=high | protocol=TCP | "
            "sport=38901 | dport=22 | confidence=0.91 | action=blocked"
        ),
        "explanation": (
            "A brute-force attack targeted SSH on port 22 with rapid repeated authentication "
            "attempts to gain unauthorized access. The login attempt rate far exceeded normal "
            "thresholds with 91% confidence — a classic credential-stuffing pattern. "
            "Block the source IP, enforce key-based SSH authentication, and check auth logs "
            "for any successful logins from this address."
        ),
    },
]

_threat_text_example_prompt = ChatPromptTemplate.from_messages(
    [("human", "{event}"), ("ai", "{explanation}")]
)

_threat_text_few_shot = FewShotChatMessagePromptTemplate(
    example_prompt=_threat_text_example_prompt,
    examples=_THREAT_TEXT_EXAMPLES,
)


def get_threat_stream_prompt() -> ChatPromptTemplate:
    """Prompt for streaming threat explanation (plain text output)."""
    return ChatPromptTemplate.from_messages(
        [("system", THREAT_SYSTEM_STREAM), _threat_text_few_shot, ("human", "{event}")]
    )


def build_threat_event_str(event: dict) -> str:
    """Format a sanitized event dict into the human-turn string for threat prompts."""
    return (
        f"reason={event.get('reason', 'unknown')} | "
        f"severity={event.get('severity', 'unknown')} | "
        f"protocol={event.get('protocol', 'unknown')} | "
        f"src_ip={event.get('src_ip', 'unknown')} | "
        f"dst_ip={event.get('dst_ip', 'unknown')} | "
        f"sport={event.get('sport', 'unknown')} | "
        f"dport={event.get('dport', 'unknown')} | "
        f"confidence={event.get('rf_confidence', 'unknown')} | "
        f"action={event.get('action', 'unknown')} | "
        f"is_malicious={event.get('is_malicious', 'unknown')}"
    )


# ── RAG log-query prompt ──────────────────────────────────────────────────────

_RAG_SYSTEM = (
    "You are a network security analyst assistant.\n\n"
    "Role: Answer questions about firewall activity using only the log entries provided below.\n\n"
    "Context: Logs come from a zero-trust firewall with ML-based threat detection. Each entry "
    "contains a timestamp, source IP, protocol, action (blocked/allowed), severity level, "
    "and detection reason.\n\n"
    "Constraints:\n"
    "  - Answer concisely in 2–4 sentences\n"
    "  - Reference specific IPs, protocols, or patterns found in the logs\n"
    "  - Use only information present in the logs; do not infer external context\n"
    "  - If the logs do not contain enough information to answer, say so explicitly\n\n"
    "Firewall logs:\n{context}"
)

_RAG_EXAMPLES = [
    {
        "question": "Which IPs had the most blocked connections?",
        "answer": (
            "IP 192.168.1.105 had the most blocked connections with 12 events, "
            "followed by 10.0.0.55 with 8 blocks. Most were triggered by port scan "
            "detection on TCP port 443."
        ),
    },
    {
        "question": "Were there any critical severity events in the logs?",
        "answer": (
            "Yes, 3 critical events were found: two SQL injection attempts from "
            "203.0.113.42 and one DDoS pattern from 198.51.100.7, all blocked by "
            "the firewall."
        ),
    },
    {
        "question": "What protocols were most commonly involved in blocked traffic?",
        "answer": (
            "TCP dominated blocked traffic with 18 events, primarily on ports 22 and 443. "
            "UDP accounted for 4 blocks, all flagged as DNS amplification attempts."
        ),
    },
]

_rag_example_prompt = ChatPromptTemplate.from_messages(
    [("human", "{question}"), ("ai", "{answer}")]
)

_rag_few_shot = FewShotChatMessagePromptTemplate(
    example_prompt=_rag_example_prompt,
    examples=_RAG_EXAMPLES,
)


def get_prompt() -> ChatPromptTemplate:
    """RAG log-query prompt (backwards-compatible entry point)."""
    return ChatPromptTemplate.from_messages(
        [("system", _RAG_SYSTEM), _rag_few_shot, ("human", "{question}")]
    )


# ── Security analyst agent system prompt ──────────────────────────────────────

AGENT_SYSTEM = (
    "You are a network security analyst AI assistant integrated with a live firewall "
    "monitoring system.\n\n"
    "Role: Investigate security events, answer analyst questions, and recommend responses.\n\n"
    "Available tools:\n"
    "  • query_logs        — semantic search over historical security logs\n"
    "  • get_threat_stats  — real-time event counts, severity breakdown, and top source IPs\n"
    "  • explain_detection — XAI explanation for a specific detection event by event ID\n"
    "  • check_ip_reputation — full activity history and current block status for an IP\n"
    "  • suggest_action    — recommended firewall response given threat type, severity, and IP\n\n"
    "Constraints:\n"
    "  - Always call at least one tool to ground your answer in actual data\n"
    "  - Be concise and actionable; cite specific IPs, counts, or event IDs\n"
    "  - Do not speculate beyond what the tools return\n"
    "  - If a tool returns no data, say so rather than guessing\n"
    "  - Prioritise critical and high severity events in your analysis"
)
