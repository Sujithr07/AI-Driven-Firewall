import json
import os
from typing import Generator
from dotenv import load_dotenv
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI
from rag.prompts import (
    sanitize_event,
    sanitize_output,
    build_threat_event_str,
    get_threat_prompt,
    get_threat_stream_prompt,
)

load_dotenv()

_explanation_cache: dict[tuple, str] = {}


def _make_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=300,
        temperature=0.2,
    )


def _make_llm_json() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=300,
        temperature=0.2,
        generation_config={"response_mime_type": "application/json"},
    )


def _format_json_explanation(raw: str) -> str:
    """Parse JSON threat output and format as readable prose. Falls back to raw text."""
    try:
        data = json.loads(raw)
        parts = []
        if data.get("summary"):
            parts.append(data["summary"])
        if data.get("why_blocked"):
            parts.append(f"Why blocked: {data['why_blocked']}")
        if data.get("admin_action"):
            parts.append(f"Recommended action: {data['admin_action']}")
        if parts:
            return "  ".join(parts)
    except (json.JSONDecodeError, AttributeError, KeyError):
        pass
    return sanitize_output(raw)


def explain_threat(event: dict) -> str:
    """Return a formatted threat explanation. Uses JSON-structured LLM output internally."""
    clean = sanitize_event(event)
    cache_key = (clean.get("src_ip"), clean.get("reason"), clean.get("action"))
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    event_str = build_threat_event_str(clean)
    chain = get_threat_prompt() | _make_llm_json() | StrOutputParser()

    try:
        raw = chain.invoke({"event": event_str})
        explanation = _format_json_explanation(raw)
        _explanation_cache[cache_key] = explanation
        return explanation
    except Exception:
        fallback = _get_heuristic_explanation(
            clean.get("reason", ""), clean.get("src_ip", "unknown"), clean.get("action", "unknown")
        )
        _explanation_cache[cache_key] = fallback
        return fallback


def stream_explain_threat(event: dict) -> Generator[str, None, None]:
    """Yield plain-text tokens from Gemini for real-time streaming."""
    clean = sanitize_event(event)
    cache_key = (clean.get("src_ip"), clean.get("reason"), clean.get("action"))
    if cache_key in _explanation_cache:
        yield _explanation_cache[cache_key]
        return

    event_str = build_threat_event_str(clean)
    chain = get_threat_stream_prompt() | _make_llm() | StrOutputParser()

    try:
        full_text = ""
        for chunk in chain.stream({"event": event_str}):
            if chunk:
                full_text += chunk
                yield chunk
        if full_text:
            _explanation_cache[cache_key] = sanitize_output(full_text)
    except Exception:
        fallback = _get_heuristic_explanation(
            clean.get("reason", ""), clean.get("src_ip", "unknown"), clean.get("action", "unknown")
        )
        _explanation_cache[cache_key] = fallback
        yield fallback


def _get_heuristic_explanation(reason: str, src_ip: str, action: str) -> str:
    r = reason.lower()
    if "syn" in r and "scan" in r:
        return f"SYN scan detected from {src_ip} — possible port scanning activity."
    elif "dos" in r or "ddos" in r:
        return f"Denial of service pattern detected from {src_ip} — traffic volume anomaly."
    elif "sql" in r and "inject" in r:
        return f"SQL injection attempt detected from {src_ip} — malicious database query pattern."
    elif "xss" in r:
        return f"Cross-site scripting attempt detected from {src_ip} — malicious script injection."
    elif "brute" in r or "force" in r:
        return f"Brute force attack detected from {src_ip} — repeated authentication attempts."
    elif "malware" in r or "virus" in r:
        return f"Malware signature detected from {src_ip} — known malicious pattern."
    elif "port" in r and "scan" in r:
        return f"Port scan detected from {src_ip} — network reconnaissance activity."
    elif "flood" in r:
        return f"Flood attack detected from {src_ip} — excessive connection attempts."
    else:
        return f"Suspicious activity detected from {src_ip} — {reason}. Traffic was {action}."
