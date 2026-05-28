import os
from typing import Generator
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

_explanation_cache: dict[tuple, str] = {}


def _make_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=300,
    )


def _build_prompt(event: dict) -> str:
    return (
        "Explain this network threat in 2-3 simple sentences. Avoid jargon.\n\n"
        "Event details:\n"
        f"- Source IP: {event.get('src_ip', 'unknown')}\n"
        f"- Destination IP: {event.get('dst_ip', 'unknown')}\n"
        f"- Protocol: {event.get('protocol', 'unknown')}\n"
        f"- Source port: {event.get('sport', 'unknown')}\n"
        f"- Destination port: {event.get('dport', 'unknown')}\n"
        f"- Detection reason: {event.get('reason', 'unknown')}\n"
        f"- Confidence: {event.get('rf_confidence', 'unknown')}\n"
        f"- Action taken: {event.get('action', 'unknown')}\n"
        f"- Severity: {event.get('severity', 'unknown')}\n"
        f"- Flagged as malicious: {event.get('is_malicious', 'unknown')}\n\n"
        "Answer: What is this threat? Why was it blocked? What should an admin do next?"
    )


def explain_threat(event: dict) -> str:
    cache_key = (event.get("src_ip"), event.get("reason"), event.get("action"))
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    try:
        result = _make_llm().invoke([HumanMessage(content=_build_prompt(event))])
        explanation = result.content.strip()
        _explanation_cache[cache_key] = explanation
        return explanation
    except Exception:
        return _get_heuristic_explanation(
            event.get("reason", ""), event.get("src_ip", "unknown"), event.get("action", "unknown")
        )


def stream_explain_threat(event: dict) -> Generator[str, None, None]:
    """Yield text tokens from Gemini for a threat explanation. Caches the full result on completion."""
    cache_key = (event.get("src_ip"), event.get("reason"), event.get("action"))
    if cache_key in _explanation_cache:
        yield _explanation_cache[cache_key]
        return

    try:
        full_text = ""
        for chunk in _make_llm().stream([HumanMessage(content=_build_prompt(event))]):
            if chunk.content:
                full_text += chunk.content
                yield chunk.content
        if full_text:
            _explanation_cache[cache_key] = full_text
    except Exception:
        fallback = _get_heuristic_explanation(
            event.get("reason", ""), event.get("src_ip", "unknown"), event.get("action", "unknown")
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
