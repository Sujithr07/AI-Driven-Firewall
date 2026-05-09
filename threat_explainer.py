import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# In-memory cache for threat explanations
_explanation_cache = {}

def explain_threat(event: dict) -> str:
    """
    Explain a threat detection event using Gemini AI.
    
    Args:
        event: Dict with keys: src_ip, dst_ip, protocol, sport, dport, 
               reason, rf_confidence, action, severity, is_malicious
    
    Returns:
        str: Explanation of the threat (2-3 sentences)
    """
    # Extract event fields
    src_ip = event.get("src_ip", "unknown")
    dst_ip = event.get("dst_ip", "unknown")
    protocol = event.get("protocol", "unknown")
    sport = event.get("sport", "unknown")
    dport = event.get("dport", "unknown")
    reason = event.get("reason", "unknown")
    rf_confidence = event.get("rf_confidence", "unknown")
    action = event.get("action", "unknown")
    severity = event.get("severity", "unknown")
    is_malicious = event.get("is_malicious", "unknown")
    
    # Check cache
    cache_key = (src_ip, reason, action)
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]
    
    # Build prompt
    prompt = f"""Explain this network threat in 2-3 simple sentences. Avoid jargon.

Event details:
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Protocol: {protocol}
- Source port: {sport}
- Destination port: {dport}
- Detection reason: {reason}
- Confidence: {rf_confidence}
- Action taken: {action}
- Severity: {severity}
- Flagged as malicious: {is_malicious}

Answer: What is this threat? Why was it blocked? What should an admin do next?"""
    
    try:
        # Call Gemini API
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=300,
            )
        )
        
        explanation = response.text.strip()
        
        # Cache the result
        _explanation_cache[cache_key] = explanation
        return explanation
        
    except Exception as e:
        # Fallback to heuristic explanation based on reason
        return _get_heuristic_explanation(reason, src_ip, action)

def _get_heuristic_explanation(reason: str, src_ip: str, action: str) -> str:
    """
    Generate a simple heuristic explanation when API fails.
    """
    reason_lower = reason.lower()
    
    if "syn" in reason_lower and "scan" in reason_lower:
        return f"SYN scan detected from {src_ip} — possible port scanning activity."
    elif "dos" in reason_lower or "ddos" in reason_lower:
        return f"Denial of service pattern detected from {src_ip} — traffic volume anomaly."
    elif "sql" in reason_lower and "inject" in reason_lower:
        return f"SQL injection attempt detected from {src_ip} — malicious database query pattern."
    elif "xss" in reason_lower:
        return f"Cross-site scripting attempt detected from {src_ip} — malicious script injection."
    elif "brute" in reason_lower or "force" in reason_lower:
        return f"Brute force attack detected from {src_ip} — repeated authentication attempts."
    elif "malware" in reason_lower or "virus" in reason_lower:
        return f"Malware signature detected from {src_ip} — known malicious pattern."
    elif "port" in reason_lower and "scan" in reason_lower:
        return f"Port scan detected from {src_ip} — network reconnaissance activity."
    elif "flood" in reason_lower:
        return f"Flood attack detected from {src_ip} — excessive connection attempts."
    else:
        return f"Suspicious activity detected from {src_ip} — {reason}. Traffic was {action}."
