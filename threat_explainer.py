"""
Threat Explainer Module
========================
Uses Google Gemini API to generate plain-English summaries of network security events.
Caches results to avoid redundant API calls for identical event types.
"""

import os
import threading
from typing import Dict, Optional, Tuple
import google.generativeai as genai


class ThreatExplainer:
    """
    Generates human-readable explanations for network security detections using Google Gemini API.

    The explainer receives a detection dictionary and returns a concise 2-3 sentence summary
    in analyst-facing tone. Results are cached keyed by (reason, protocol, dport, severity) to
    avoid redundant API calls.
    """

    def __init__(self):
        """Initialize the threat explainer with cache and API key."""
        self._cache: Dict[Tuple[str, str, int, str], str] = {}
        self._cache_lock = threading.Lock()
        self._api_key = os.getenv("GEMINI_API_KEY")
        if not self._api_key:
            print("[ThreatExplainer] GEMINI_API_KEY not set. Explanations will return placeholder text.")
        else:
            genai.configure(api_key=self._api_key)

        # System prompt instructs Gemini to act as a SOC analyst
        self._system_prompt = """You are a SOC (Security Operations Center) analyst summarizing a network security event for incident review.

Your task:
- Write a 2-3 sentence plain-English summary of the security event.
- Use analyst-facing tone: professional, concise, actionable.
- Avoid jargon dumps or overly technical explanations.
- Focus on: what happened, why it's flagged, and what action was taken.
- Do NOT include confidence scores, technical field names, or raw feature values.

Example output:
"External IP 203.0.113.42 attempted to connect to internal host on port 4444, a known exploit port. The SYN scan pattern and suspicious port triggered a block action. This traffic was blocked as a potential intrusion attempt."

Be concise and direct."""

    def _build_cache_key(self, detection: Dict) -> Tuple[str, str, int, str]:
        """
        Build a cache key from detection attributes.

        Key components: (reason, protocol, dport, severity)
        These capture the essential event type while ignoring variable IPs and timestamps.
        """
        return (
            detection.get("reason", "unknown"),
            detection.get("protocol", "unknown"),
            detection.get("dport", 0),
            detection.get("severity", "unknown"),
        )

    def _call_gemini_api(self, detection: Dict) -> Optional[str]:
        """
        Call Google Gemini API to generate an explanation.

        Returns the explanation text or None if the API call fails.
        """
        if not self._api_key:
            return "API key not configured. Enable GEMINI_API_KEY to generate AI explanations."

        try:
            model = genai.GenerativeModel('gemini-pro')

            # Build user message with detection details
            user_message = f"""{self._system_prompt}

Summarize this network security event:

Source IP: {detection.get('src_ip', 'unknown')}
Destination IP: {detection.get('dst_ip', 'unknown')}
Protocol: {detection.get('protocol', 'unknown')}
Source Port: {detection.get('sport', 0)}
Destination Port: {detection.get('dport', 0)}
Packet Size: {detection.get('size', 0)} bytes
TCP Flags: {detection.get('flags', 'none')}
Reason: {detection.get('reason', 'unknown')}
RandomForest Prediction: {detection.get('rf_prediction', 'unknown')}
RandomForest Confidence: {detection.get('rf_confidence', 0):.2f}
RL Action: {detection.get('rl_action', 'unknown')}
Severity: {detection.get('severity', 'unknown')}

Provide a 2-3 sentence summary for SOC analysts."""

            # Call Gemini API
            response = model.generate_content(user_message)

            # Extract the explanation text
            explanation = response.text.strip()
            return explanation

        except Exception as e:
            print(f"[ThreatExplainer] API call failed: {e}")
            return f"Explanation generation failed: {str(e)}"

    def explain(self, detection: Dict) -> str:
        """
        Generate an explanation for a detection event.

        Args:
            detection: Dictionary containing detection details with keys:
                src_ip, dst_ip, protocol, reason, rf_confidence, rl_action,
                severity, flags, sport, dport, size

        Returns:
            Plain-English explanation string (2-3 sentences).
        """
        cache_key = self._build_cache_key(detection)

        # Check cache first
        with self._cache_lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        # Generate new explanation via API
        explanation = self._call_gemini_api(detection)

        # Cache the result
        with self._cache_lock:
            self._cache[cache_key] = explanation

        return explanation

    def get_cache_stats(self) -> Dict:
        """Return cache statistics for monitoring."""
        with self._cache_lock:
            return {
                "cache_size": len(self._cache),
                "api_key_configured": bool(self._api_key),
            }

    def clear_cache(self):
        """Clear the explanation cache."""
        with self._cache_lock:
            self._cache.clear()
