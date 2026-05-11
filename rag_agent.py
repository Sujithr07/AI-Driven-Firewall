import google.generativeai as genai
from dotenv import load_dotenv
import os
from log_embedder import embedder

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


def answer_log_query(question: str) -> dict:
    retrieved_logs = embedder.search(question, k=8)
    
    if not retrieved_logs:
        return {"answer": "No matching logs found.", "sources": []}
    
    context_lines = []
    for log in retrieved_logs:
        context_lines.append(
            f"{log.get('timestamp', 'N/A')} {log.get('src_ip', 'N/A')} {log.get('reason', 'N/A')} {log.get('action', 'N/A')}"
        )
    context = "\n".join(context_lines)
    
    prompt = f"""Based on the following firewall logs, answer the user's question in 2-4 sentences. Use only the provided logs. Mention specific IPs or patterns you found.

Logs:
{context}

Question: {question}
"""
    
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt, generation_config={"max_output_tokens": 400})
        answer = response.text
    except Exception as e:
        reason_counts = {}
        unique_ips = set()
        for log in retrieved_logs:
            reason = log.get("reason", "unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            if "src_ip" in log:
                unique_ips.add(log["src_ip"])
        
        summary_parts = []
        for reason, count in reason_counts.items():
            summary_parts.append(f"{count} logs for {reason}")
        summary = "; ".join(summary_parts)
        if unique_ips:
            summary += f". Unique IPs: {', '.join(sorted(unique_ips))}"
        
        answer = f"Based on {len(retrieved_logs)} logs: {summary}"
    
    return {
        "answer": answer,
        "sources": retrieved_logs,
        "query": question
    }
