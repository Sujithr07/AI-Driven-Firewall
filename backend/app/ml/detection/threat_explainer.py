import json
import os
from dotenv import load_dotenv
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI
from app.rag.prompts import sanitize_event, sanitize_output, build_threat_event_str, get_threat_prompt, get_threat_stream_prompt

load_dotenv()

_explanation_cache: dict = {}


def explain_threat(event: dict) -> str:
    cache_key = (event.get('src_ip'), event.get('reason'), event.get('action'))
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    event = sanitize_event(event)
    prompt = get_threat_prompt()
    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=300,
    )
    chain = prompt | llm | StrOutputParser()
    try:
        result = chain.invoke({"event": build_threat_event_str(event)})
        result = sanitize_output(result)
        _explanation_cache[cache_key] = result
        return result
    except Exception as e:
        return f"Explanation unavailable: {str(e)[:100]}"


def stream_explain_threat(event: dict):
    event = sanitize_event(event)
    prompt = get_threat_stream_prompt()
    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=300,
    )
    chain = prompt | llm | StrOutputParser()
    try:
        for token in chain.stream({"event": build_threat_event_str(event)}):
            yield sanitize_output(token)
    except Exception as e:
        yield f"Explanation unavailable: {str(e)[:100]}"
