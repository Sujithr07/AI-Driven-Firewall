import os
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.checkpoint.memory import InMemorySaver
from dotenv import load_dotenv
from agents.tools import (
    query_logs,
    get_threat_stats,
    explain_detection,
    check_ip_reputation,
    suggest_action,
)

load_dotenv()

_TOOLS = [query_logs, get_threat_stats, explain_detection, check_ip_reputation, suggest_action]

_SYSTEM = (
    "You are a network security analyst AI assistant integrated with a live firewall monitoring system. "
    "You have access to five tools:\n"
    "  • query_logs — semantic search over historical security logs\n"
    "  • get_threat_stats — real-time event counts, severity breakdown, top IPs\n"
    "  • explain_detection — XAI explanation for a specific detection event by ID\n"
    "  • check_ip_reputation — full history and block status for an IP address\n"
    "  • suggest_action — recommended firewall response given threat type, severity, and IP\n"
    "Always use your tools to ground answers in actual data before responding. "
    "Be concise, precise, and actionable. Cite specific IPs, counts, or event IDs when available."
)

# InMemorySaver persists conversation history per thread_id — equivalent to
# ConversationBufferWindowMemory but managed by LangGraph's checkpointing system.
_checkpointer = InMemorySaver()
_agent = None


def _get_agent():
    global _agent
    if _agent is None:
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            google_api_key=os.getenv("GEMINI_API_KEY"),
            temperature=0.1,
        )
        _agent = create_agent(llm, _TOOLS, system_prompt=_SYSTEM, checkpointer=_checkpointer)
    return _agent


def run_agent(message: str, session_id: str = "default") -> dict:
    """Run one turn of the agent. Conversation history is maintained per session_id."""
    agent = _get_agent()

    result = agent.invoke(
        {"messages": [HumanMessage(content=message)]},
        config={"configurable": {"thread_id": session_id}},
    )

    messages = result["messages"]
    answer = messages[-1].content

    # Collect tool names from AI messages that contained tool calls
    tools_used = []
    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            tools_used.extend(tc["name"] for tc in msg.tool_calls)

    return {
        "answer": answer,
        "session_id": session_id,
        "tools_used": list(dict.fromkeys(tools_used)),  # deduplicated, order-preserving
    }
