import os
from typing import Generator
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
from rag.embeddings import get_embeddings
from rag.prompts import get_prompt

load_dotenv()

_CHROMA_DIR = "data/chroma_db"
_COLLECTION = "firewall_logs"

_vectorstore: Chroma | None = None


def _get_vectorstore() -> Chroma:
    global _vectorstore
    if _vectorstore is None:
        _vectorstore = Chroma(
            collection_name=_COLLECTION,
            embedding_function=get_embeddings(),
            persist_directory=_CHROMA_DIR,
        )
    return _vectorstore


def _format_docs(docs: list[Document]) -> str:
    return "\n".join(doc.page_content for doc in docs)


def add_logs(logs: list[dict]) -> None:
    docs = []
    for log in logs:
        content = (
            f"[{log.get('timestamp', 'N/A')}] "
            f"src={log.get('src_ip', 'N/A')} "
            f"proto={log.get('protocol', 'N/A')} "
            f"action={log.get('action', 'N/A')} "
            f"severity={log.get('severity', 'N/A')} "
            f"reason={log.get('reason', 'N/A')}"
        )
        metadata = {k: str(v) for k, v in log.items() if v is not None}
        docs.append(Document(page_content=content, metadata=metadata))
    if docs:
        _get_vectorstore().add_documents(docs)


def search_logs(
    query: str,
    k: int = 8,
    severity: str | None = None,
    protocol: str | None = None,
) -> list[dict]:
    where: dict = {}
    if severity:
        where["severity"] = severity
    if protocol:
        where["protocol"] = protocol

    retriever = _get_vectorstore().as_retriever(
        search_kwargs={"k": k, **({"filter": where} if where else {})}
    )
    docs = retriever.invoke(query)
    return [doc.metadata for doc in docs]


def _make_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=400,
    )


def stream_answer(
    question: str, k: int = 8
) -> tuple[list[dict], Generator[str, None, None]]:
    """Retrieve sources, then return a generator that streams LLM tokens.

    Returns (sources, token_generator). Caller iterates the generator to
    consume tokens while sources are available immediately.
    """
    retriever = _get_vectorstore().as_retriever(search_kwargs={"k": k})
    source_docs = retriever.invoke(question)
    sources = [doc.metadata for doc in source_docs]
    context = _format_docs(source_docs)

    chain = get_prompt() | _make_llm() | StrOutputParser()

    def _gen() -> Generator[str, None, None]:
        for chunk in chain.stream({"context": context, "question": question}):
            yield chunk

    return sources, _gen()


def answer_query(question: str, k: int = 8) -> dict:
    retriever = _get_vectorstore().as_retriever(search_kwargs={"k": k})

    rag_chain = (
        {"context": retriever | _format_docs, "question": RunnablePassthrough()}
        | get_prompt()
        | _make_llm()
        | StrOutputParser()
    )

    try:
        source_docs = retriever.invoke(question)
        answer = rag_chain.invoke(question)
        return {
            "answer": answer,
            "sources": [doc.metadata for doc in source_docs],
            "query": question,
        }
    except Exception:
        retrieved = search_logs(question, k)
        reason_counts: dict[str, int] = {}
        unique_ips: set[str] = set()
        for log in retrieved:
            reason = log.get("reason", "unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            if "src_ip" in log:
                unique_ips.add(log["src_ip"])
        parts = [f"{c} logs for {r}" for r, c in reason_counts.items()]
        summary = "; ".join(parts)
        if unique_ips:
            summary += f". Unique IPs: {', '.join(sorted(unique_ips))}"
        return {
            "answer": f"Based on {len(retrieved)} logs: {summary}",
            "sources": retrieved,
            "query": question,
        }
