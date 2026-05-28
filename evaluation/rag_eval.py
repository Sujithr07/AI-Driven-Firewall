"""
evaluation/rag_eval.py — RAGAS-based RAG quality evaluation for the firewall log RAG system.

Metrics:
    Faithfulness       — answer is grounded in retrieved context (no hallucination)
    Answer Relevancy   — answer addresses the question
    Context Precision  — retrieved chunks are relevant / well-ranked
    Context Recall     — context covers what the reference answer requires

Usage:
    python evaluation/rag_eval.py
    python -c "from evaluation.rag_eval import run_evaluation; run_evaluation()"
"""

import os
import sys
import json
import datetime
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ragas imports ChatVertexAI from a path removed in langchain-community >= 0.4.
# Inject a stub before ragas loads so the import resolves without VertexAI installed.
from types import ModuleType as _ModuleType
if "langchain_community.chat_models.vertexai" not in sys.modules:
    _stub = _ModuleType("langchain_community.chat_models.vertexai")
    _stub.ChatVertexAI = type("ChatVertexAI", (), {})  # type: ignore[attr-defined]
    sys.modules["langchain_community.chat_models.vertexai"] = _stub

from dotenv import load_dotenv
load_dotenv()

# ── Test set: security log questions with reference answers ───────────────────

EVAL_QUESTIONS = [
    {
        "question": "Which source IP addresses have been blocked the most?",
        "reference": (
            "The most frequently blocked source IPs show repeated connection attempts "
            "that trigger multiple firewall rules. High block counts from a single IP "
            "indicate persistent scanning, brute force campaigns, or botnet activity."
        ),
    },
    {
        "question": "Are there any port scan attempts detected in the logs?",
        "reference": (
            "Port scan attempts appear as a single source IP making connections to many "
            "different destination ports in rapid succession. The firewall classifies these "
            "as TCP SYN scans and blocks them with high or critical severity."
        ),
    },
    {
        "question": "What protocols are most commonly involved in blocked traffic?",
        "reference": (
            "TCP is the most frequently blocked protocol due to port scans and brute force "
            "attempts. UDP blocks typically involve DNS amplification or flood attacks. "
            "ICMP traffic may also be blocked when used in reconnaissance sweeps."
        ),
    },
    {
        "question": "What are the most common reasons for blocking firewall connections?",
        "reference": (
            "Common block reasons include port scanning, brute force login attempts against "
            "SSH or HTTP endpoints, connections from known malicious IP addresses, and "
            "traffic patterns that deviate significantly from normal baseline behavior."
        ),
    },
    {
        "question": "Were there any critical severity events in the logs?",
        "reference": (
            "Critical severity events represent the highest-priority threats, including "
            "active exploitation attempts, connections from known threat actors, SYN flood "
            "attacks, and brute force attacks against RDP or SSH services."
        ),
    },
    {
        "question": "Which source IPs show signs of brute force attacks?",
        "reference": (
            "Brute force attacks are identified by repeated failed authentication attempts "
            "from a single source IP against SSH (port 22), RDP (port 3389), or HTTP login "
            "endpoints within a short time window, often exceeding hundreds of attempts."
        ),
    },
    {
        "question": "How many SSH connections were blocked and why?",
        "reference": (
            "SSH connections are blocked when source IPs exceed login attempt thresholds, "
            "originate from known malicious IP ranges, or exhibit timing patterns consistent "
            "with automated credential stuffing tools targeting port 22."
        ),
    },
    {
        "question": "Are there any DNS-based attacks or suspicious DNS traffic in the logs?",
        "reference": (
            "DNS-based attacks include amplification attacks using spoofed source IPs to "
            "reflect large responses, DNS tunneling for data exfiltration through encoded "
            "subdomains, and fast-flux DNS used to obscure command-and-control servers."
        ),
    },
    {
        "question": "What network traffic patterns indicate a potential DDoS attack?",
        "reference": (
            "DDoS patterns include high-volume SYN floods from multiple source IPs targeting "
            "specific ports, UDP floods exhausting bandwidth, and application-layer attacks "
            "with repeated requests to the same endpoint from distributed sources."
        ),
    },
    {
        "question": "Which blocked connections involved known malicious IP addresses?",
        "reference": (
            "Connections from known malicious IPs are flagged using threat intelligence "
            "databases and IP reputation feeds. These are immediately blocked with critical "
            "severity and may trigger additional network isolation or alerting workflows."
        ),
    },
]

# ── Synthetic log seeds (injected when the Chroma collection is empty) ────────

SEED_LOGS = [
    # Port scan — 192.168.1.105
    {"timestamp": "2025-01-15T08:23:41Z", "src_ip": "192.168.1.105", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "port_scan"},
    {"timestamp": "2025-01-15T08:23:42Z", "src_ip": "192.168.1.105", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "port_scan"},
    {"timestamp": "2025-01-15T08:23:43Z", "src_ip": "192.168.1.105", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "port_scan"},
    {"timestamp": "2025-01-15T08:23:44Z", "src_ip": "192.168.1.105", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "port_scan"},
    # SSH brute force — 10.0.0.45
    {"timestamp": "2025-01-15T09:11:05Z", "src_ip": "10.0.0.45", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "brute_force_ssh"},
    {"timestamp": "2025-01-15T09:11:07Z", "src_ip": "10.0.0.45", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "brute_force_ssh"},
    {"timestamp": "2025-01-15T09:11:09Z", "src_ip": "10.0.0.45", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "brute_force_ssh"},
    {"timestamp": "2025-01-15T09:11:11Z", "src_ip": "10.0.0.45", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "brute_force_ssh"},
    # DNS amplification — 172.16.0.200
    {"timestamp": "2025-01-15T10:05:22Z", "src_ip": "172.16.0.200", "protocol": "UDP",
     "action": "blocked", "severity": "high", "reason": "dns_amplification"},
    {"timestamp": "2025-01-15T10:05:23Z", "src_ip": "172.16.0.200", "protocol": "UDP",
     "action": "blocked", "severity": "high", "reason": "dns_amplification"},
    # Normal traffic (allowed)
    {"timestamp": "2025-01-15T10:30:00Z", "src_ip": "10.1.1.10", "protocol": "TCP",
     "action": "allowed", "severity": "low", "reason": "normal_traffic"},
    {"timestamp": "2025-01-15T10:30:01Z", "src_ip": "10.1.1.11", "protocol": "HTTPS",
     "action": "allowed", "severity": "low", "reason": "normal_traffic"},
    # Known malicious IP — 185.220.101.47 (Tor exit node)
    {"timestamp": "2025-01-15T11:45:00Z", "src_ip": "185.220.101.47", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "known_malicious_ip"},
    {"timestamp": "2025-01-15T11:45:01Z", "src_ip": "185.220.101.47", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "known_malicious_ip"},
    {"timestamp": "2025-01-15T11:45:02Z", "src_ip": "185.220.101.47", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "known_malicious_ip"},
    # SYN flood / DDoS — multiple sources
    {"timestamp": "2025-01-15T14:20:00Z", "src_ip": "203.0.113.5", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "syn_flood"},
    {"timestamp": "2025-01-15T14:20:00Z", "src_ip": "203.0.113.6", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "syn_flood"},
    {"timestamp": "2025-01-15T14:20:01Z", "src_ip": "203.0.113.7", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "syn_flood"},
    {"timestamp": "2025-01-15T14:20:01Z", "src_ip": "203.0.113.8", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "syn_flood"},
    # HTTP brute force — 198.51.100.23
    {"timestamp": "2025-01-15T15:00:00Z", "src_ip": "198.51.100.23", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "http_brute_force"},
    {"timestamp": "2025-01-15T15:00:05Z", "src_ip": "198.51.100.23", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "http_brute_force"},
    {"timestamp": "2025-01-15T15:00:10Z", "src_ip": "198.51.100.23", "protocol": "TCP",
     "action": "blocked", "severity": "high", "reason": "http_brute_force"},
    # DNS tunneling — 10.0.0.99
    {"timestamp": "2025-01-15T16:30:00Z", "src_ip": "10.0.0.99", "protocol": "UDP",
     "action": "blocked", "severity": "high", "reason": "dns_tunneling"},
    {"timestamp": "2025-01-15T16:30:05Z", "src_ip": "10.0.0.99", "protocol": "UDP",
     "action": "blocked", "severity": "high", "reason": "dns_tunneling"},
    # RDP brute force — 45.33.32.156
    {"timestamp": "2025-01-15T17:00:00Z", "src_ip": "45.33.32.156", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "rdp_brute_force"},
    {"timestamp": "2025-01-15T17:00:02Z", "src_ip": "45.33.32.156", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "rdp_brute_force"},
    {"timestamp": "2025-01-15T17:00:04Z", "src_ip": "45.33.32.156", "protocol": "TCP",
     "action": "blocked", "severity": "critical", "reason": "rdp_brute_force"},
]


# ── Pipeline helpers ──────────────────────────────────────────────────────────

def _seed_vectorstore_if_empty() -> None:
    from rag.chain import _get_vectorstore, add_logs
    vs = _get_vectorstore()
    count = vs._collection.count()
    if count == 0:
        print(f"  Vectorstore empty — seeding {len(SEED_LOGS)} synthetic logs.")
        add_logs(SEED_LOGS)
    else:
        print(f"  Vectorstore has {count} existing documents.")


def _query_with_contexts(question: str, k: int = 6) -> dict:
    """Run the RAG pipeline and return the answer plus raw retrieved page_content strings."""
    from rag.chain import _get_vectorstore, _make_llm, _format_docs
    from rag.prompts import get_prompt, sanitize_query
    from langchain_core.output_parsers import StrOutputParser

    question = sanitize_query(question)
    retriever = _get_vectorstore().as_retriever(search_kwargs={"k": k})
    source_docs = retriever.invoke(question)
    context = _format_docs(source_docs)

    chain = get_prompt() | _make_llm() | StrOutputParser()
    try:
        answer = chain.invoke({"context": context, "question": question})
    except Exception:
        answer = f"Retrieved {len(source_docs)} log entries. Context: {context[:300]}"

    return {
        "answer": answer,
        "retrieved_contexts": [doc.page_content for doc in source_docs],
    }


def _build_eval_samples(k: int = 6) -> list[dict]:
    samples = []
    for i, item in enumerate(EVAL_QUESTIONS, 1):
        q = item["question"]
        print(f"  [{i}/{len(EVAL_QUESTIONS)}] {q[:70]}...")
        result = _query_with_contexts(q, k=k)
        samples.append({
            "user_input": q,
            "response": result["answer"],
            "retrieved_contexts": result["retrieved_contexts"],
            "reference": item["reference"],
        })
    return samples


# ── RAGAS evaluation ──────────────────────────────────────────────────────────

def _run_ragas(samples: list[dict]) -> dict[str, float]:
    """
    Score samples with RAGAS. Tries v0.2+ API first; falls back to v0.1.x.
    Returns {metric_name: score} for all four metrics.
    """
    try:
        return _run_ragas_v2(samples)
    except (ImportError, AttributeError, TypeError) as e:
        print(f"  RAGAS v0.2+ API unavailable ({e}), trying v0.1.x...")
        return _run_ragas_v1(samples)


def _run_ragas_v2(samples: list[dict]) -> dict[str, float]:
    """RAGAS >= 0.2 — EvaluationDataset API."""
    from ragas import evaluate
    from ragas.dataset_schema import SingleTurnSample, EvaluationDataset
    from ragas.llms import LangchainLLMWrapper
    from ragas.embeddings import LangchainEmbeddingsWrapper
    from langchain_google_genai import ChatGoogleGenerativeAI
    from rag.embeddings import get_embeddings

    # Import metrics (names changed between minor versions)
    try:
        from ragas.metrics import Faithfulness, AnswerRelevancy, ContextPrecision, ContextRecall
    except ImportError:
        from ragas.metrics import (
            Faithfulness,
            AnswerRelevancy,
            LLMContextPrecision as ContextPrecision,
            LLMContextRecall as ContextRecall,
        )

    llm = LangchainLLMWrapper(ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        max_output_tokens=512,
    ))
    emb = LangchainEmbeddingsWrapper(get_embeddings())

    metrics = [
        Faithfulness(llm=llm),
        AnswerRelevancy(llm=llm, embeddings=emb),
        ContextPrecision(llm=llm),
        ContextRecall(llm=llm),
    ]

    ragas_samples = [
        SingleTurnSample(
            user_input=s["user_input"],
            response=s["response"],
            retrieved_contexts=s["retrieved_contexts"],
            reference=s["reference"],
        )
        for s in samples
    ]
    result = evaluate(dataset=EvaluationDataset(samples=ragas_samples), metrics=metrics)
    return {str(k): float(v) for k, v in result.items()}


def _run_ragas_v1(samples: list[dict]) -> dict[str, float]:
    """RAGAS 0.1.x — HuggingFace Dataset API."""
    from ragas import evaluate
    from ragas.metrics import faithfulness, answer_relevancy, context_precision, context_recall
    from datasets import Dataset

    dataset = Dataset.from_dict({
        "question":     [s["user_input"] for s in samples],
        "answer":       [s["response"] for s in samples],
        "contexts":     [s["retrieved_contexts"] for s in samples],
        "ground_truth": [s["reference"] for s in samples],
    })
    result = evaluate(
        dataset,
        metrics=[faithfulness, answer_relevancy, context_precision, context_recall],
    )
    return {str(k): float(v) for k, v in result.items()}


# ── MLflow logging ────────────────────────────────────────────────────────────

def _log_to_mlflow(
    scores: dict[str, float],
    params: dict,
    samples: list[dict],
) -> None:
    try:
        import mlflow
        from mlops.tracking import TRACKING_URI, MLFLOW_AVAILABLE
        if not MLFLOW_AVAILABLE:
            print("  MLflow unavailable — skipping.")
            return

        mlflow.set_tracking_uri(TRACKING_URI)
        mlflow.set_experiment("firewall/rag-evaluation")
        run_name = f"ragas-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        with mlflow.start_run(run_name=run_name):
            # Sanitize metric keys (MLflow rejects "/" and spaces)
            mlflow.log_metrics({k.replace("/", "_").replace(" ", "_"): v for k, v in scores.items()})
            mlflow.log_params(params)

            # Upload per-sample details as a JSON artifact
            tmp = os.path.join(tempfile.gettempdir(), "ragas_samples.json")
            with open(tmp, "w") as f:
                json.dump(samples, f, indent=2)
            mlflow.log_artifact(tmp, artifact_path="evaluation")
            os.unlink(tmp)

        print(f"  Run '{run_name}' logged to 'firewall/rag-evaluation'.")
    except Exception as e:
        print(f"  MLflow logging failed: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def run_evaluation(
    output_path: str = "data/rag_eval_results.json",
    k: int = 6,
) -> dict:
    """
    Full evaluation pipeline:
      1. Seed Chroma with synthetic logs if the collection is empty
      2. Run each test question through the RAG pipeline
      3. Score all samples with RAGAS (Faithfulness, Answer Relevancy,
         Context Precision, Context Recall)
      4. Log scores and metadata to MLflow
      5. Write a JSON report to output_path

    Returns the report dict.
    """
    print("\n=== RAG Evaluation with RAGAS ===\n")

    print("[1/4] Checking vectorstore...")
    _seed_vectorstore_if_empty()

    print(f"\n[2/4] Querying RAG pipeline ({len(EVAL_QUESTIONS)} questions, k={k})...")
    samples = _build_eval_samples(k=k)

    print("\n[3/4] Computing RAGAS metrics...")
    scores = _run_ragas(samples)

    print("\n  Scores:")
    for name, val in scores.items():
        print(f"    {name}: {val:.4f}")

    params = {
        "num_questions": len(samples),
        "retrieval_k": k,
        "llm_model": "gemini-1.5-flash",
        "embedding_model": "all-MiniLM-L6-v2",
        "vectorstore": "chroma",
    }

    print("\n[4/4] Logging to MLflow...")
    _log_to_mlflow(scores, params, samples)

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "scores": scores,
        "params": params,
        "samples": samples,
    }
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved → {output_path}")
    print("\n=== Done ===\n")
    return report


if __name__ == "__main__":
    run_evaluation()
