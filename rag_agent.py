from rag.chain import answer_query


def answer_log_query(question: str) -> dict:
    return answer_query(question)
