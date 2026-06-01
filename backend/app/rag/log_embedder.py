from app.rag.chain import add_logs as _add_logs, search_logs as _search_logs


class LogEmbedder:
    def add_logs(self, logs: list[dict]) -> None:
        _add_logs(logs)

    def search(self, query: str, k: int = 8) -> list[dict]:
        return _search_logs(query, k)

    def save(self, path: str = "data/faiss.index") -> None:
        pass  # ChromaDB persists automatically on each write

    def load(self, path: str = "data/faiss.index") -> None:
        pass  # ChromaDB loads automatically from persist_directory on init


embedder = LogEmbedder()
