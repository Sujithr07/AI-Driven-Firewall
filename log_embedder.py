from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import json
import os


class LogEmbedder:
    def __init__(self):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.index = faiss.IndexFlatL2(384)
        self.log_store = []

    def add_logs(self, logs: list[dict]):
        for log in logs:
            search_string = f"{log.get('src_ip', '')} {log.get('protocol', '')} {log.get('reason', '')} {log.get('action', '')} {log.get('severity', '')}"
            embedding = self.model.encode([search_string], convert_to_numpy=True)
            self.index.add(embedding)
            self.log_store.append(log)

    def search(self, query: str, k: int = 8) -> list[dict]:
        query_embedding = self.model.encode([query], convert_to_numpy=True)
        distances, indices = self.index.search(query_embedding, k)
        results = []
        for idx in indices[0]:
            if idx < len(self.log_store):
                results.append(self.log_store[idx])
        return results

    def save(self, path="data/faiss.index"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        faiss.write_index(self.index, path)
        with open(path.replace(".index", "_logs.json"), "w") as f:
            json.dump(self.log_store, f)

    def load(self, path="data/faiss.index"):
        if os.path.exists(path):
            self.index = faiss.read_index(path)
            logs_path = path.replace(".index", "_logs.json")
            if os.path.exists(logs_path):
                with open(logs_path, "r") as f:
                    self.log_store = json.load(f)


embedder = LogEmbedder()
embedder.load()
