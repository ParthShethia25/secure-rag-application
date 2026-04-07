"""Vector store with query-time metadata filtering.

Chroma is the reference implementation for this project (see README), but the
security properties being demonstrated — tenant/role filtering enforced *during*
the search rather than after it — are independent of the backend. This local
implementation keeps the lab dependency-free and deterministic so the attack
suite reproduces in CI.

Embeddings are TF-IDF vectors fitted over the ingested corpus. They are not a
transformer, and they do not need to be: the vulnerabilities under test concern
access control and trust, not retrieval quality. TF-IDF is used rather than a
plain bag of words because ranking has to be good enough that a restricted
document genuinely is the nearest neighbour for a targeted query — otherwise the
cross-tenant test would "pass" for the wrong reason.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


@dataclass
class Chunk:
    id: str
    text: str
    source: str
    classification: str  # "public" | "internal" | "hr-confidential"
    allowed_roles: tuple[str, ...]
    tf: Counter = field(default_factory=Counter)


class VectorStore:
    """TF-IDF index. IDF is recomputed as documents are added."""

    def __init__(self) -> None:
        self._chunks: list[Chunk] = []
        self._df: Counter = Counter()
        self._idf: dict[str, float] = {}

    def add(self, chunk: Chunk) -> None:
        chunk.tf = Counter(tokenize(chunk.text))
        self._chunks.append(chunk)
        for term in set(chunk.tf):
            self._df[term] += 1
        self._refit()

    def _refit(self) -> None:
        n = len(self._chunks)
        self._idf = {
            term: math.log((n + 1) / (df + 1)) + 1.0 for term, df in self._df.items()
        }

    def _vector(self, tf: Counter) -> dict[str, float]:
        vec = {t: c * self._idf.get(t, 0.0) for t, c in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    def _similarity(self, query_vec: dict[str, float], chunk: Chunk) -> float:
        chunk_vec = self._vector(chunk.tf)
        shared = set(query_vec) & set(chunk_vec)
        return sum(query_vec[t] * chunk_vec[t] for t in shared)

    def __len__(self) -> int:
        return len(self._chunks)

    def all_chunks(self) -> list[Chunk]:
        return list(self._chunks)

    def search(
        self,
        query: str,
        k: int = 4,
        allowed_roles: tuple[str, ...] | None = None,
    ) -> list[tuple[Chunk, float]]:
        """Similarity search.

        ``allowed_roles`` is the security-critical parameter. When supplied the
        candidate set is filtered *before* ranking, so a document the caller may
        not read is never a candidate — it cannot be surfaced by a cleverly
        worded query, and it never reaches the prompt builder.

        When it is None (the insecure configuration) every chunk is a candidate
        regardless of who is asking. That single difference is the cross-tenant
        finding.
        """
        candidates = self._chunks
        if allowed_roles is not None:
            candidates = [
                c for c in candidates if any(r in c.allowed_roles for r in allowed_roles)
            ]
        query_vec = self._vector(Counter(tokenize(query)))
        scored = [(c, self._similarity(query_vec, c)) for c in candidates]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return [pair for pair in scored[:k] if pair[1] > 0]
