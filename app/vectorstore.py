"""Minimal vector store with metadata filtering.

Chroma is the reference implementation for this project (see README), but the
security properties being demonstrated — tenant/role filtering enforced at
query time, not after retrieval — are independent of the backend. This local
implementation keeps the lab dependency-free and deterministic so the attack
suite reproduces in CI.

The embedding is a hashed bag-of-words vector. It is not semantically clever,
and it does not need to be: the vulnerabilities under test are about *access
control and trust*, not retrieval quality.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field

EMBED_DIM = 256


def embed(text: str) -> list[float]:
    """Deterministic hashed bag-of-words embedding, L2-normalised."""
    vec = [0.0] * EMBED_DIM
    for token in re.findall(r"[a-z0-9]+", text.lower()):
        h = int(hashlib.md5(token.encode()).hexdigest(), 16)
        vec[h % EMBED_DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


@dataclass
class Chunk:
    id: str
    text: str
    source: str
    classification: str  # "public" | "internal" | "hr-confidential"
    allowed_roles: tuple[str, ...]
    embedding: list[float] = field(default_factory=list)


class VectorStore:
    def __init__(self) -> None:
        self._chunks: list[Chunk] = []

    def add(self, chunk: Chunk) -> None:
        if not chunk.embedding:
            chunk.embedding = embed(chunk.text)
        self._chunks.append(chunk)

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

        ``allowed_roles`` is the security-critical parameter. When supplied, the
        candidate set is filtered *before* ranking, so a document the caller may
        not see is never a candidate — it cannot be surfaced by a cleverly
        worded query, and it never reaches the prompt builder.

        When it is None (the insecure configuration) every chunk in the store is
        a candidate regardless of who is asking.
        """
        candidates = self._chunks
        if allowed_roles is not None:
            candidates = [
                c for c in candidates
                if any(r in c.allowed_roles for r in allowed_roles)
            ]
        q = embed(query)
        scored = [(c, cosine(q, c.embedding)) for c in candidates]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return [pair for pair in scored[:k] if pair[1] > 0]
