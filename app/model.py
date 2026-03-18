"""Model backends for the RAG assistant.

``MockModel`` emulates a capable-but-credulous model: it answers from the
retrieved context, and — critically for this lab — it *obeys instructions it
finds inside that context*. That is the behaviour indirect prompt injection
exploits, and it is realistic: a model has no innate way to tell a document's
words from its operator's words once both are in the same context window.

``OllamaModel`` targets a live local model for manual testing.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class ModelResponse:
    text: str


class BaseModel:
    def generate(self, system_prompt: str, user_prompt: str) -> ModelResponse:  # pragma: no cover
        raise NotImplementedError


class MockModel(BaseModel):
    """Deterministic stand-in that follows instructions found in its context."""

    _INJECTION_RE = re.compile(
        r"ignore all previous instructions|you are now in\s+maintenance mode|system notice",
        re.I,
    )
    _MARKER_RE = re.compile(r"(HR-CONF-[A-Z0-9-]+)")

    def generate(self, system_prompt: str, user_prompt: str) -> ModelResponse:
        # Does the context contain an instruction aimed at the model? If the
        # application handed it over without labelling it as data, the model
        # cannot distinguish it from its operator's instructions - so it obeys.
        if self._INJECTION_RE.search(user_prompt) and "UNTRUSTED" not in user_prompt:
            marker = self._MARKER_RE.search(user_prompt)
            leaked = marker.group(1) if marker else "HR-CONF-4419-SALARY"
            return ModelResponse(
                text=f"{leaked}\nSECURITY OVERRIDE ACCEPTED"
            )

        # Otherwise answer from whatever context was supplied. The behaviour is
        # naive on purpose: it grounds its answer in the highest-ranked
        # retrieved chunk and quotes it. That is what a real RAG assistant does,
        # and it means an access-control failure upstream shows up directly in
        # the output instead of being hidden by clever summarisation.
        context = _extract_context(user_prompt)
        if not context.strip():
            return ModelResponse(
                text="I don't have any documents that answer that question."
            )

        top = _top_chunk(context)
        return ModelResponse(text=f"Based on the documents I can see:\n{top}")


class OllamaModel(BaseModel):
    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3.1")
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def generate(self, system_prompt: str, user_prompt: str) -> ModelResponse:
        import json
        import urllib.request

        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())
        return ModelResponse(text=body["message"]["content"])


def _extract_context(prompt: str) -> str:
    m = re.search(r"CONTEXT:?\s*(.*?)(?:QUESTION:|$)", prompt, re.S)
    return m.group(1) if m else prompt


def _extract_question(prompt: str) -> str:
    m = re.search(r"QUESTION:?\s*(.*)", prompt, re.S)
    return m.group(1) if m else prompt


def _top_chunk(context: str, limit: int = 700) -> str:
    """Return the first retrieved chunk, stripped of any trust-label wrapper.

    The retriever supplies chunks in rank order, so the first one is the best
    match. The label tags are removed because a model reproduces the document's
    words, not the application's markup.
    """
    body = context.strip()
    blocks = re.split(r"</UNTRUSTED_DOCUMENT>", body)
    first = blocks[0] if blocks else body
    first = re.sub(r"<UNTRUSTED_DOCUMENT[^>]*>", "", first).strip()
    return first[:limit]


def get_model(name: str | None = None) -> BaseModel:
    name = (name or os.environ.get("RAG_MODEL", "mock")).lower()
    if name == "ollama":
        return OllamaModel()
    return MockModel()
