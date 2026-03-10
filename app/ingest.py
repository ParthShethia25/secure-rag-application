"""Document ingestion pipeline.

This is trust boundary #2 from the data-flow diagram: untrusted content enters
the system here. Two behaviours are configurable so the "before/after" can be
demonstrated:

* ``sanitize`` — strip HTML/markdown comments and neutralise imperative
  instruction patterns found inside document bodies. Documents are *data*; text
  in them that looks like instructions to the model is the indirect-injection
  payload.
* ``quarantine`` — refuse to ingest a document whose body contains
  instruction-like content, flagging it for review instead of silently
  publishing it into the index.

With both disabled the pipeline is the insecure baseline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.vectorstore import Chunk, VectorStore

CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"

# Patterns that indicate a document is trying to instruct the model rather than
# inform the reader. Tuned against the corpus: policy documents legitimately use
# imperative voice ("Do not discuss open cases"), so the patterns target
# *model-directed* phrasing specifically.
INJECTION_PATTERNS = [
    re.compile(r"ignore (all |the |your )?(previous |above )?instructions", re.I),
    re.compile(r"disregard (all |the |your )?(previous |above )?instructions", re.I),
    re.compile(r"you are now\b", re.I),
    re.compile(r"system (notice|override|prompt)", re.I),
    re.compile(r"maintenance mode", re.I),
    re.compile(r"takes priority over your", re.I),
    re.compile(r"do not (mention|tell) (this|the user)", re.I),
]

COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


@dataclass
class IngestReport:
    ingested: list[str]
    quarantined: list[str]
    sanitized: list[str]

    def summary(self) -> str:
        return (
            f"ingested={len(self.ingested)} "
            f"sanitized={len(self.sanitized)} "
            f"quarantined={len(self.quarantined)}"
        )


def parse_front_matter(raw: str) -> tuple[dict, str]:
    if not raw.startswith("---"):
        return {}, raw
    _, fm, body = raw.split("---", 2)
    meta = {}
    for line in fm.strip().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta, body.strip()


def find_injection(text: str) -> list[str]:
    return [p.pattern for p in INJECTION_PATTERNS if p.search(text)]


def sanitize_text(text: str) -> str:
    """Remove the channels an injection usually rides in on.

    Comments are stripped entirely (a reader never sees them, so nothing of
    value is lost), and any surviving instruction-like line is defanged rather
    than deleted so the document remains readable and the tampering is visible.
    """
    cleaned = COMMENT_RE.sub("", text)
    out_lines = []
    for line in cleaned.splitlines():
        if find_injection(line):
            out_lines.append("[REDACTED: instruction-like content removed during ingestion]")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def chunk_text(text: str, size: int = 700) -> list[str]:
    """Split on blank lines, packing paragraphs up to ``size`` characters."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks, current = [], ""
    for para in paragraphs:
        if current and len(current) + len(para) > size:
            chunks.append(current.strip())
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        chunks.append(current.strip())
    return chunks


def ingest_corpus(
    store: VectorStore,
    corpus_dir: Path | None = None,
    sanitize: bool = True,
    quarantine: bool = True,
) -> IngestReport:
    corpus_dir = corpus_dir or CORPUS_DIR
    report = IngestReport([], [], [])

    for path in sorted(corpus_dir.glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        meta, body = parse_front_matter(raw)
        classification = meta.get("classification", "internal")
        allowed_roles = tuple(
            r.strip() for r in meta.get("allowed_roles", "employee,hr").split(",")
        )

        hits = find_injection(body)
        if hits and quarantine:
            report.quarantined.append(path.name)
            continue
        if hits and sanitize:
            body = sanitize_text(body)
            report.sanitized.append(path.name)
        elif sanitize:
            body = sanitize_text(body)

        for i, piece in enumerate(chunk_text(body)):
            store.add(
                Chunk(
                    id=f"{path.stem}#{i}",
                    text=piece,
                    source=path.name,
                    classification=classification,
                    allowed_roles=allowed_roles,
                )
            )
        report.ingested.append(path.name)

    return report
