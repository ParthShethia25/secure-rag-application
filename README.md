# Secure RAG Application

A retrieval-augmented generation assistant over fictional Northwind Retail
documents, built to study the trust boundaries RAG introduces.

## Trust boundaries

1. User to app, where role is decided
2. Document to ingestion pipeline, where untrusted content enters
3. Retriever to vector store, where filtering must be enforced
4. Model output to user, where validation happens

## Planned attacks

- Indirect prompt injection through a poisoned document
- Cross-tenant retrieval of HR-only material
- Context exfiltration
- Embedding-space probing

## Objectives

- [ ] Ingestion, embedding, retrieval, generation
- [ ] Two roles with different entitlements
- [ ] Attack suite with before/after evidence
- [ ] Report mapped to LLM01 / LLM02 / LLM08

## Status

In progress.
