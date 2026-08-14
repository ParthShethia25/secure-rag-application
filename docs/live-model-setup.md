# Running the RAG attack suite against a live model

The app defaults to `MockModel`, a deterministic stand-in that obeys
instructions it finds inside retrieved context. That behaviour is the whole
point of the lab — it is exactly what indirect prompt injection exploits, and
making it deterministic is what lets the before/after evidence in
`docs/security-report.md` be reproducible.

Pointing the app at a real model tests something the mock cannot: whether a
model that has *some* resistance to injection still falls to a payload buried in
a retrieved document. That is the finding this project exists to produce, so it
is worth running at least once against live inference.

## Backend options

| Backend | `RAG_MODEL` | Needs |
|---|---|---|
| Deterministic mock (default) | `mock` | nothing |
| Local Ollama | `ollama` | Ollama installed, a model pulled |
| Any OpenAI-compatible endpoint | `openai` | a base URL and an API key |

## Option A — a local FreeLLMAPI gateway

[FreeLLMAPI](https://github.com/tashfeenahmed/freellmapi) aggregates the free
tiers of many providers behind a single OpenAI-compatible endpoint.

**It is a router, not a source of credentials.** You supply your own free-tier
keys from upstream providers; it routes across them and handles failover. With
no provider keys configured, every request fails with
`no_providers_configured`.

```bash
git clone https://github.com/tashfeenahmed/freellmapi.git
cd freellmapi && npm install && npm run build && npm start -w server
```

Then open <http://localhost:3001>, create the first account, and add free-tier
keys under **Keys** (Groq, Google AI Studio, Cerebras, Mistral and OpenRouter
all offer self-service free keys). Full walkthrough:
[`01-ai-red-teaming-lab/docs/live-model-setup.md`](../../01-ai-red-teaming-lab/docs/live-model-setup.md).

## Configure the app

```bash
cp .env.example .env      # then edit .env
```

```ini
RAG_MODEL=openai
LLM_BASE_URL=http://localhost:3001/v1
LLM_API_KEY=freellmapi-...
LLM_MODEL=auto
```

`.env` is gitignored. Never commit the key.

## Running the suite

```bash
# Vulnerable baseline — all controls off
RAG_MODEL=openai python -m attacks.suite --insecure

# Hardened retest — ACL, trust labels and output validation on
RAG_MODEL=openai python -m attacks.suite
```

## What to watch for with a live model

The three attacks degrade differently once a real model is in the loop:

**Cross-tenant leakage** is unaffected. The retrieval ACL filters candidates
before the model is called at all, so the model never sees HR chunks it should
not. This attack's result should be identical on mock and live — if it is not,
the ACL has a bug worth finding.

**Indirect prompt injection** is where live results diverge most. A capable
model may partially resist a payload the mock always obeys. Resistance is not a
control: record it as a model-behaviour observation, not as a mitigation. The
trust-label and output-validation controls are what the report should credit,
because they hold regardless of which model is deployed.

**Context exfiltration** depends heavily on how verbose the model is. A chatty
model may paraphrase restricted content without reproducing the `HR-CONF-*`
marker the scorer looks for — which would score as a pass while still leaking.
If you test this against a live model, read the raw responses in `results/`
rather than trusting the scorer alone. This limitation is documented as residual
risk R-3 in `docs/security-report.md`.

## Reproducibility caveat

Live models vary between runs even at `temperature=0`. Run the suite several
times and record a pass rate rather than a single result. Keep CI on the mock
backend so guardrail regressions are never masked by model variance.
