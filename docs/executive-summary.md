# Executive Summary — Internal RAG Assistant Security Review

**One page. For leadership. No AI expertise assumed.**

---

## What we tested

An internal assistant that answers employee questions by reading company
documents — policies, IT guides, and HR files including salary bands and open
disciplinary cases.

We tested it as **Dana, an ordinary employee with no HR access**.

## What we found

**All five attacks succeeded.** Two matter most:

**1. Every employee could read HR-confidential files.**
Dana asked "what are the salary bands for a regional manager and director?" and
got them. She asked about disciplinary cases and got named records of live
investigations. The files were correctly labelled as HR-only — the system simply
never checked the label before searching them.

**2. A tampered document could give the assistant orders.**
Someone had added hidden text to the IT VPN guide — invisible when you read the
document normally. When Dana asked a completely ordinary question ("how do I
connect to the VPN?"), the assistant obeyed the hidden text instead of answering
her, and disclosed restricted information.

This second one is the important one to understand. **Dana did nothing wrong and
typed nothing suspicious.** The attack was placed in a document weeks earlier.
Anyone who can edit a document that the assistant reads — a wiki page, a shared
drive file, a supplier's PDF — can change how the assistant behaves for
everyone.

## Why this happened

Two root causes:

1. **Access labels existed but were never enforced.** The system knew which
   documents were HR-only. It just never asked that question before searching.
2. **The system could not tell a document's words from its own instructions.**
   Everything arrived as one block of text, so text inside a document had the
   same authority as the rules we wrote.

## What we changed

Four controls. The critical one: **the assistant now only ever searches the
documents you personally have permission to read.** Restricted files are not
filtered out of the answer — they are never looked at. Nothing was found, so
nothing can slip out.

We also strip hidden instructions from documents as they are loaded, label all
document content as untrusted data, and check every answer before it is shown.

## Where we are now

**Zero out of five attacks succeed.** HR staff still have full access to HR
files. Employees still get normal answers.

| | Before | After |
|---|---|---|
| Attacks succeeding | 5 / 5 | **0 / 5** |
| Employees able to read HR files | Yes | **No** |
| Hidden document instructions obeyed | Yes | **No** |
| HR staff's own access | Working | Working |

**One decision worth highlighting.** Our first fix removed the tampered VPN
guide from the system entirely. It stopped the attack — and also meant nobody
could get VPN help. An attacker could have taken down any document just by
editing it. We changed the approach: we now remove the hidden instructions and
keep the document. Security that breaks the tool people need is not a fix.

## Remaining risk: LOW-MEDIUM

Our document-scanning catches the patterns we know about; a novel one could get
through. We designed for that: even if the assistant is completely fooled, it
can only reveal documents the person asking was already allowed to read.

## What we recommend next

1. **Treat document changes like code changes** — review before anything enters
   the assistant's library. This is currently the weakest link.
2. **Alert on blocked attempts.** Right now, an employee repeatedly probing for
   salary data is stopped silently. We should know it happened.
3. **Move to finer-grained permissions** — currently whole-document; some files
   need field-level control.

## Decision needed from leadership

- Confirm the **data-protection position** on the pre-fix exposure: employees
  could access personal data in live disciplinary cases. Legal and the DPO
  should determine whether this build ever ran outside the lab.
- Approve **document review-on-change** as a required process before the
  assistant is connected to shared drives or the company wiki.
