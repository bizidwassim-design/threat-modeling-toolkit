# STRIDE guide

STRIDE is a checklist of six things that can go wrong, applied to each element of a data-flow diagram. It is fast,
teachable in an hour, and good enough for most application reviews. This guide explains the method as used in this
toolkit and how the generator fits in.

## The six categories

| Letter | Threat | Property violated | Ask yourself |
|--------|--------|-------------------|--------------|
| **S** | Spoofing | Authentication | Can someone pretend to be this user, service or device? |
| **T** | Tampering | Integrity | Can data or code be modified in transit, at rest or in memory without detection? |
| **R** | Repudiation | Non-repudiation | Can an actor deny having done something because we cannot prove it? |
| **I** | Information disclosure | Confidentiality | Can data reach someone not entitled to it? |
| **D** | Denial of service | Availability | Can the component be made slow, unavailable or too expensive to run? |
| **E** | Elevation of privilege | Authorisation | Can an actor do more than their role allows? |

## STRIDE per element

Not every category applies to every element. The toolkit uses the classic mapping:

| Element type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| External entity | ✔ | | ✔ | | | |
| Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Data store | | ✔ | ✔ | ✔ | ✔ | |
| Data flow | | ✔ | | ✔ | ✔ | |

The mapping is a prompt, not a law. If a data flow *can* be spoofed in your architecture (unauthenticated webhook,
for example), add the threat manually.

## AI additions

Systems that embed a model (chat assistant, recommendation engine, document classifier) have threats the classic list
does not name. The generator adds, for any process flagged `ai: true`:

| Extra threat | STRIDE letter | Why it matters |
|--------------|---------------|----------------|
| Prompt injection | T | Untrusted content (user text, retrieved documents, tool output) changes what the model does |
| Model and prompt leakage | I | System prompts, other tenants' retrieved data or memorised training data are exposed; model extraction by repeated queries |
| Excessive agency | E | Tools the model can call run with more permission than the requesting user |
| Cost and capacity exhaustion | D | Crafted prompts burn tokens, GPU time or third-party quota |

and for any data store flagged `training_data: true`:

| Extra threat | STRIDE letter | Why it matters |
|--------------|---------------|----------------|
| Data poisoning | T | Manipulated training, fine-tuning or retrieval content teaches the model wrong or harmful behaviour |

## The process in five phases

Each phase has a checklist in [`../checklists/`](../checklists/).

1. **Scope** — what is in, what is out, who owns it, what are the crown jewels, which compliance regimes apply.
2. **Decompose** — draw the DFD following the [convention](dfd-convention.md). Stop when every boundary crossing and
   every sensitive store is visible.
3. **Identify threats** — run `scripts/stride_from_dfd.py` on the YAML model to get the baseline table, then do a
   workshop to prune generic threats, add system-specific ones and rate likelihood and impact.
4. **Mitigate** — decide per threat. Write mitigations as verifiable requirements ("all admin endpoints require MFA
   and are not reachable from the internet"), map them to ASVS chapters and ISO 27001 Annex A controls, and put them
   in the backlog.
5. **Validate** — confirm the mitigations exist (code review, test, configuration check, pen-test finding), update the
   model, set the next-review trigger.

## Using the generator

```bash
pip install pyyaml
python scripts/stride_from_dfd.py examples/northwind-portal.yaml --out examples/northwind-portal
```

Outputs `stride-threats.md` (summary, Mermaid DFD, element tables, threat table) and `stride-threats.csv` (import into
a spreadsheet, a ticketing tool or the risk register).

What the priority column means:

| Priority | Set when |
|----------|----------|
| High | the element receives a flow that crosses a trust boundary (processes: S, T, D, E) · the data store is marked Confidential/Restricted or holds personal data (T, I) · the flow crosses a boundary, or carries credentials or personal data (I) · the threat is AI-specific |
| Medium | everything else |

Priority tells you where to spend workshop time first. It is not a risk score; score likelihood and impact in the template.

## Pruning generic threats without losing the real ones

The generator produces around eight threats per process and three per flow. In the workshop:

* Collapse duplicates: if three internal flows share the same mTLS mesh, keep one Tampering/Disclosure threat and
  note the others as "same control".
* Delete what the architecture already rules out — but write *why* in the decision column, so the next reviewer does
  not re-add it.
* Add the threats only a human sees: business-logic abuse, race conditions, misuse of a legitimate feature, insider
  paths. These are usually the ones that matter.

## Mapping to standards

Every generated mitigation carries OWASP ASVS 5.0 chapter numbers (so a developer can look up the verification
requirements) and ISO/IEC 27001:2022 Annex A control IDs (so the GRC team can link the threat model to the Statement of
Applicability). The mapping is indicative; adjust it to how your organisation has implemented the controls.
