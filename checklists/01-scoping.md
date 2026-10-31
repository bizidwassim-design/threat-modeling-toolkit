# Checklist 1 — Scoping

Use before the first workshop. If more than two items are unanswered, the workshop will drift.

## Ownership and trigger

- [ ] A named system owner (role) has agreed to the exercise and will receive the result.
- [ ] The trigger is recorded: new system, significant change, periodic review, incident, regulatory change.
- [ ] A facilitator and the minimum participants are booked: architect or lead developer, product owner, security.
- [ ] The model ID and storage location are decided (the model lives next to the code or in the architecture repo).

## Boundaries

- [ ] What is in scope is listed by component and environment (production only? pre-production too?).
- [ ] What is out of scope is listed **with the reason** and the model that covers it (identity provider, shared platform).
- [ ] Third parties and managed services the system depends on are named, with what they receive and return.
- [ ] Any AI or machine-learning component is identified, including third-party model APIs.

## What matters

- [ ] Crown jewels are stated: the three to five data sets or capabilities whose loss hurts most.
- [ ] Security objectives are written in business language (3–6 statements).
- [ ] The compliance context is noted: personal data (and whose), regulated sector, contractual clauses, certification scope.
- [ ] The impact scale to be used is agreed (reuse the organisation's 1–5 risk scale).

## Method

- [ ] Method chosen with [`docs/choosing-a-method.md`](../docs/choosing-a-method.md): STRIDE / + LINDDUN / + PASTA.
- [ ] Existing inputs collected: architecture diagrams, previous models, pen-test reports, scan results, incident history.
- [ ] Time-box agreed: a STRIDE model of a mid-sized system should fit in two workshops of 90 minutes.

## Output of this phase

A filled header and section 1 of the template, and a list of inputs for the decomposition workshop.
