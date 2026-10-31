# LINDDUN guide (privacy threat modelling)

LINDDUN does for privacy what STRIDE does for security: it gives you seven categories of things that can go wrong for
the people whose data flows through your system. Run it alongside STRIDE whenever personal data is involved, and feed
the result into a DPIA or an ISO/IEC 42001 AI system impact assessment.

## The seven categories

| Letter | Threat | Plain-language question | Typical example |
|--------|--------|-------------------------|-----------------|
| **L** | Linking | Can data items or actions be associated with the same person, even without a name? | Session IDs, device fingerprints and order history joined across services |
| **I** | Identifying | Can a person be singled out from the data? | A "pseudonymous" dataset that still contains delivery addresses |
| **N** | Non-repudiation | Can a person be unable to deny an action or attribute when they should be able to? | Immutable logs of a sensitive choice (health-related delivery instructions) kept longer than needed |
| **D** | Detecting | Can someone learn that data about a person exists, without reading it? | "Account already exists" error on sign-up; timing differences |
| **D** | Data disclosure | Is personal data exposed to parties who should not have it? | Full customer record sent to a third-party model API |
| **U** | Unawareness and unintervenability | Are people unaware of what is collected, or unable to exercise their rights? | No notice that an AI recommendation uses support tickets; no way to opt out |
| **N** | Non-compliance | Does processing deviate from law, policy or stated purpose? | Data collected for delivery used to train a marketing model |

(The classic acronym reads **L-I-N-D-D-U-N**; the two D's are Detecting and Data disclosure.)

## Where threats appear

Use the same DFD as for STRIDE. Mark every flow and store that carries personal data (`personal_data: true` in the
YAML). Then apply the categories:

| Element | Most relevant categories |
|---------|--------------------------|
| Data flow carrying personal data | Linking, Identifying, Data disclosure |
| Data store with personal data | Identifying, Data disclosure, Non-repudiation, Non-compliance |
| Process that combines data sources | Linking, Identifying, Unawareness |
| External entity (third party receiving data) | Data disclosure, Non-compliance, Unawareness |
| AI process trained on or retrieving personal data | all seven — memorisation, inference, purpose drift |

## Mitigation strategies

For each threat, choose a strategy, then a concrete technique:

| Strategy | What it does | Techniques |
|----------|--------------|------------|
| **Minimise** | Collect and keep less | Drop fields, shorten retention, aggregate, sample |
| **Separate** | Keep data apart so it cannot be linked | Separate stores per purpose, tenant isolation, different identifiers per context |
| **Abstract** | Make data less precise | Generalise (city instead of address), bucket ages, round timestamps |
| **Hide** | Make data unreadable to unauthorised parties | Encryption, pseudonymisation, tokenisation, access control, private channels |
| **Inform** | Tell people what happens | Privacy notice at the point of collection, AI disclosure, model cards |
| **Control** | Let people act | Consent, opt-out, access/export/erasure, human review of automated decisions |
| **Enforce** | Make the policy real | Purpose tags on data, retention jobs, audit, contracts with processors |
| **Demonstrate** | Prove it | Records of processing, DPIA, logs of rights requests, test evidence |

## Running a LINDDUN session (two hours)

1. **Prepare** (security + product, 30 minutes before): DFD with personal-data flows highlighted; list of data
   categories per store; the purposes you told users about.
2. **Walk the flows** (60 minutes): for each highlighted flow and store, ask the seven questions. Capture threats in
   the [LINDDUN template](../templates/threat-model-linddun.md) with the affected data subjects.
3. **Rate** (20 minutes): likelihood and severity for the *individual*, not the company. A low-probability leak of
   health-related delivery notes can still be severe.
4. **Decide** (30 minutes): strategy, technique, owner. Note the legal basis and whether a DPIA is required.
5. **Hand over**: privacy/legal gets the table; engineering gets the backlog items; the AI governance lead gets the
   AI-specific findings for the impact assessment.

## Links to other frameworks

| Framework | How LINDDUN output is used |
|-----------|----------------------------|
| GDPR Art. 35 DPIA | Threat table becomes the "risks to rights and freedoms" section |
| ISO/IEC 27001:2022 | A.5.34 (privacy and PII), A.8.10 (deletion), A.8.11 (masking), A.8.12 (leakage prevention) |
| ISO/IEC 27701 | Evidence for PIMS risk assessment |
| ISO/IEC 42001:2023 | Input to clause 6.1.4 AI system impact assessment and Annex A.5 / A.7 |
| EU AI Act | Transparency obligations for AI interacting with people map to *Unawareness* threats |

Clause and control numbers are references only; read the standards for the requirements.
