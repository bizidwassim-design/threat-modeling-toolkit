# Checklist 4 — Mitigation and decisions

A threat without a decision is a liability. Every threat leaves this phase as Mitigate, Accept, Transfer or Avoid.

## Decisions

- [ ] Critical and High threats are decided in the room, with the system owner present.
- [ ] Each Mitigate decision becomes a **verifiable requirement**, not a wish: "all admin endpoints require
      phishing-resistant MFA" rather than "improve admin security".
- [ ] Each Accept decision records why, who accepted (role) and a review date; acceptance of a High threat is signed by senior management.
- [ ] Transfer decisions name the contract, insurance or provider responsibility — and the part that is **not** transferred.
- [ ] Avoid decisions name the feature or data that is removed.

## Writing good mitigations

- [ ] One mitigation can cover several threats; list all threat IDs it covers.
- [ ] Prefer controls that remove a class of threats (central authorisation middleware, service mesh mTLS, managed secrets) over per-endpoint fixes.
- [ ] Each mitigation maps to OWASP ASVS 5.0 chapter(s) so developers can find the verification requirements, and to
      ISO/IEC 27001:2022 Annex A control IDs so GRC can trace it in the Statement of Applicability. AI mitigations also
      reference ISO/IEC 42001:2023 Annex A.6 / A.7.
- [ ] Each mitigation has a verification method: code review, automated test, configuration check, pen-test case, monitoring alert.
- [ ] Detection is considered as a mitigation: if a threat cannot be prevented, can it be detected quickly?

## Backlog and ownership

- [ ] Every mitigation has a backlog item (ticket ID), an owner (role) and a target date proportionate to the band:
      Critical within 30 days with an interim control now; High within 90 days; Medium next planning cycle.
- [ ] Interim controls for Critical threats are in place before the workshop ends or the next business day.
- [ ] High and Critical threats are copied to the organisation's risk register with the model ID as reference.

## Output of this phase

Sections 4 and 5 of the template: mitigation plan and accepted risks, all with owners and dates.
