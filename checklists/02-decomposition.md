# Checklist 2 — Decomposition (the data-flow diagram)

The diagram is where threats hide or show. Follow [`docs/dfd-convention.md`](../docs/dfd-convention.md).

## Completeness

- [ ] Every external entity that sends or receives data is drawn — people, partner systems, SaaS, model providers, carriers, monitoring.
- [ ] Every process that transforms data is drawn, including batch jobs, queue consumers, schedulers and model-serving services.
- [ ] Every data store is drawn, including caches, object storage, log stores, backups, vector indexes and message queues that persist data.
- [ ] Every data flow has an ID, a name, a protocol and the data it carries.
- [ ] Administrative paths are drawn (admin consoles, CI/CD deploys, database maintenance access), not only the user path.
- [ ] Logging and audit flows are drawn — their absence is itself a finding.

## Trust boundaries

- [ ] Every element sits inside exactly one trust boundary.
- [ ] Boundaries reflect reality: internet, edge, application zone, data zone, third party, corporate network, build pipeline.
- [ ] Every flow crossing a boundary is visible and labelled; nothing "tunnels" through an unlabelled arrow.
- [ ] Identity changes at boundaries are noted: where user identity is replaced by a service identity.

## Attributes the generator uses

- [ ] `ai: true` on processes that call or host a model.
- [ ] `training_data: true` on stores used for training, fine-tuning or retrieval.
- [ ] `classification` and `personal_data` on stores; `credentials` and `personal_data` on flows.

## Sanity checks

- [ ] A developer who was not in the room can read the diagram and recognise the system.
- [ ] The YAML validates: `python scripts/stride_from_dfd.py model.yaml --validate-only`.
- [ ] No secrets, hostnames, IP addresses or account names appear in names or descriptions.
- [ ] Level of detail is right: if a process hides a trust boundary or a sensitive store inside it, split it.

## Output of this phase

A YAML model (or a hand-drawn Mermaid block), the entry-point table and the roles/permissions table in the template.
