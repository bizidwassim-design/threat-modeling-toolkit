# Threat Modeling Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/bizidwassim-design/threat-modeling-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/bizidwassim-design/threat-modeling-toolkit/actions/workflows/ci.yml) [![Fictional data](https://img.shields.io/badge/sample%20data-fictional-informational)](SECURITY.md)

A free, open-source toolkit for threat modelling applications with **STRIDE**, **PASTA** and **LINDDUN**: method
guides, Markdown templates, per-phase checklists, a Mermaid data-flow-diagram convention, and a small Python tool that
turns a YAML data-flow model into a **STRIDE-per-element threat table** with mitigations mapped to **OWASP ASVS 5.0**
chapters and **ISO/IEC 27001:2022 Annex A** control IDs. Comes with a fully worked fictional example — a logistics
customer portal with an LLM-based recommendation API.

> 🇫🇷 Résumé en français en bas de page.

## Layout

```
docs/
  choosing-a-method.md        STRIDE vs PASTA vs LINDDUN, decision tree
  dfd-convention.md           Mermaid shapes, IDs, YAML schema read by the generator
  stride-guide.md             the per-element method, AI additions, priority rules
  pasta-guide.md              seven stages trimmed for a small team
  linddun-guide.md            seven privacy threat categories and mitigation strategies
templates/
  threat-model-stride.md      one template per method, ready to copy
  threat-model-pasta.md
  threat-model-linddun.md
checklists/
  01-scoping.md … 05-validation.md
examples/
  northwind-portal.yaml                 fictional data-flow model (13 elements, 14 flows, 6 boundaries)
  northwind-portal/stride-threats.md    generated: summary, Mermaid DFD, element tables, 101 threats
  northwind-portal/stride-threats.csv   generated: same threats for spreadsheets and ticketing
  northwind-portal-worked-example.md    the full exercise: scoping → STRIDE → PASTA → LINDDUN → validation
scripts/
  stride_from_dfd.py          YAML model → Markdown + CSV threat table
tests/
  test_stride_from_dfd.py     unit tests (pytest)
```

## Quick start

```bash
pip install pyyaml
python scripts/stride_from_dfd.py examples/northwind-portal.yaml --out examples/northwind-portal
```

Then:

1. Copy `examples/northwind-portal.yaml`, describe your own system (see [`docs/dfd-convention.md`](docs/dfd-convention.md)).
2. Run the script. Open `stride-threats.md` — the Mermaid diagram renders on GitHub, GitLab and most wikis.
3. Copy [`templates/threat-model-stride.md`](templates/threat-model-stride.md), paste the diagram, and run a
   90-minute workshop on the High-priority rows using [`checklists/03-threat-identification.md`](checklists/03-threat-identification.md).
4. Decide, assign, verify — checklists 4 and 5.

Validate a model without writing anything: `python scripts/stride_from_dfd.py model.yaml --validate-only`.

## What's inside

| Component | What it gives you |
|-----------|-------------------|
| `stride_from_dfd.py` | Classic STRIDE-per-element (entity S R · process STRIDE · store TRID · flow TID), boundary-crossing detection, a priority column, and **AI extras**: prompt injection, model/prompt leakage, excessive agency, cost exhaustion (`ai: true`) and data poisoning (`training_data: true`) |
| Mitigation library | One original mitigation per threat pattern, each mapped to ASVS 5.0 chapter numbers and ISO 27001 Annex A IDs — ready for developers and for the Statement of Applicability |
| Method guides | When to use which method, how to run it in a time-box, common mistakes |
| Templates | Header, scope, decomposition, threat table, mitigation plan, accepted risks, validation record, sign-off |
| Checklists | Scoping · Decomposition · Threat identification · Mitigation · Validation and maintenance |
| Worked example | Northwind Logistics portal + recommendation API: 101 generated threats pruned to 14 + 4 workshop threats, 13 mitigations with standards mapping, 2 PASTA scenarios with an attack tree, 5 LINDDUN privacy threats, validation log |

## Design choices

* **Diagram as code.** The YAML model is the source of truth; the threat table and the Mermaid diagram are generated
  from it in CI, so they cannot drift from each other.
* **Stable IDs.** Threat IDs are `<element>-<letter><n>` (`P4-T2`), so review comments and backlog links survive edits.
* **Priority is not risk.** The script flags where to look first (boundary crossings, sensitive stores, AI components);
  likelihood and impact are scored by people in the template, with the same 1–25 bands as the sibling risk-register workbooks.
* **AI is a first-class element.** Flag a process `ai: true` and a store `training_data: true` and the threats that
  classic STRIDE misses are generated with mitigations.
* **Standards by ID only.** ASVS and ISO 27001 are referenced by chapter and control identifier; no standard text is reproduced.
* **Deterministic output.** No timestamps, LF line endings, sorted as declared — `git diff --exit-code` works.

## Related repositories

| Repository | How it connects |
|------------|-----------------|
| [application-risk-assessment-template](https://github.com/bizidwassim-design/application-risk-assessment-template) | Copy High/Critical threats into the 5×5 risk register; same rating bands |
| [ai-risk-assessment-template](https://github.com/bizidwassim-design/ai-risk-assessment-template) | AI-specific threats feed the ISO/IEC 42001 AI risk register and impact assessment |
| [grc-control-crosswalk](https://github.com/bizidwassim-design/grc-control-crosswalk) | Translate the ISO 27001 Annex A IDs in the mitigations to NIST CSF, CIS and other frameworks |
| [soc-detection-playbooks](https://github.com/bizidwassim-design/soc-detection-playbooks) | Detection rules for the threats you cannot prevent; PASTA actors map to ATT&CK |
| [ciso-executive-dashboard](https://github.com/bizidwassim-design/ciso-executive-dashboard) | Report open High/Critical threats and model age as KPIs |
| [iso27001-iso42001-toolkit](https://github.com/bizidwassim-design/iso27001-iso42001-toolkit) | Statement of Applicability and AI impact assessment template that consume this output |
| [public-scripts](https://github.com/bizidwassim-design/public-scripts) | Other small, reviewable security scripts |

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Run the tests and regenerate the example before opening a pull request.

## Disclaimer

A generated threat table is a starting point, not a security assessment. The mitigations and standards mappings are
indicative and must be adapted to your architecture and your implementation of the controls. Nothing here is legal advice.

## AI assistance

Built with Claude Code as a coding and writing assistant, which is why it appears as a co-author on some commits.
**Editor and reviewer: Wassim Bizid**, who set the scope, the frameworks and the GRC approach, edited the content
and decided what was published. Automated tests in CI check the published outputs. This is a maintainer review,
not an independent one.

## License

[MIT](LICENSE) — free to use, copy, modify and redistribute.

---

## 🇫🇷 Résumé

Boîte à outils **open source** de modélisation des menaces applicatives avec **STRIDE**, **PASTA** et **LINDDUN** :
guides de méthode, modèles Markdown, listes de contrôle par phase, convention de diagramme de flux de données en Mermaid,
et un script Python (`scripts/stride_from_dfd.py`) qui transforme un modèle YAML en **tableau de menaces STRIDE par élément**
(Markdown + CSV) avec des mesures d'atténuation reliées aux chapitres **OWASP ASVS 5.0** et aux identifiants de contrôles
**ISO/IEC 27001:2022 Annexe A**. Les composants d'IA (injection de prompt, fuite de modèle, empoisonnement des données) sont
pris en charge. Exemple complet et fictif : portail client Northwind Logistics et API de recommandation basée sur un LLM. Licence MIT.
