# Contributing

Threat models improve with more eyes. Welcome contributions:

* corrections or additions to the threat and mitigation library in `scripts/stride_from_dfd.py`
  (better wording, missing threats, more precise ASVS or ISO 27001 mappings);
* new example models in `examples/` (fictional systems only) with their generated output;
* improvements to the guides, templates and checklists; translations;
* new AI-specific threat patterns, with a short rationale.

## Ground rules

* **Fictional data only.** Example companies are Northwind Logistics, Contoso and Fabrikam. No real organisations,
  people, hostnames, IP addresses, account names or incident details.
* **Original text.** Reference standards by name and identifier (ASVS chapter, ISO 27001 Annex A control ID, ATT&CK
  technique ID); never paste their text.
* Be kind — see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Making a change

1. Fork and branch (`feat/queue-threats`, `fix/asvs-mapping`).
2. Edit the script, a template or a doc.
3. Run the checks CI runs:

   ```bash
   pip install pyyaml pytest
   python -m pytest -q tests/
   python scripts/stride_from_dfd.py examples/northwind-portal.yaml --out examples/northwind-portal
   git diff --exit-code -- examples/northwind-portal/
   ```

   If you changed the library, the generated example changes too: commit the regenerated `stride-threats.md` and
   `.csv` together with the script.
4. Open a pull request describing what changed and why.

## Style

* Threat text: one or two sentences, present tense, names the element, says what the attacker gains.
* Mitigation text: imperative, verifiable, names the element; prefer controls that remove a class of threats.
* Mappings: OWASP ASVS 5.0 chapter numbers (`V1`–`V16`), ISO/IEC 27001:2022 Annex A IDs (`A.5.x`, `A.8.x`).
* Markdown: tables for catalogues, short paragraphs, British English.

## Licensing of contributions

By contributing you agree that your work is released under the repository's [MIT License](LICENSE).
