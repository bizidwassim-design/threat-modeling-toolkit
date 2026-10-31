# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] — 2026-10-31

### Added
- Initial public release.
- Method guides for STRIDE, PASTA and LINDDUN and a guide to choosing between them.
- Markdown templates for each method and five per-phase checklists.
- Data-flow-diagram convention in Mermaid.
- `scripts/stride_from_dfd.py`: generates a STRIDE-per-element threat table (Markdown + CSV) from a YAML
  data-flow model, with mitigations mapped to OWASP ASVS chapters and ISO/IEC 27001:2022 Annex A control IDs.
- Fully worked fictional example: Northwind Logistics customer portal and AI recommendation API.
- Continuous integration: parses the script, runs the tests, regenerates the example output and fails if it drifts.
