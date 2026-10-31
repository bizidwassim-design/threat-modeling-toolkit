#!/usr/bin/env python3
"""
stride_from_dfd.py — generate a STRIDE-per-element threat table from a YAML data-flow model.

Reads a data-flow model (external entities, processes, data stores, data flows, trust
boundaries), applies the classic STRIDE-per-element rules, adds AI-specific threats for
elements flagged `ai: true` / `training_data: true`, and writes:

  <out>/stride-threats.md   Markdown report: summary, Mermaid DFD, element list, threat table
  <out>/stride-threats.csv  the same threats as CSV (stable column order, LF line endings)

Every threat carries a suggested mitigation mapped to OWASP ASVS 5.0 chapter numbers and
ISO/IEC 27001:2022 Annex A control IDs (identifiers only — the standards' text is not reproduced).

Usage:
    pip install pyyaml
    python scripts/stride_from_dfd.py examples/northwind-portal.yaml --out examples/northwind-portal
    python scripts/stride_from_dfd.py model.yaml --validate-only

Output is deterministic: no timestamps, sorted element order as declared, LF newlines.
Licensed under the MIT License. All example data is fictional.
"""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

# --------------------------------------------------------------------------- #
# STRIDE vocabulary
# --------------------------------------------------------------------------- #
STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}

# Classic STRIDE-per-element applicability.
APPLICABLE = {
    "external_entity": "SR",
    "process": "STRIDE",
    "data_store": "TRID",
    "data_flow": "TID",
}

TYPE_LABEL = {
    "external_entity": "External entity",
    "process": "Process",
    "data_store": "Data store",
    "data_flow": "Data flow",
}

# OWASP ASVS 5.0 chapter numbers (used in the legend of the Markdown report).
ASVS_CHAPTERS = {
    "V1": "Encoding and Sanitization",
    "V2": "Validation and Business Logic",
    "V3": "Web Frontend Security",
    "V4": "API and Web Service",
    "V5": "File Handling",
    "V6": "Authentication",
    "V7": "Session Management",
    "V8": "Authorization",
    "V9": "Self-contained Tokens",
    "V10": "OAuth and OIDC",
    "V11": "Cryptography",
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V14": "Data Protection",
    "V15": "Secure Coding and Architecture",
    "V16": "Security Logging and Error Handling",
}

# --------------------------------------------------------------------------- #
# Threat and mitigation library — one entry per (element type, STRIDE letter).
# Text is original. `{name}` and friends are filled from the model.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pattern:
    threat: str
    mitigation: str
    asvs: tuple[str, ...]
    iso: tuple[str, ...]
    suffix: str = ""          # distinguishes several patterns with the same letter (AI extras)


LIBRARY: dict[tuple[str, str], list[Pattern]] = {
    # ---- External entities
    ("external_entity", "S"): [Pattern(
        "Someone or something pretends to be {name} (stolen credentials, replayed token, forged client) and "
        "obtains the access that {name} legitimately has.",
        "Authenticate {name} with a method proportionate to what it can reach: MFA for people, mutual TLS or "
        "signed requests for systems; rotate and revoke credentials; detect impossible-travel and credential-stuffing patterns.",
        ("V6", "V7", "V12"), ("A.5.16", "A.5.17", "A.8.5", "A.8.16"))],
    ("external_entity", "R"): [Pattern(
        "{name} later denies having sent a request or taken an action, and the system cannot prove otherwise.",
        "Log security-relevant actions of {name} with an identity, timestamp and request identifier; protect the "
        "logs from modification; keep them for the period your policy requires.",
        ("V16",), ("A.5.33", "A.8.15", "A.8.17"))],

    # ---- Processes
    ("process", "S"): [Pattern(
        "A rogue component impersonates {name} to its callers or data stores, or {name} accepts a caller it "
        "has not properly identified.",
        "Give {name} its own workload identity (managed identity, mTLS certificate or signed service token); "
        "verify the identity of every caller and every downstream service it talks to; never share credentials between components.",
        ("V6", "V9", "V12"), ("A.5.16", "A.8.5", "A.8.24"))],
    ("process", "T"): [Pattern(
        "Input to {name} is crafted to change its behaviour (injection, parameter manipulation, business-logic "
        "abuse) or its code and configuration are modified without authorisation.",
        "Validate and encode all input at the boundary of {name}; use parameterised queries and safe APIs; "
        "sign or hash deployed artefacts; manage configuration as code with reviewed changes.",
        ("V1", "V2", "V13", "V15"), ("A.8.9", "A.8.26", "A.8.28", "A.8.32"))],
    ("process", "R"): [Pattern(
        "Actions performed through {name} cannot be attributed to a user or a calling system afterwards.",
        "Emit audit events from {name} for authentication, authorisation decisions and data changes, including "
        "the caller identity and a correlation ID; forward them to central, append-only logging.",
        ("V16",), ("A.8.15", "A.8.17"))],
    ("process", "I"): [Pattern(
        "{name} reveals more than it should: verbose errors, debug endpoints, secrets in configuration, or "
        "responses containing data the caller is not entitled to see.",
        "Return generic error messages from {name}; disable debug features in production; keep secrets in a "
        "vault, not in code or environment files; filter responses to the minimum fields the caller needs.",
        ("V8", "V13", "V14", "V16"), ("A.8.3", "A.8.9", "A.8.11", "A.8.12"))],
    ("process", "D"): [Pattern(
        "{name} is overwhelmed or crashed by a flood of requests, expensive operations or malformed input, "
        "making the service unavailable.",
        "Rate-limit and size-limit requests to {name}; set time-outs on every downstream call; autoscale with "
        "an upper bound; test failure modes; monitor saturation and alert.",
        ("V4", "V13"), ("A.8.6", "A.8.14", "A.8.16"))],
    ("process", "E"): [Pattern(
        "A caller of {name} performs an action or reaches data beyond its role, or {name} itself runs with "
        "more privilege than its function needs.",
        "Enforce authorisation on every request inside {name} (object level and function level); run {name} "
        "under a least-privilege identity; separate administrative interfaces from user-facing ones.",
        ("V4", "V8"), ("A.5.15", "A.5.18", "A.8.2", "A.8.3"))],

    # ---- Data stores
    ("data_store", "T"): [Pattern(
        "Records in {name} are modified or deleted without authorisation — through a compromised process, "
        "direct database access or a tampered backup.",
        "Restrict write access to {name} to the processes that need it; keep integrity-checked, immutable "
        "backups; alert on bulk changes; version or checksum critical records.",
        ("V8", "V14"), ("A.5.33", "A.8.3", "A.8.13", "A.8.15"))],
    ("data_store", "R"): [Pattern(
        "Changes to {name} cannot be traced to who or what made them.",
        "Enable change auditing on {name} (who, what, when); protect the audit trail separately from the data.",
        ("V16",), ("A.8.15", "A.8.17"))],
    ("data_store", "I"): [Pattern(
        "Data held in {name} is read by someone who should not see it: exposed storage, stolen backup, "
        "over-broad query, or leakage through logs and exports.",
        "Encrypt {name} at rest with managed keys; limit read access per role; mask or tokenise sensitive "
        "fields; control exports and backups; delete data when it is no longer needed.",
        ("V8", "V11", "V14"), ("A.5.33", "A.8.3", "A.8.10", "A.8.11", "A.8.24"))],
    ("data_store", "D"): [Pattern(
        "{name} becomes unavailable or is filled up — ransomware, deletion, quota exhaustion, corrupted replica.",
        "Back up {name} regularly and test restores; use redundancy appropriate to its criticality; monitor "
        "capacity; isolate backups from production credentials.",
        ("V13",), ("A.8.6", "A.8.13", "A.8.14"))],

    # ---- Data flows
    ("data_flow", "T"): [Pattern(
        "Data in transit on {name} ({protocol}) is modified by a party on the path.",
        "Protect {name} with authenticated encryption (TLS 1.2+ with modern cipher suites, or message "
        "signatures); validate on receipt, not just on send.",
        ("V12", "V11"), ("A.8.20", "A.8.21", "A.8.24"))],
    ("data_flow", "I"): [Pattern(
        "Data carried by {name} ({data}) is read in transit — sniffing, TLS downgrade, misconfigured proxy, "
        "or leakage into intermediaries' logs.",
        "Encrypt {name} end to end; pin or validate certificates; keep sensitive fields out of URLs and "
        "intermediary logs; minimise the data carried to what the receiver needs.",
        ("V12", "V14"), ("A.8.12", "A.8.20", "A.8.24"))],
    ("data_flow", "D"): [Pattern(
        "{name} is blocked, throttled or flooded so that the receiver never gets the data.",
        "Design the receiver of {name} to degrade gracefully (queueing, retries with back-off, cached "
        "fallback); monitor flow latency and error rates.",
        ("V4", "V13"), ("A.8.6", "A.8.14", "A.8.16"))],
}

# AI-specific extras, applied in addition to the classic rules.
AI_PROCESS_EXTRAS: list[tuple[str, Pattern]] = [
    ("T", Pattern(
        "Prompt injection: instructions hidden in user input or in content retrieved by {name} (documents, web "
        "pages, tool results) change what the model does, bypassing the intended task.",
        "Treat all model input as untrusted; separate system instructions from user content; constrain the "
        "model's tools and output format; filter and test with adversarial prompts before and after release.",
        ("V1", "V2", "V4", "V15"), ("A.8.26", "A.8.28", "A.8.29", "A.8.16"),
        suffix="prompt-injection")),
    ("I", Pattern(
        "Model or prompt leakage: {name} reveals its system prompt, retrieved documents from other tenants, or "
        "memorised training data; repeated queries allow the model to be extracted.",
        "Apply tenant and user authorisation to retrieval before the model sees the data; redact personal data "
        "in prompts and logs; rate-limit and monitor query patterns; do not put secrets in prompts.",
        ("V4", "V8", "V14", "V16"), ("A.5.33", "A.8.3", "A.8.12", "A.8.16"),
        suffix="model-leakage")),
    ("E", Pattern(
        "Excessive agency: tools or actions that {name} can trigger run with broader permissions than the "
        "requesting user has, so a manipulated model performs privileged operations.",
        "Give model-invoked tools only the permissions of the requesting user; require human approval for "
        "consequential actions; log every tool call with its initiating request.",
        ("V4", "V8"), ("A.5.15", "A.8.2", "A.8.3", "A.8.15"),
        suffix="excessive-agency")),
    ("D", Pattern(
        "Cost and capacity exhaustion: crafted or looping prompts make {name} consume tokens, GPU time or "
        "third-party quota until the service degrades or the budget is spent.",
        "Cap tokens, context size and tool-call depth per request; set per-user and global quotas; alert on "
        "spend anomalies; fall back to a non-AI path when the model is unavailable.",
        ("V4", "V13"), ("A.8.6", "A.8.16"),
        suffix="resource-exhaustion")),
]

AI_STORE_EXTRAS: list[tuple[str, Pattern]] = [
    ("T", Pattern(
        "Data poisoning: training, fine-tuning or retrieval content in {name} is manipulated so that the model "
        "learns biased, backdoored or harmful behaviour.",
        "Control who can write to {name}; record provenance for every dataset version; validate and sample "
        "data before training; keep signed snapshots so a poisoned version can be identified and rolled back.",
        ("V5", "V8", "V14"), ("A.5.33", "A.8.3", "A.8.9", "A.8.32"),
        suffix="data-poisoning")),
]

# --------------------------------------------------------------------------- #
# Model loading and validation
# --------------------------------------------------------------------------- #
@dataclass
class Element:
    id: str
    type: str
    name: str
    boundary: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Flow:
    id: str
    name: str
    src: str
    dst: str
    protocol: str
    data: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Model:
    name: str
    version: str
    description: str
    boundaries: list[dict[str, str]]
    elements: list[Element]
    flows: list[Flow]

    def element(self, eid: str) -> Element:
        for e in self.elements:
            if e.id == eid:
                return e
        raise KeyError(eid)

    def boundary_name(self, bid: str | None) -> str:
        for b in self.boundaries:
            if b["id"] == bid:
                return b["name"]
        return "(none)"


class ModelError(ValueError):
    pass


def _req(d: dict, key: str, ctx: str) -> Any:
    if key not in d or d[key] in (None, ""):
        raise ModelError(f"{ctx}: missing required field '{key}'")
    return d[key]


def load_model(path: Path) -> Model:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ModelError("top level must be a mapping")
    sysinfo = raw.get("system") or {}
    name = _req(sysinfo, "name", "system")

    boundaries = []
    for b in raw.get("trust_boundaries") or []:
        boundaries.append({"id": str(_req(b, "id", "trust_boundary")), "name": _req(b, "name", "trust_boundary"),
                           "description": b.get("description", "")})
    bids = {b["id"] for b in boundaries}
    if len(bids) != len(boundaries):
        raise ModelError("duplicate trust boundary id")

    elements: list[Element] = []
    for etype, key in (("external_entity", "external_entities"), ("process", "processes"), ("data_store", "data_stores")):
        for item in raw.get(key) or []:
            eid = str(_req(item, "id", key))
            ename = _req(item, "name", f"{key}/{eid}")
            boundary = item.get("boundary")
            if boundary is not None and str(boundary) not in bids:
                raise ModelError(f"{key}/{eid}: unknown boundary '{boundary}'")
            attrs = {k: v for k, v in item.items() if k not in ("id", "name", "boundary")}
            elements.append(Element(eid, etype, ename, None if boundary is None else str(boundary), attrs))
    ids = [e.id for e in elements]
    if len(set(ids)) != len(ids):
        dup = sorted({i for i in ids if ids.count(i) > 1})
        raise ModelError(f"duplicate element id(s): {', '.join(dup)}")
    if not elements:
        raise ModelError("model has no elements")

    flows: list[Flow] = []
    for item in raw.get("data_flows") or []:
        fid = str(_req(item, "id", "data_flows"))
        src, dst = str(_req(item, "from", f"data_flows/{fid}")), str(_req(item, "to", f"data_flows/{fid}"))
        for ref in (src, dst):
            if ref not in ids:
                raise ModelError(f"data_flows/{fid}: unknown element '{ref}'")
        attrs = {k: v for k, v in item.items() if k not in ("id", "name", "from", "to", "protocol", "data")}
        flows.append(Flow(fid, _req(item, "name", f"data_flows/{fid}"), src, dst,
                          str(item.get("protocol", "unspecified")), str(item.get("data", "unspecified")), attrs))
    fids = [f.id for f in flows]
    if len(set(fids)) != len(fids) or set(fids) & set(ids):
        raise ModelError("data flow ids must be unique and distinct from element ids")

    return Model(name, str(sysinfo.get("version", "1.0")), sysinfo.get("description", ""), boundaries, elements, flows)


# --------------------------------------------------------------------------- #
# Threat generation
# --------------------------------------------------------------------------- #
@dataclass
class Threat:
    id: str
    element_id: str
    element_name: str
    element_type: str
    stride: str
    crosses_boundary: str
    priority: str
    threat: str
    mitigation: str
    asvs: str
    iso: str


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "yes", "y", "1")


def _fill(text: str, **kw: str) -> str:
    return text.format(**kw)


def generate(model: Model) -> list[Threat]:
    flows_by_src: dict[str, list[Flow]] = {}
    flows_by_dst: dict[str, list[Flow]] = {}
    crossing: dict[str, bool] = {}
    for fl in model.flows:
        a, b = model.element(fl.src), model.element(fl.dst)
        crossing[fl.id] = (a.boundary != b.boundary)
        flows_by_src.setdefault(fl.src, []).append(fl)
        flows_by_dst.setdefault(fl.dst, []).append(fl)

    threats: list[Threat] = []

    def emit(eid: str, ename: str, etype: str, letter: str, pat: Pattern, counter: dict[str, int],
             crosses: bool, priority: str, **kw: str) -> None:
        counter[letter] = counter.get(letter, 0) + 1
        tid = f"{eid}-{letter}{counter[letter]}"
        threats.append(Threat(
            tid, eid, ename, TYPE_LABEL[etype], f"{letter} — {STRIDE[letter]}",
            "yes" if crosses else "no", priority,
            _fill(pat.threat, name=ename, **kw), _fill(pat.mitigation, name=ename, **kw),
            " ".join(pat.asvs), " ".join(pat.iso)))

    for e in model.elements:
        counter: dict[str, int] = {}
        exposed = any(crossing[f.id] for f in flows_by_dst.get(e.id, []))
        if e.type == "external_entity":
            exposed = exposed or any(crossing[f.id] for f in flows_by_src.get(e.id, []))
        sensitive = _truthy(e.attrs.get("personal_data")) or str(e.attrs.get("classification", "")).lower() in (
            "confidential", "restricted", "secret")
        for letter in APPLICABLE[e.type]:
            if e.type == "process":
                prio = "High" if exposed and letter in "STDE" else "Medium"
            elif e.type == "data_store":
                prio = "High" if sensitive and letter in "TI" else "Medium"
            else:
                prio = "High" if (e.type == "external_entity" and letter == "S" and exposed) else "Medium"
            for pat in LIBRARY[(e.type, letter)]:
                emit(e.id, e.name, e.type, letter, pat, counter, exposed, prio)
        if e.type == "process" and _truthy(e.attrs.get("ai")):
            for letter, pat in AI_PROCESS_EXTRAS:
                emit(e.id, e.name, e.type, letter, pat, counter, exposed, "High")
        if e.type == "data_store" and _truthy(e.attrs.get("training_data")):
            for letter, pat in AI_STORE_EXTRAS:
                emit(e.id, e.name, e.type, letter, pat, counter, False, "High")

    for fl in model.flows:
        counter = {}
        crosses = crossing[fl.id]
        carries_sensitive = _truthy(fl.attrs.get("personal_data")) or _truthy(fl.attrs.get("credentials"))
        for letter in APPLICABLE["data_flow"]:
            if letter == "I":
                prio = "High" if (crosses or carries_sensitive) else "Medium"
            else:
                prio = "High" if crosses else "Medium"
            for pat in LIBRARY[("data_flow", letter)]:
                emit(fl.id, fl.name, "data_flow", letter, pat, counter, crosses, prio,
                     protocol=fl.protocol, data=fl.data)
    return threats


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _mm_label(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def mermaid(model: Model) -> str:
    lines = ["flowchart LR"]
    by_boundary: dict[str | None, list[Element]] = {}
    for e in model.elements:
        by_boundary.setdefault(e.boundary, []).append(e)

    def node(e: Element) -> str:
        label = _mm_label(e.name)
        if e.type == "external_entity":
            return f'    {e.id}["{label}"]'
        if e.type == "process":
            return f'    {e.id}(["{label}"])'
        return f'    {e.id}[("{label}")]'

    for b in model.boundaries:
        members = by_boundary.get(b["id"], [])
        if not members:
            continue
        lines.append(f'    subgraph {b["id"]}["{_mm_label(b["name"])}"]')
        for e in members:
            lines.append("    " + node(e))
        lines.append("    end")
    for e in by_boundary.get(None, []):
        lines.append(node(e))
    for fl in model.flows:
        lines.append(f'    {fl.src} -->|"{fl.id}: {_mm_label(fl.name)} ({_mm_label(fl.protocol)})"| {fl.dst}')
    lines.append("    classDef ee fill:#fff,stroke:#333,stroke-width:1.5px;")
    lines.append("    classDef proc fill:#e8f0fe,stroke:#1f3864,stroke-width:1.5px;")
    lines.append("    classDef store fill:#fff7e6,stroke:#7f6000,stroke-width:1.5px;")
    for etype, cls in (("external_entity", "ee"), ("process", "proc"), ("data_store", "store")):
        ids = [e.id for e in model.elements if e.type == etype]
        if ids:
            lines.append(f"    class {','.join(ids)} {cls};")
    return "\n".join(lines)


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(model: Model, threats: list[Threat], source_name: str) -> str:
    counts = {t: sum(1 for e in model.elements if e.type == t) for t in ("external_entity", "process", "data_store")}
    n_cross = sum(1 for fl in model.flows if model.element(fl.src).boundary != model.element(fl.dst).boundary)
    high = sum(1 for t in threats if t.priority == "High")
    out: list[str] = []
    out.append(f"# STRIDE threat table — {model.name}")
    out.append("")
    out.append(f"Generated by `scripts/stride_from_dfd.py` from `{source_name}` (model version {model.version}). "
               "Do not edit by hand — change the YAML and regenerate.")
    out.append("")
    if model.description:
        out.append(model.description.strip())
        out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Item | Count |")
    out.append("|------|-------|")
    out.append(f"| External entities | {counts['external_entity']} |")
    out.append(f"| Processes | {counts['process']} |")
    out.append(f"| Data stores | {counts['data_store']} |")
    out.append(f"| Data flows | {len(model.flows)} |")
    out.append(f"| Data flows crossing a trust boundary | {n_cross} |")
    out.append(f"| Trust boundaries | {len(model.boundaries)} |")
    out.append(f"| Threats generated | {len(threats)} |")
    out.append(f"| Threats marked High priority | {high} |")
    out.append("")
    out.append("## Data-flow diagram")
    out.append("")
    out.append("```mermaid")
    out.append(mermaid(model))
    out.append("```")
    out.append("")
    out.append("## Elements")
    out.append("")
    out.append("| ID | Type | Name | Trust boundary | Attributes |")
    out.append("|----|------|------|----------------|------------|")
    for e in model.elements:
        attrs = ", ".join(f"{k}={str(v).lower() if isinstance(v, bool) else v}"
                          for k, v in e.attrs.items() if k != "description")
        out.append(f"| {e.id} | {TYPE_LABEL[e.type]} | {_md_cell(e.name)} | {_md_cell(model.boundary_name(e.boundary))} | {_md_cell(attrs)} |")
    out.append("")
    out.append("| ID | Data flow | From | To | Protocol | Data | Crosses boundary |")
    out.append("|----|-----------|------|----|----------|------|------------------|")
    for fl in model.flows:
        a, b = model.element(fl.src), model.element(fl.dst)
        out.append(f"| {fl.id} | {_md_cell(fl.name)} | {fl.src} | {fl.dst} | {_md_cell(fl.protocol)} | {_md_cell(fl.data)} | "
                   f"{'yes' if a.boundary != b.boundary else 'no'} |")
    out.append("")
    out.append("## Threats")
    out.append("")
    out.append("Priority is a starting point, not a verdict: High = the element is reachable across a trust boundary "
               "or holds sensitive data, or the threat is AI-specific. Rate likelihood and impact yourself in the "
               "threat-model template, then decide mitigate / accept / transfer / avoid.")
    out.append("")
    out.append("| Threat ID | Element | Type | STRIDE | Priority | Threat | Suggested mitigation | ASVS 5.0 | ISO 27001 Annex A |")
    out.append("|-----------|---------|------|--------|----------|--------|----------------------|----------|-------------------|")
    for t in threats:
        out.append(f"| {t.id} | {_md_cell(t.element_name)} | {t.element_type} | {t.stride} | {t.priority} | "
                   f"{_md_cell(t.threat)} | {_md_cell(t.mitigation)} | {t.asvs} | {t.iso} |")
    out.append("")
    out.append("## Reference key")
    out.append("")
    out.append("OWASP ASVS 5.0 chapters cited above:")
    out.append("")
    used = sorted({c for t in threats for c in t.asvs.split()}, key=lambda s: int(s[1:]))
    for c in used:
        out.append(f"- {c} — {ASVS_CHAPTERS[c]}")
    out.append("")
    out.append("ISO/IEC 27001:2022 Annex A identifiers are given as IDs only; consult the standard for the control text. "
               "AI-specific threats also relate to ISO/IEC 42001:2023 Annex A.6 (life cycle) and A.7 (data).")
    out.append("")
    return "\n".join(out)


CSV_COLUMNS = ["threat_id", "element_id", "element_name", "element_type", "stride", "crosses_boundary",
               "priority", "threat", "mitigation", "asvs_chapters", "iso27001_annex_a"]


def write_outputs(model: Model, threats: list[Threat], out_dir: Path, source_name: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "stride-threats.md"
    md.write_text(to_markdown(model, threats, source_name), encoding="utf-8", newline="\n")
    csv_path = out_dir / "stride-threats.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CSV_COLUMNS)
        for t in threats:
            w.writerow([t.id, t.element_id, t.element_name, t.element_type, t.stride, t.crosses_boundary,
                        t.priority, t.threat, t.mitigation, t.asvs, t.iso])
    return md, csv_path


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a STRIDE-per-element threat table from a YAML data-flow model.")
    ap.add_argument("model", type=Path, help="YAML data-flow model")
    ap.add_argument("--out", type=Path, default=None, help="output directory (default: <model stem>/ next to the model)")
    ap.add_argument("--validate-only", action="store_true", help="only validate the model, write nothing")
    args = ap.parse_args(argv)

    try:
        model = load_model(args.model)
    except (ModelError, yaml.YAMLError, OSError) as exc:
        print(f"ERROR: {args.model}: {exc}", file=sys.stderr)
        return 2
    threats = generate(model)
    if args.validate_only:
        print(f"OK: {args.model} — {len(model.elements)} elements, {len(model.flows)} flows, {len(threats)} threats")
        return 0
    out_dir = args.out or args.model.with_suffix("")
    md, csv_path = write_outputs(model, threats, out_dir, args.model.name)
    print(f"Wrote {md} and {csv_path} ({len(threats)} threats)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
