"""Tests for scripts/stride_from_dfd.py — run with `python -m pytest -q tests/`."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import stride_from_dfd as s  # noqa: E402

MINI = {
    "system": {"name": "Mini", "version": "0.1"},
    "trust_boundaries": [{"id": "TB1", "name": "Outside"}, {"id": "TB2", "name": "Inside"}],
    "external_entities": [{"id": "EE1", "name": "User", "boundary": "TB1"}],
    "processes": [
        {"id": "P1", "name": "Web app", "boundary": "TB2"},
        {"id": "P2", "name": "Assistant", "boundary": "TB2", "ai": True},
    ],
    "data_stores": [
        {"id": "DS1", "name": "DB", "boundary": "TB2", "classification": "Confidential"},
        {"id": "DS2", "name": "Corpus", "boundary": "TB2", "training_data": "yes"},
    ],
    "data_flows": [
        {"id": "DF1", "name": "Login", "from": "EE1", "to": "P1", "protocol": "HTTPS", "data": "creds", "credentials": True},
        {"id": "DF2", "name": "Query", "from": "P1", "to": "DS1", "protocol": "TLS", "data": "rows"},
        {"id": "DF3", "name": "Ask", "from": "P1", "to": "P2", "protocol": "HTTPS", "data": "question"},
    ],
}


def write_model(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "model.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return p


def test_classic_counts_per_element_type(tmp_path: Path) -> None:
    model = s.load_model(write_model(tmp_path, MINI))
    threats = s.generate(model)
    by_el = {}
    for t in threats:
        by_el.setdefault(t.element_id, []).append(t)
    assert len(by_el["EE1"]) == 2          # S, R
    assert len(by_el["P1"]) == 6           # STRIDE
    assert len(by_el["P2"]) == 6 + 4       # STRIDE + four AI extras
    assert len(by_el["DS1"]) == 4          # T, R, I, D
    assert len(by_el["DS2"]) == 4 + 1      # + data poisoning
    assert all(len(by_el[f]) == 3 for f in ("DF1", "DF2", "DF3"))  # T, I, D


def test_boundary_crossing_and_priority(tmp_path: Path) -> None:
    model = s.load_model(write_model(tmp_path, MINI))
    threats = {t.id: t for t in s.generate(model)}
    assert threats["DF1-T1"].crosses_boundary == "yes" and threats["DF1-T1"].priority == "High"
    assert threats["DF2-T1"].crosses_boundary == "no" and threats["DF2-T1"].priority == "Medium"
    # P1 receives a crossing flow -> exposed -> S/T/D/E High, R/I Medium
    assert threats["P1-S1"].priority == "High"
    assert threats["P1-R1"].priority == "Medium"
    # Confidential store -> T and I High
    assert threats["DS1-I1"].priority == "High"
    assert threats["DS1-D1"].priority == "Medium"
    # AI extras are always High and have their own ids
    assert threats["P2-T2"].priority == "High" and "Prompt injection" in threats["P2-T2"].threat
    assert "Data poisoning" in threats["DS2-T2"].threat


def test_every_threat_has_mappings(tmp_path: Path) -> None:
    model = s.load_model(write_model(tmp_path, MINI))
    for t in s.generate(model):
        assert t.asvs and all(c in s.ASVS_CHAPTERS for c in t.asvs.split()), t.id
        assert t.iso and all(c.startswith("A.") for c in t.iso.split()), t.id
        assert "{" not in t.threat and "{" not in t.mitigation, t.id


def test_validation_errors(tmp_path: Path) -> None:
    bad = dict(MINI)
    bad["data_flows"] = [{"id": "DF1", "name": "x", "from": "EE1", "to": "NOPE"}]
    with pytest.raises(s.ModelError):
        s.load_model(write_model(tmp_path, bad))
    dup = dict(MINI)
    dup["processes"] = [{"id": "EE1", "name": "clash", "boundary": "TB2"}]
    with pytest.raises(s.ModelError):
        s.load_model(write_model(tmp_path, dup))
    unknown_boundary = dict(MINI)
    unknown_boundary["external_entities"] = [{"id": "EE1", "name": "User", "boundary": "TB9"}]
    with pytest.raises(s.ModelError):
        s.load_model(write_model(tmp_path, unknown_boundary))


def test_outputs_are_deterministic(tmp_path: Path) -> None:
    model = s.load_model(write_model(tmp_path, MINI))
    threats = s.generate(model)
    md1, csv1 = s.write_outputs(model, threats, tmp_path / "a", "model.yaml")
    md2, csv2 = s.write_outputs(model, threats, tmp_path / "b", "model.yaml")
    assert md1.read_bytes() == md2.read_bytes()
    assert csv1.read_bytes() == csv2.read_bytes()
    assert b"\r\n" not in csv1.read_bytes()
    assert csv1.read_text(encoding="utf-8").splitlines()[0] == ",".join(s.CSV_COLUMNS)
    assert "```mermaid" in md1.read_text(encoding="utf-8")


def test_northwind_example_is_current() -> None:
    model = s.load_model(ROOT / "examples" / "northwind-portal.yaml")
    threats = s.generate(model)
    expected = (ROOT / "examples" / "northwind-portal" / "stride-threats.md").read_text(encoding="utf-8")
    assert s.to_markdown(model, threats, "northwind-portal.yaml") == expected
