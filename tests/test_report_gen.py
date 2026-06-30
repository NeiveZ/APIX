"""Tests for modules/report_gen.py."""
import json
import os

from modules.report_gen import ReportGenerator

SAMPLE_FINDINGS = {
    "api/fuzz": [
        {"severity": "HIGH", "check": "Endpoint Found", "endpoint": "GET https://api.test/admin",
         "detail": "HTTP 200"},
        {"severity": "INFO", "check": "Endpoint Found", "endpoint": "GET https://api.test/health",
         "detail": "HTTP 200"},
    ],
    "api/auth": [
        {"severity": "CRITICAL", "check": "JWT alg:none", "endpoint": "https://api.test/me",
         "detail": "JWT accepts unsigned tokens"},
    ],
}
SAMPLE_STATS = {"id": "ABCD1234", "started": "2026-06-30 10:00:00", "scans": 2,
                 "results": 3, "reports": 0}


def test_generate_creates_a_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = ReportGenerator(SAMPLE_FINDINGS, SAMPLE_STATS)
    path = gen.generate(fmt="txt", filename="test_report")
    assert os.path.isfile(path)


def test_unknown_format_returns_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = ReportGenerator(SAMPLE_FINDINGS, SAMPLE_STATS)
    assert gen.generate(fmt="pdf") is None


def test_json_report_contains_all_findings_and_correct_severity_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = ReportGenerator(SAMPLE_FINDINGS, SAMPLE_STATS)
    path = gen.generate(fmt="json", filename="test_report")
    with open(path) as f:
        data = json.load(f)
    assert data["summary"]["total"] == 3
    assert data["summary"]["high"] == 2   # HIGH + CRITICAL both count
    assert data["meta"]["session"]["id"] == "ABCD1234"


def test_html_report_embeds_endpoint_and_is_well_formed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = ReportGenerator(SAMPLE_FINDINGS, SAMPLE_STATS)
    path = gen.generate(fmt="html", filename="test_report")
    with open(path) as f:
        html = f.read()
    assert "<!DOCTYPE html>" in html
    assert "https://api.test/admin" in html


def test_empty_findings_html_shows_no_findings_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = ReportGenerator({}, SAMPLE_STATS)
    path = gen.generate(fmt="html", filename="empty_report")
    with open(path) as f:
        html = f.read()
    assert "No findings" in html
