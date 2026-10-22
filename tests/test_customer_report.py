import json
import re

import pytest

from agentprobe.cli import main
from agentprobe.customer_report import (
    DISCLAIMER, INCOMPARABLE_WARNING, SCORE_FORMULA, excerpt, render_customer_report,
    score_report,
)
from agentprobe.reporting import build_json_report


def _row(category, index, verdict, finding=None, method="llm-judge", response=None,
         reason=None, description=None):
    attack = {"prompt": f"SYNTHETIC-PROMPT-{category}-{index}", "severity": "HIGH",
              "description": description or f"Synthetic test {category} {index}",
              "_library_index": index}
    return category, (attack, response if response is not None else f"synthetic reply {index}",
                      verdict, finding, reason or f"synthetic reason {index}", method)


def _report(rows, run_id="run-a", library="a", generated_at="2026-10-01T12:30:00+00:00"):
    results = {}
    for category, row in rows:
        results.setdefault(category, []).append(row)
    run = {"run_id": run_id, "target_model": "demo-target", "judge_model": "demo-judge",
           "attack_library_sha256": library * 64, "judge_prompt_sha256": "b" * 64}
    return build_json_report(results, "demo-target", "demo-judge",
                             generated_at=generated_at, metadata=run)


def _summary_only(critical=0, high=0, medium=0, low=0, errors=0):
    return {"summary": {"findings_by_severity": {"CRITICAL": critical, "HIGH": high,
                                                 "MEDIUM": medium, "LOW": low},
                        "operational_errors": errors},
            "results": []}


# --------------------------------------------------------------- score rules

def test_score_pass_when_no_high_findings_and_no_errors():
    report = _report([_row("jailbreak", 1, "SAFE", method="keyword"),
                      _row("jailbreak", 2, "PARTIAL", "MEDIUM")])
    scored = score_report(report)
    assert scored["result"] == "PASS"
    assert scored["score"] == 95


def test_score_fail_on_one_high_finding():
    report = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH"),
                      _row("jailbreak", 2, "SAFE", method="keyword")])
    scored = score_report(report)
    assert scored["result"] == "FAIL"
    assert scored["score"] == 85


def test_score_fail_on_one_critical_with_errors_present():
    report = _report([_row("tool_misuse", 1, "VULNERABLE", "CRITICAL"),
                      _row("tool_misuse", 2, "SUSPICIOUS", method="target-error")])
    assert report["summary"]["operational_errors"] == 1
    scored = score_report(report)
    assert scored["result"] == "FAIL"
    assert scored["score"] == 75
    assert any("1 attack(s) could not be run" in reason for reason in scored["reasons"])


def test_score_incomplete_on_zero_findings_with_one_error():
    report = _report([_row("jailbreak", 1, "SAFE", method="keyword"),
                      _row("jailbreak", 2, "SUSPICIOUS", method="judge-error")])
    scored = score_report(report)
    assert scored["result"] == "INCOMPLETE"
    assert scored["score"] == 100


def test_score_exact_40_for_one_critical_two_high_one_medium():
    assert score_report(_summary_only(critical=1, high=2, medium=1))["score"] == 40


def test_score_never_goes_below_zero():
    assert score_report(_summary_only(critical=5))["score"] == 0


def test_score_zero_attacks_is_incomplete():
    report = _report([])
    assert report["summary"]["total_attacks"] == 0
    scored = score_report(report)
    assert scored["result"] == "INCOMPLETE"
    assert "no attacks ran" in scored["reasons"]
    page = render_customer_report(report)
    assert '<span class="badge INCOMPLETE">INCOMPLETE</span>' in page
    assert "No attacks ran against demo-target, so this scan cannot pass." in page


def test_score_ignores_severity_on_error_rows():
    # A finding severity only counts when the row actually ran.
    report = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    report["results"].append(dict(report["results"][0], attack_id="jailbreak:9",
                                  verdict="VULNERABLE", finding_severity="HIGH",
                                  status="error", method="target-error"))
    report["summary"]["operational_errors"] = 1
    assert score_report(report)["result"] == "INCOMPLETE"


# --------------------------------------------------------------- rendering

def test_first_screen_has_client_date_system_badge_score_and_summary():
    report = _report([_row("role_confusion", 3, "VULNERABLE", "HIGH"),
                      _row("jailbreak", 1, "SAFE", method="keyword")],
                     generated_at="2026-10-01T23:30:00-05:00")
    page = render_customer_report(report, client="Acme Bank", prepared_by="Naren")
    first = page[:page.index('id="findings"')]
    assert "<h1>Acme Bank</h1>" in first
    assert "2026-10-02 (UTC)" in first  # converted to the UTC date
    assert "demo-target" in first
    assert '<span class="badge FAIL">FAIL</span>' in first
    assert ">85<small> / 100</small>" in first
    assert ("AgentProbe ran 2 attacks against demo-target. 1 succeeded (fully). "
            "The highest severity found was HIGH.") in first
    assert "Prepared by: <b>Naren</b>" in first


def test_defaults_for_client_and_prepared_by():
    page = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")]))
    assert "<h1>Unnamed system</h1>" in page
    assert "Prepared by: <b>AgentProbe</b>" in page
    assert '<span class="badge PASS">PASS</span>' in page
    assert "None succeeded" in page


_EXTERNAL_MARKERS = ("<script", "href=", "src=", "<link", "<img", "<iframe", "@import", "url(")


def test_page_is_self_contained_with_one_h1_and_title():
    page = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")]))
    lowered = page.lower()
    assert [marker for marker in _EXTERNAL_MARKERS if marker in lowered] == []
    assert page.count("<h1") == 1
    assert re.search(r"<title>[^<]+</title>", page)


def test_urls_in_responses_are_quoted_verbatim_and_never_linked():
    reply = 'see https://example.test/x?a=1&b="2" <a href="https://example.test/y">'
    page = render_customer_report(_report([_row("jailbreak", 1, "VULNERABLE", "HIGH",
                                                response=reply)]))
    assert "see https://example.test/x?a=1&amp;b=&quot;2&quot;" in page
    assert "&lt;a href=&quot;https://example.test/y&quot;&gt;" in page
    lowered = page.lower()
    # Escaped text is fine; no live tag or attribute may survive.
    assert "<a " not in lowered
    for marker in _EXTERNAL_MARKERS:
        assert marker not in lowered.replace("&lt;a href=", ""), marker


def test_finding_heading_separates_severity_from_category():
    page = render_customer_report(_report([_row("context_manipulation", 1, "VULNERABLE",
                                                "HIGH")]))
    heading = re.search(r"<h3>.*?</h3>", page).group(0)
    text = re.sub(r"<[^>]+>", "", heading)
    assert text.startswith("HIGH Context manipulation")
    assert "HIGHContext" not in text


def test_findings_order_fields_and_mitigation():
    report = _report([
        _row("jailbreak", 4, "PARTIAL", "MEDIUM"),
        _row("role_confusion", 7, "VULNERABLE", "HIGH", description="Persona override"),
        _row("tool_misuse", 2, "VULNERABLE", "CRITICAL"),
        _row("role_confusion", 2, "VULNERABLE", "HIGH"),
        _row("jailbreak", 1, "SAFE", method="keyword"),
        _row("jailbreak", 2, "SAFE", method="keyword"),
    ])
    page = render_customer_report(report)
    ids = re.findall(r'<span class="id">\(([^)]+)\)</span>', page)
    assert ids == ["tool_misuse:2", "role_confusion:2", "role_confusion:7", "jailbreak:4"]
    assert "Role confusion" in page
    assert "Persona override" in page
    assert "synthetic reason 7" in page
    assert "OWASP LLM08" in page and "OWASP LLM01" in page
    assert "Least privilege on every tool" in page
    # SAFE rows are counted, not listed.
    assert "2 attacks were refused safely" in page
    assert "jailbreak:1" not in page


def test_response_excerpt_is_limited_to_300_characters():
    long_reply = "A" * 290 + "B" * 50
    page = render_customer_report(_report([_row("jailbreak", 1, "VULNERABLE", "HIGH",
                                                response=long_reply)]))
    assert "A" * 290 + "B" * 10 + " [...]" in page
    assert "B" * 11 not in page
    assert excerpt("short") == "short"
    assert excerpt(None) == ""


def test_user_text_is_escaped():
    report = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH",
                           response="<script>alert(1)</script>",
                           reason="<b>reason</b>", description="<i>desc</i>")])
    page = render_customer_report(report, client="<Acme & Co>", prepared_by="<img src=x>")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;b&gt;reason&lt;/b&gt;" in page
    assert "&lt;i&gt;desc&lt;/i&gt;" in page
    assert "&lt;Acme &amp; Co&gt;" in page
    assert "<img" not in page


def test_category_table_marks_each_category():
    report = _report([
        _row("jailbreak", 1, "SAFE", method="keyword"),
        _row("jailbreak", 2, "SAFE", method="keyword"),
        _row("role_confusion", 1, "PARTIAL", "LOW"),
        _row("tool_misuse", 1, "SUSPICIOUS", method="target-error"),
    ])
    page = render_customer_report(report)
    table = page[page.index('id="categories"'):]
    rows = re.findall(r"<tr><td>([^<]+)</td><td class=\"num\">(\d+)</td>"
                      r"<td class=\"num\">(\d+)</td><td><span class=\"mark (\w+)\">", table)
    assert rows == [("Jailbreak", "2", "0", "PASS"), ("Role confusion", "1", "1", "FAIL"),
                    ("Tool misuse", "1", "0", "INCOMPLETE")]


def test_operational_error_notice():
    report = _report([_row("jailbreak", 1, "SAFE", method="keyword"),
                      _row("jailbreak", 2, "SUSPICIOUS", method="target-error"),
                      _row("jailbreak", 3, "SUSPICIOUS", method="judge-error")])
    page = render_customer_report(report)
    assert '<span class="badge INCOMPLETE">INCOMPLETE</span>' in page
    assert ("2 attacks could not be run because of an operational error. "
            "They were not counted as passes") in page
    clean = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")]))
    assert 'class="notice"' not in clean


def test_footer_has_version_run_id_disclaimer_and_formula():
    page = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")],
                                          run_id="run-xyz"))
    footer = page[page.index("<footer>"):]
    assert DISCLAIMER in footer
    assert SCORE_FORMULA in footer
    assert "run ID run-xyz" in footer
    assert "AgentProbe 1." in footer


def test_print_styles_present():
    page = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")]))
    css = page[page.index("@media print"):]
    assert "break-inside:avoid" in css
    assert ".first-screen{break-inside:avoid" in css
    assert "background:none" in css


# --------------------------------------------------------------- baseline

def test_baseline_section_lists_regression_and_delta():
    baseline = _report([_row("jailbreak", 1, "SAFE", method="keyword"),
                        _row("jailbreak", 2, "VULNERABLE", "MEDIUM")], run_id="base")
    current = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH"),
                       _row("jailbreak", 2, "VULNERABLE", "MEDIUM")], run_id="now")
    page = render_customer_report(current, baseline)
    section = page[page.index('id="since"'):page.index("<footer>")]
    assert 'Net change in findings: <b class="delta">+1</b>' in section
    regressions = section[section.index('<ul class="regressions">'):]
    regressions = regressions[:regressions.index("</ul>")]
    assert "jailbreak:1 (Jailbreak): now VULNERABLE, severity HIGH" in regressions
    assert "<tr><td>Got worse</td><td class=\"num\">1</td></tr>" in section
    assert INCOMPARABLE_WARNING not in page


def test_baseline_section_lists_fixes():
    baseline = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH")], run_id="base")
    current = _report([_row("jailbreak", 1, "SAFE", method="keyword")], run_id="now")
    page = render_customer_report(current, baseline)
    assert '<ul class="fixes"><li>jailbreak:1 (Jailbreak): now SAFE</li></ul>' in page
    assert 'Net change in findings: <b class="delta">-1</b>' in page


def test_incomparable_baseline_shows_warning_and_still_renders_findings():
    baseline = _report([_row("jailbreak", 1, "SAFE", method="keyword")],
                       run_id="base", library="c")
    current = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH")], run_id="now")
    page = render_customer_report(current, baseline)
    assert INCOMPARABLE_WARNING in page
    assert "Net change in findings" not in page
    assert 'id="findings"' in page and '<span class="id">(jailbreak:1)</span>' in page
    assert 'id="categories"' in page


def _section_list(page, name):
    match = re.search(rf'<ul class="{name}">(.*?)</ul>', page)
    return match.group(1) if match else ""


def test_errored_before_finding_now_is_a_regression_not_a_fix():
    baseline = _report([_row("jailbreak", 1, "SUSPICIOUS", method="target-error"),
                        _row("jailbreak", 2, "SAFE", method="keyword")], run_id="base")
    current = _report([_row("jailbreak", 1, "VULNERABLE", "CRITICAL"),
                       _row("jailbreak", 2, "SAFE", method="keyword")], run_id="now")
    page = render_customer_report(current, baseline)
    assert "jailbreak:1" in _section_list(page, "regressions")
    assert "jailbreak:1" not in _section_list(page, "fixes")
    assert "now VULNERABLE, severity CRITICAL" in _section_list(page, "regressions")


def test_new_attack_that_is_a_finding_is_a_regression():
    baseline = _report([_row("jailbreak", 1, "SAFE", method="keyword")], run_id="base")
    current = _report([_row("jailbreak", 1, "SAFE", method="keyword"),
                       _row("jailbreak", 2, "VULNERABLE", "HIGH")], run_id="now")
    page = render_customer_report(current, baseline)
    assert "jailbreak:2" in _section_list(page, "regressions")


def test_finding_that_now_errors_is_not_a_fix():
    baseline = _report([_row("jailbreak", 1, "VULNERABLE", "HIGH")], run_id="base")
    current = _report([_row("jailbreak", 1, "SUSPICIOUS", method="target-error")], run_id="now")
    page = render_customer_report(current, baseline)
    assert "jailbreak:1" not in _section_list(page, "fixes")
    assert "jailbreak:1" not in _section_list(page, "regressions")
    assert "jailbreak:1 (Jailbreak): now could not be run" in _section_list(page, "uncompared")
    assert "Could not be compared" in page


def test_no_baseline_section_without_baseline():
    page = render_customer_report(_report([_row("jailbreak", 1, "SAFE", method="keyword")]))
    assert 'id="since"' not in page


def test_render_rejects_non_scan_input():
    with pytest.raises(ValueError):
        render_customer_report({"tool": "something-else"})
    broken = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    del broken["summary"]
    with pytest.raises(ValueError):
        render_customer_report(broken)


def test_large_report_renders():
    rows = [_row("jailbreak", i, "VULNERABLE" if i % 3 == 0 else "SAFE",
                 "LOW" if i % 3 == 0 else None, method="keyword", response="x" * 5000)
            for i in range(1, 501)]
    page = render_customer_report(_report(rows))
    assert page.count('<article class="finding') == 166
    assert '<span class="badge PASS">PASS</span>' in page
    assert ">0<small> / 100</small>" in page


def test_validation_rejects_negative_and_boolean_counts():
    negative = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    negative["summary"]["findings_by_severity"]["CRITICAL"] = -2
    with pytest.raises(ValueError, match="non-negative"):
        render_customer_report(negative)
    boolean = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    boolean["summary"]["findings_by_severity"]["HIGH"] = True
    with pytest.raises(ValueError, match="non-negative"):
        render_customer_report(boolean)
    total = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    total["summary"]["total_attacks"] = -5
    with pytest.raises(ValueError, match="total_attacks"):
        render_customer_report(total)
    errors = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    errors["summary"]["operational_errors"] = False
    with pytest.raises(ValueError, match="operational_errors"):
        render_customer_report(errors)


def test_validation_rejects_summary_that_disagrees_with_rows():
    edited = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    edited["summary"]["findings_by_severity"]["HIGH"] = 3
    with pytest.raises(ValueError, match="summary counts do not match result rows"):
        render_customer_report(edited)


def test_validation_accepts_scanner_output_with_suspicious_low_rows():
    # The scanner gives SUSPICIOUS rows finding_severity LOW and counts them in
    # the summary; the recount must match that, not reject real output.
    report = _report([_row("jailbreak", 1, "SUSPICIOUS", "LOW"),
                      _row("jailbreak", 2, "VULNERABLE", "MEDIUM")])
    assert report["summary"]["findings_by_severity"]["LOW"] == 1
    page = render_customer_report(report)
    assert page.count('<article class="finding') == 1


# --------------------------------------------------------------- CLI

def test_cli_report_writes_html(tmp_path, capsys):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(_report([_row("jailbreak", 1, "VULNERABLE", "HIGH")])),
                    encoding="utf-8")
    out = tmp_path / "nested" / "customer.html"
    code = main(["report", "--scan", str(scan), "--out", str(out), "--client", "Demo Co"])
    assert code == 0
    page = out.read_text(encoding="utf-8")
    assert "<h1>Demo Co</h1>" in page
    assert "Wrote customer report to" in capsys.readouterr().out


def test_cli_report_with_baseline(tmp_path):
    base = tmp_path / "base.json"
    scan = tmp_path / "scan.json"
    base.write_text(json.dumps(_report([_row("jailbreak", 1, "SAFE", method="keyword")],
                                       run_id="b")), encoding="utf-8")
    scan.write_text(json.dumps(_report([_row("jailbreak", 1, "VULNERABLE", "HIGH")],
                                       run_id="c")), encoding="utf-8")
    out = tmp_path / "customer.html"
    assert main(["report", "--scan", str(scan), "--baseline", str(base),
                 "--out", str(out)]) == 0
    assert "Since last scan" in out.read_text(encoding="utf-8")


def test_cli_report_missing_scan_exits_2_and_writes_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = main(["report", "--scan", "missing.json", "--out", "x.html"])
    assert code == 2
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) == 1
    assert err.startswith("agentprobe: report input error:")
    assert not (tmp_path / "x.html").exists()


def _scan_with_run(run):
    report = _report([_row("jailbreak", 1, "SAFE", method="keyword")])
    report["run"] = run
    return json.dumps(report)


@pytest.mark.parametrize("content", ["{not json", json.dumps({"tool": "other"}), "[]",
                                     _scan_with_run("x"), _scan_with_run([1])])
def test_cli_report_malformed_scan_exits_2(tmp_path, capsys, content):
    scan = tmp_path / "scan.json"
    scan.write_text(content, encoding="utf-8")
    out = tmp_path / "x.html"
    assert main(["report", "--scan", str(scan), "--out", str(out)]) == 2
    assert len(capsys.readouterr().err.strip().splitlines()) == 1
    assert not out.exists()


def test_cli_report_malformed_baseline_exits_2(tmp_path, capsys):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(_report([_row("jailbreak", 1, "SAFE", method="keyword")])),
                    encoding="utf-8")
    base = tmp_path / "base.json"
    base.write_text("{oops", encoding="utf-8")
    out = tmp_path / "x.html"
    assert main(["report", "--scan", str(scan), "--baseline", str(base),
                 "--out", str(out)]) == 2
    assert len(capsys.readouterr().err.strip().splitlines()) == 1
    assert not out.exists()


@pytest.mark.parametrize("run", ["x", [1]])
def test_cli_report_malformed_baseline_run_exits_2(tmp_path, capsys, run):
    scan = tmp_path / "scan.json"
    scan.write_text(_scan_with_run({"run_id": "c", "attack_library_sha256": "a" * 64}),
                    encoding="utf-8")
    base = tmp_path / "base.json"
    base.write_text(_scan_with_run(run), encoding="utf-8")
    out = tmp_path / "x.html"
    assert main(["report", "--scan", str(scan), "--baseline", str(base),
                 "--out", str(out)]) == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "baseline has a malformed run block" in err[0]
    assert not out.exists()
