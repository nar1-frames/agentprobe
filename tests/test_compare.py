import json


from agentprobe import scanner
from agentprobe.cli import main
from agentprobe.compare import compare_scan_reports, format_comparison_text
from agentprobe.providers import build_client
from agentprobe.reporting import build_harness_report, build_json_report
from attacks.library import ATTACK_LIBRARY
from test_replay import _FakeProvider, _write_config


_ERROR_REASON = "[ERROR: SENTINEL-REASON provider failure]"


def _row(index, verdict, method, finding=None, category="fixture"):
    attack = {"prompt": f"SENTINEL-PROMPT-{index}", "severity": "HIGH",
              "description": "fixture", "_library_index": index}
    response = "[ERROR: SENTINEL-RESPONSE]" if method.endswith("-error") else f"SENTINEL-RESPONSE-{index}"
    reason = _ERROR_REASON if method.endswith("-error") else f"SENTINEL-REASON-{index}"
    return category, (attack, response, verdict, finding, reason, method)


def _report(rows, run_id, **metadata):
    results = {}
    for category, row in rows:
        results.setdefault(category, []).append(row)
    run = {"run_id": run_id, "target_model": "target-3b", "judge_model": "judge-8b",
           "attack_library_sha256": "a" * 64, "judge_prompt_sha256": "b" * 64, **metadata}
    return build_json_report(results, run["target_model"], run["judge_model"],
                             generated_at=f"{run_id}-time", metadata=run)


BASELINE = [
    _row(1, "SAFE", "keyword"),
    _row(2, "VULNERABLE", "llm-judge", "HIGH"),
    _row(3, "PARTIAL", "llm-judge", "MEDIUM"),
    _row(4, "SAFE", "keyword"),
    _row(5, "SUSPICIOUS", "judge-error"),
    _row(6, "SUSPICIOUS", "target-error"),
    _row(8, "SAFE", "keyword"),
    _row(10, "SAFE", "keyword"),
    _row(1, "SAFE", "keyword", category="alpha"),
]
CANDIDATE = [
    _row(1, "VULNERABLE", "llm-judge", "HIGH"),
    _row(2, "SAFE", "keyword"),
    _row(3, "PARTIAL", "keyword", "MEDIUM"),
    _row(4, "SUSPICIOUS", "target-error"),
    _row(5, "SAFE", "keyword"),
    _row(6, "SUSPICIOUS", "judge-error"),
    _row(7, "SAFE", "keyword"),
    _row(10, "SAFE", "keyword"),
    _row(1, "SAFE", "keyword", category="alpha"),
]


def test_every_change_class_is_classified_sorted_and_text_free():
    result = compare_scan_reports(_report(BASELINE, "base"), _report(CANDIDATE, "cand"))
    assert [(e["attack_id"], e["change"]) for e in result["changes"]] == [
        ("alpha:1", "unchanged"),
        ("fixture:1", "regressed"),
        ("fixture:2", "improved"),
        ("fixture:3", "unchanged"),
        ("fixture:4", "newly_errored"),
        ("fixture:5", "recovered"),
        ("fixture:6", "still_errored"),
        ("fixture:7", "added"),
        ("fixture:8", "removed"),
        ("fixture:10", "unchanged"),
    ]
    by_id = {entry["attack_id"]: entry for entry in result["changes"]}
    assert by_id["fixture:3"]["method_changed"] is True
    assert by_id["fixture:1"]["method_changed"] is True
    assert by_id["fixture:6"]["method_changed"] is False
    assert by_id["fixture:7"]["baseline"] is None
    assert by_id["fixture:1"]["candidate"] == {
        "verdict": "VULNERABLE", "finding_severity": "HIGH", "method": "llm-judge", "status": "complete",
    }
    assert result["summary"] == {
        "regressed": 1, "improved": 1, "unchanged": 3, "newly_errored": 1,
        "recovered": 1, "still_errored": 1, "added": 1, "removed": 1,
        "method_changed": 3, "net_findings_delta": 0,
    }
    assert result["baseline"] == {"run_id": "base", "generated_at": "base-time",
                                  "target_model": "target-3b", "judge_model": "judge-8b"}
    assert result["comparability"] == {"comparable": True, "mismatches": []}
    text = json.dumps(result) + format_comparison_text(result)
    assert "SENTINEL" not in text


def test_net_findings_delta_counts_vulnerable_and_partial_only():
    baseline = _report([_row(1, "SAFE", "keyword"), _row(2, "SUSPICIOUS", "llm-judge", "LOW")], "b")
    candidate = _report([_row(1, "PARTIAL", "llm-judge", "MEDIUM"),
                         _row(2, "VULNERABLE", "llm-judge", "HIGH")], "c")
    assert compare_scan_reports(baseline, candidate)["summary"]["net_findings_delta"] == 2
    assert compare_scan_reports(candidate, baseline)["summary"]["net_findings_delta"] == -2


def test_comparability_blocks_on_library_and_warns_on_model_changes():
    rows = [_row(1, "SAFE", "keyword")]
    other_library = compare_scan_reports(
        _report(rows, "b"), _report(rows, "c", attack_library_sha256="c" * 64)
    )["comparability"]
    assert other_library["comparable"] is False
    assert other_library["mismatches"][0]["field"] == "attack_library_sha256"
    assert other_library["mismatches"][0]["blocking"] is True

    new_judge = compare_scan_reports(_report(rows, "b"), _report(rows, "c", judge_model="judge-70b"))
    assert new_judge["comparability"]["comparable"] is True
    assert new_judge["comparability"]["mismatches"] == [{
        "field": "judge_model", "baseline": "judge-8b", "candidate": "judge-70b",
        "blocking": False, "reason": "differs",
    }]
    assert format_comparison_text(new_judge).startswith("Comparable: yes (changed: judge_model)")

    undigested = _report(rows, "c")
    del undigested["run"]["attack_library_sha256"]
    assert compare_scan_reports(_report(rows, "b"), undigested)["comparability"]["comparable"] is False


def _write(path, report):
    path.write_text(json.dumps(report), encoding="utf-8")
    return str(path)


def test_compare_cli_exit_codes(tmp_path, capsys):
    base = _write(tmp_path / "base.json", _report(BASELINE, "base"))
    same = _write(tmp_path / "same.json", _report(BASELINE, "same"))
    cand = _write(tmp_path / "cand.json", _report(CANDIDATE, "cand"))
    other = _write(tmp_path / "other.json", _report(BASELINE, "other", attack_library_sha256="c" * 64))

    assert main(["compare", "--baseline", base, "--candidate", same, "--fail-on-regression"]) == 0
    assert main(["compare", "--baseline", base, "--candidate", cand]) == 0
    assert main(["compare", "--baseline", base, "--candidate", cand, "--fail-on-regression"]) == 1
    assert main(["compare", "--baseline", base, "--candidate", other, "--fail-on-incomparable"]) == 4
    assert main(["compare", "--baseline", base, "--candidate", other,
                 "--fail-on-incomparable", "--fail-on-regression"]) == 4
    capsys.readouterr()

    harness = _write(tmp_path / "harness.json", build_harness_report([], "guarded"))
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    for bad in (harness, str(garbage), str(tmp_path / "missing.json")):
        assert main(["compare", "--baseline", base, "--candidate", bad]) == 2
    assert "harness report; compare supports scan reports only" in capsys.readouterr().err

    assert main(["compare", "--baseline", base, "--candidate", cand, "--json", "-"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["summary"]["regressed"] == 1
    assert "REGRESSED fixture:1: SAFE via keyword -> VULNERABLE via llm-judge" in captured.err


def test_replayed_scans_show_a_flipped_response_as_a_regression(tmp_path, monkeypatch):
    index, prompt = next(
        (i, attack["prompt"]) for i, attack in enumerate(ATTACK_LIBRARY["jailbreak"], start=1)
        if len(attack["prompt"]) % 2
    )

    class FlippedProvider(_FakeProvider):
        def _create(self, **request):
            if request["model"] == "fixture-target" and request["messages"][-1]["content"] == prompt:
                self.calls.append(request)
                return super()._create(**{**request, "messages": [{"role": "user", "content": "xx"}]})
            return super()._create(**request)

    reports = []
    for name, provider in (("base", _FakeProvider()), ("cand", FlippedProvider())):
        recording = tmp_path / f"{name}.replay.json"
        monkeypatch.setattr(scanner, "build_client", lambda _config, p=provider: p)
        scanner.run_configured_scan(_write_config(
            tmp_path / f"{name}-record.yaml", {"provider": "ollama"}, {"provider": "ollama"},
            {"record_replay_path": str(recording)}, tmp_path / f"{name}-recorded",
        ))
        monkeypatch.setattr(scanner, "build_client", build_client)
        replay = {"provider": "replay", "replay_path": str(recording)}
        run = scanner.run_configured_scan(_write_config(
            tmp_path / f"{name}-replay.yaml", replay, replay, {}, tmp_path / f"{name}-replayed",
        ))
        reports.append(run["json_path"])

    assert main(["compare", "--baseline", reports[0], "--candidate", reports[1],
                 "--fail-on-regression", "--fail-on-incomparable",
                 "--json", str(tmp_path / "comparison.json")]) == 1
    result = json.loads((tmp_path / "comparison.json").read_text(encoding="utf-8"))
    assert result["comparability"] == {"comparable": True, "mismatches": []}
    regressed = [entry for entry in result["changes"] if entry["change"] == "regressed"]
    assert [entry["attack_id"] for entry in regressed] == [f"jailbreak:{index}"]
    assert regressed[0]["baseline"]["verdict"] == "SAFE"
    assert regressed[0]["candidate"]["verdict"] == "VULNERABLE"
    assert result["summary"]["unchanged"] == 12



def test_compare_text_has_tags_legend_and_summary(tmp_path, capsys):
    result = compare_scan_reports(_report(BASELINE, "base"), _report(CANDIDATE, "cand"))
    text = format_comparison_text(result)
    lines = text.splitlines()
    assert lines[0] == "Comparable: yes"
    assert lines[1] == (
        "Summary: 1 regressed, 1 improved, 3 unchanged, 1 newly errored, 1 recovered, "
        "1 still errored, 1 added, 1 removed; net findings delta +0; 3 changed method"
    )
    assert "  REGRESSED fixture:1: SAFE via keyword -> VULNERABLE via llm-judge" in lines
    assert any(line.startswith("  NEWLY_ERRORED ") for line in lines)
    assert any(line.startswith("  ADDED ") for line in lines)
    assert any(line.startswith("  REMOVED ") for line in lines)
    assert not any(line.lstrip().startswith(("IMPROVED", "UNCHANGED", "RECOVERED", "STILL_ERRORED"))
                   for line in lines)
    assert lines[-2] == ("Legend: REGRESSED got worse than the baseline  "
                         "NEWLY_ERRORED now fails operationally")
    assert lines[-1] == "        ADDED only in the new scan  REMOVED only in the baseline"
    assert all(ord(ch) < 128 for ch in text)

    base = _write(tmp_path / "base.json", _report(BASELINE, "base"))
    cand = _write(tmp_path / "cand.json", _report(CANDIDATE, "cand"))
    same = _write(tmp_path / "same.json", _report(BASELINE, "same"))
    other = _write(tmp_path / "other.json",
                   _report(BASELINE, "other", attack_library_sha256="c" * 64))

    assert main(["compare", "--baseline", base, "--candidate", cand]) == 0
    assert "Exit code" not in capsys.readouterr().out
    assert main(["compare", "--baseline", base, "--candidate", cand, "--fail-on-regression"]) == 1
    assert ("Exit code 1: an attack regressed or newly errored and --fail-on-regression is set"
            in capsys.readouterr().out)
    assert main(["compare", "--baseline", base, "--candidate", same, "--fail-on-regression"]) == 0
    assert "Exit code 0: nothing that --fail-on-regression checks for happened" in capsys.readouterr().out
    assert main(["compare", "--baseline", base, "--candidate", other,
                 "--fail-on-incomparable", "--fail-on-regression"]) == 4
    out = capsys.readouterr().out
    assert out.startswith("NOT COMPARABLE:")
    assert "Exit code 4: the reports are not comparable and --fail-on-incomparable is set" in out
