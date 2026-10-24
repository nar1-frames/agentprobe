"""External attack packs: loading, validation, selection, provenance, and CLI."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from agentprobe import packs as packs_module
from agentprobe import scanner
from agentprobe.attackpack import attack_pack_digest, build_attack_pack
from agentprobe.cli import main
from agentprobe.config import validate_config
from agentprobe.customer_report import render_customer_report
from agentprobe.packs import (
    BUILTIN_PACK_ID, PackError, builtin_pack, load_pack, load_packs, resolve_pack,
)
from agentprobe.reporting import attack_library_digest, build_json_report


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "packs" / "support-desk-sample"
# Published digests of built-in selections (writeups/public-scan-01.md, docs/demo/).
FULL_LIBRARY_SHA256 = "1b268572becf8cb8ae3daa7a8e6f44da1e8f0eefb2866542384731cfbc5965d6"
DEMO_SELECTION_SHA256 = "39524741b71f5cc334093395462a75957520343c1dce89bcbf84f058effeac35"

_MANIFEST = {"schema_version": "1.0", "id": "test-pack", "version": "1.2.3",
             "license": "CC-BY-4.0", "categories": ["jailbreak", "billing_abuse"]}


def _attack(attack_id="a-01", category="jailbreak", **overrides):
    attack = {"id": attack_id, "category": category, "prompt": f"prompt {attack_id}",
              "severity": "HIGH", "description": f"tests {attack_id}",
              "oracle": {"type": "marker_output", "evaluator": "deterministic",
                         "success": "The marker appears.", "marker": "MARKER-1"}}
    attack.update(overrides)
    return attack


def _write_pack(root, manifest=None, files=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.yaml").write_text(yaml.safe_dump(manifest or _MANIFEST), encoding="utf-8")
    attacks_dir = root / "attacks"
    attacks_dir.mkdir(exist_ok=True)
    if files is None:
        files = {"main.yaml": {"attacks": [_attack("a-01"),
                                            _attack("b-01", "billing_abuse", severity="LOW")]}}
    for name, document in files.items():
        text = document if isinstance(document, str) else yaml.safe_dump(document)
        (attacks_dir / name).write_text(text, encoding="utf-8")
    return root


class _RefusingClient:
    calls = 0

    def __init__(self):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    @classmethod
    def create(cls, **_kwargs):
        cls.calls += 1
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content="I can't help with that, and I won't provide it."))])


# ---------------------------------------------------------------- built-in pack

def test_builtin_pack_is_the_bundled_library():
    pack = builtin_pack()
    assert (pack.id, pack.version, pack.builtin) == (BUILTIN_PACK_ID, "1.0.0", True)
    assert len(pack.attacks) == 49 and len(pack.categories) == 8
    assert pack.sha256 == attack_pack_digest(build_attack_pack())
    assert pack.provenance() == {"id": "agentprobe-core", "version": "1.0.0",
                                 "schema_version": "1.0", "license": "MIT", "attacks": 49,
                                 "sha256": pack.sha256}


def test_builtin_only_selection_keeps_its_published_digests():
    full = scanner.filter_attacks({"scan": {"categories": "all"}})
    assert attack_library_digest(full) == FULL_LIBRARY_SHA256
    demo = scanner.filter_attacks({"scan": {
        "categories": ["role_confusion", "context_manipulation", "tool_misuse"],
        "severity_filter": "HIGH"}})
    assert attack_library_digest(demo) == DEMO_SELECTION_SHA256


# ------------------------------------------------------------------- loading

def test_example_pack_loads_with_indexed_attacks():
    pack = load_pack(str(EXAMPLE))
    assert pack.id == "support-desk-sample" and not pack.builtin
    assert [a["id"] for a in pack.attacks] == ["ticket-marker-01", "policy-text-01",
                                               "bulk-refund-01"]
    assert all(a["index"] == 1 for a in pack.attacks)


def test_pack_digest_ignores_line_endings_and_layout(tmp_path):
    copy = tmp_path / "crlf"
    shutil.copytree(EXAMPLE, copy)
    for path in copy.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    assert load_pack(str(copy)).sha256 == load_pack(str(EXAMPLE)).sha256


def test_pack_digest_changes_when_content_changes(tmp_path):
    first = load_pack(str(_write_pack(tmp_path / "one")))
    files = {"main.yaml": {"attacks": [_attack("a-01", prompt="edited"),
                                        _attack("b-01", "billing_abuse", severity="LOW")]}}
    second = load_pack(str(_write_pack(tmp_path / "two", files=files)))
    assert first.sha256 != second.sha256


@pytest.mark.parametrize("manifest_change, message", [
    ({"owner": "x"}, "unknown fields: owner"),
    ({"schema_version": "2.0"}, "schema_version must be '1.0'"),
    ({"id": "Bad_ID"}, "must be 2-63 lowercase"),
    ({"id": "builtin"}, "reserved for the built-in pack"),
    ({"version": 1.0}, "MAJOR.MINOR.PATCH"),
    ({"license": ""}, "license must be non-empty text"),
    ({"categories": []}, "categories must be a non-empty list"),
    ({"categories": ["Jailbreak"]}, "lowercase snake_case"),
    ({"categories": ["jailbreak", "billing_abuse", "unused_cat"]}, "no attack uses: unused_cat"),
])
def test_manifest_is_validated(tmp_path, manifest_change, message):
    _write_pack(tmp_path / "p", manifest={**_MANIFEST, **manifest_change})
    with pytest.raises(PackError, match=message):
        load_pack(str(tmp_path / "p"))


@pytest.mark.parametrize("attacks, message", [
    ([_attack("a-01"), _attack("a-01", "billing_abuse")], "repeats attack id 'a-01'"),
    ([_attack("a-01", "privilege_escalation")], "not listed in the manifest"),
    ([_attack("a-01", severity="SEVERE")], "severity must be one of"),
    ([{**_attack("a-01"), "notes": "x"}], "unknown fields: notes"),
    ([{k: v for k, v in _attack("a-01").items() if k != "oracle"}], "missing fields: oracle"),
    ([_attack("a-01", oracle={"type": "marker_output", "evaluator": "judge",
                              "success": "x", "marker": "m"})], "must use evaluator"),
    ([_attack("a-01", prompt="x" * 4001)], "longer than 4000"),
    ([_attack("A 01")], "must be lowercase letters"),
])
def test_attacks_are_validated(tmp_path, attacks, message):
    files = {"main.yaml": {"attacks": attacks + [_attack("b-01", "billing_abuse")]}}
    _write_pack(tmp_path / "p", files=files)
    with pytest.raises(PackError, match=message):
        load_pack(str(tmp_path / "p"))


@pytest.mark.parametrize("files, message", [
    ({"main.yaml": "attacks: [unclosed\n"}, "not valid YAML"),
    ({"main.yaml": {"attacks": []}}, "non-empty list"),
    ({"main.yaml": {"attacks": [_attack()], "extra": 1}}, "exactly one key, attacks"),
    ({"main.yaml": {"attacks": [_attack(), _attack("b-01", "billing_abuse")]},
      "notes.txt": "hello"}, "only .yaml files; found: notes.txt"),
    ({}, "no attack files"),
])
def test_attack_files_are_validated(tmp_path, files, message):
    _write_pack(tmp_path / "p", files=files)
    with pytest.raises(PackError, match=message):
        load_pack(str(tmp_path / "p"))


def test_missing_manifest_and_oversized_files_are_refused(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir()
    with pytest.raises(PackError, match="manifest.yaml cannot be read"):
        load_pack(str(tmp_path / "empty"))
    _write_pack(tmp_path / "big")
    monkeypatch.setattr(packs_module, "MAX_FILE_BYTES", 10)
    with pytest.raises(PackError, match="larger than 10 bytes"):
        load_pack(str(tmp_path / "big"))


# ---------------------------------------------------------- resolving packs

def test_resolve_by_alias_path_and_search_path(tmp_path, monkeypatch):
    assert resolve_pack("builtin").builtin and resolve_pack(BUILTIN_PACK_ID).builtin
    _write_pack(tmp_path / "shelf" / "test-pack")
    assert resolve_pack("shelf/test-pack", base_dir=str(tmp_path)).id == "test-pack"
    monkeypatch.setenv("AGENTPROBE_PACKS_PATH", str(tmp_path / "shelf"))
    assert resolve_pack("test-pack").id == "test-pack"
    with pytest.raises(PackError, match="not found"):
        resolve_pack("no-such-pack")


def test_load_packs_defaults_to_builtin_and_rejects_duplicates():
    assert [pack.id for pack in load_packs()] == [BUILTIN_PACK_ID]
    with pytest.raises(PackError, match="loaded more than once"):
        load_packs(["builtin", BUILTIN_PACK_ID])
    with pytest.raises(PackError, match="loaded more than once"):
        load_packs(["builtin", str(EXAMPLE)], extra_specs=[str(EXAMPLE)])


# --------------------------------------------------------------- selection

def test_selection_namespaces_external_attacks_and_keeps_builtin_first():
    loaded = load_packs(["builtin", str(EXAMPLE)])
    selection = scanner.filter_attacks({"scan": {"categories": "all"}}, loaded)
    assert list(selection)[:8] == list(builtin_pack().categories)
    indirect = selection["indirect_injection"]
    assert "_attack_id" not in indirect[0]
    assert indirect[-1]["_attack_id"] == "support-desk-sample:ticket-marker-01"
    assert attack_library_digest(selection) != FULL_LIBRARY_SHA256


def test_selection_filters_pack_categories_and_severity(tmp_path):
    loaded = load_packs([str(_write_pack(tmp_path / "p"))])
    only = scanner.filter_attacks({"scan": {"categories": ["billing_abuse"]}}, loaded)
    assert list(only) == ["billing_abuse"]
    high = scanner.filter_attacks({"scan": {"categories": "all", "severity_filter": "HIGH"}},
                                  loaded)
    assert list(high) == ["jailbreak"]
    with pytest.raises(ValueError, match="no loaded attack pack provides"):
        scanner.filter_attacks({"scan": {"categories": ["tool_misuse"]}}, loaded)


def test_config_validates_packs_and_category_names():
    base = {"target": {"provider": "ollama", "model": "t-3b"},
            "judge": {"provider": "ollama", "model": "j-8b"}}
    assert validate_config({**base, "packs": ["builtin", "./p"]})["packs"] == ["builtin", "./p"]
    assert validate_config({**base, "scan": {"categories": ["billing_abuse"]}})
    for bad in ([], "builtin", [""], [3]):
        with pytest.raises(ValueError, match="packs must be a list"):
            validate_config({**base, "packs": bad})


# -------------------------------------------------- scans and provenance

def _scan_config(tmp_path, packs_line):
    _write_pack(tmp_path / "packs" / "test-pack")
    config = tmp_path / "cfg" / "scan.yaml"
    config.parent.mkdir()
    config.write_text(
        "target: {provider: ollama, model: target-3b, max_tokens: 32}\n"
        "judge: {provider: ollama, model: judge-8b, max_tokens: 16}\n"
        f"{packs_line}"
        "scan: {categories: all, rate_limit_seconds: 0, retries: 0, retry_delay_seconds: 0}\n"
        f"output: {{report_format: json, report_dir: {json.dumps(str(tmp_path / 'reports'))}}}\n",
        encoding="utf-8")
    return str(config)


@pytest.fixture
def fake_providers(monkeypatch):
    _RefusingClient.calls = 0
    monkeypatch.setattr(scanner, "build_client", lambda _block: _RefusingClient())
    monkeypatch.setattr(scanner, "preflight_model", lambda *_args, **_kwargs: None)


def test_scan_records_every_pack_and_namespaced_rows(tmp_path, fake_providers):
    config = _scan_config(tmp_path, "packs: [builtin, ../packs/test-pack]\n")
    run = scanner.run_configured_scan(config, packs=[str(EXAMPLE)])
    report = run["report"]
    assert report["summary"]["total_attacks"] == 49 + 2 + 3
    ids = {row["attack_id"] for row in report["results"]}
    assert {"jailbreak:1", "test-pack:a-01", "test-pack:b-01",
            "support-desk-sample:bulk-refund-01"} <= ids
    recorded = report["run"]["attack_packs"]
    assert [(p["id"], p["version"]) for p in recorded] == [
        ("agentprobe-core", "1.0.0"), ("test-pack", "1.2.3"), ("support-desk-sample", "1.0.0")]
    assert all(len(p["sha256"]) == 64 and "path" not in p for p in recorded)
    assert report["run"]["attack_pack_sha256"] == builtin_pack().sha256


def test_external_only_scan_omits_the_builtin_pack_digest(tmp_path, fake_providers):
    config = _scan_config(tmp_path, "packs: [../packs/test-pack]\n")
    report = scanner.run_configured_scan(config)["report"]
    assert report["summary"]["total_attacks"] == 2
    assert "attack_pack_sha256" not in report["run"]
    assert [p["id"] for p in report["run"]["attack_packs"]] == ["test-pack"]


def test_checkpoint_resume_with_pack_attacks_makes_no_new_calls(tmp_path, fake_providers):
    config = _scan_config(tmp_path, "packs: [../packs/test-pack]\n")
    checkpoint = str(tmp_path / "scan.checkpoint.json")
    scanner.run_configured_scan(config, checkpoint_path=checkpoint)
    calls = _RefusingClient.calls
    resumed = scanner.run_configured_scan(config, checkpoint_path=checkpoint, resume=True)
    assert _RefusingClient.calls == calls
    assert {row["attack_id"] for row in resumed["report"]["results"]} == {
        "test-pack:a-01", "test-pack:b-01"}


def test_customer_report_names_packs_only_when_external_packs_were_used():
    attack = {"prompt": "p", "severity": "HIGH", "description": "d", "_library_index": 1,
              "_attack_id": "test-pack:a-01"}
    run = {"run_id": "r", "attack_packs": [builtin_pack().provenance(), {
        "id": "test-pack", "version": "1.2.3", "schema_version": "1.0",
        "license": "CC-BY-4.0", "attacks": 2, "sha256": "c" * 64}]}
    report = build_json_report({"jailbreak": [(attack, "no", "SAFE", None, "kw", "keyword")]},
                               "t", "j", metadata=run)
    page = render_customer_report(report)
    assert "from the attack packs agentprobe-core 1.0.0, test-pack 1.2.3" in page
    assert "Attack pack test-pack 1.2.3 (CC-BY-4.0, 2 attacks, sha256 cccccccccccc)." in page
    report["run"]["attack_packs"] = [builtin_pack().provenance()]
    assert "from AgentProbe's public attack library" in render_customer_report(report)


# --------------------------------------------------------------------- CLI

def test_cli_packs_validate_and_list(tmp_path, monkeypatch, capsys):
    assert main(["packs", "validate", str(EXAMPLE)]) == 0
    assert capsys.readouterr().out.startswith("Pack OK: support-desk-sample 1.0.0: 3 attacks")
    _write_pack(tmp_path / "bad", manifest={**_MANIFEST, "id": "Bad"})
    assert main(["packs", "validate", str(tmp_path / "bad")]) == 2
    assert "agentprobe: pack error:" in capsys.readouterr().err
    shelf = tmp_path / "shelf"
    shutil.copytree(EXAMPLE, shelf / "support-desk-sample")
    _write_pack(shelf / "broken", manifest={**_MANIFEST, "version": "x"})
    monkeypatch.setenv("AGENTPROBE_PACKS_PATH", str(shelf))
    assert main(["packs", "list"]) == 2
    out = capsys.readouterr().out
    assert "agentprobe-core 1.0.0: 49 attacks" in out and "support-desk-sample 1.0.0" in out
    assert "[INVALID]" in out and "broken" in out


def test_cli_scan_pack_requires_non_interactive(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["scan", "--pack", str(EXAMPLE)])
    assert raised.value.code == 2
    assert "--pack currently requires --non-interactive" in capsys.readouterr().err


def test_cli_scan_unknown_pack_is_a_config_error(tmp_path, fake_providers, capsys):
    config = _scan_config(tmp_path, "")
    assert main(["scan", "--non-interactive", "--config", config, "--pack", "nope"]) == 2
    assert "pack 'nope' not found" in capsys.readouterr().out
