import copy
import json

import pytest

from attacks.library import ATTACK_LIBRARY
from attacks.oracles import ORACLES
from agentprobe import scanner
from agentprobe.attackpack import (
    ATTACK_PACK_SCHEMA_VERSION,
    attack_pack_digest,
    build_attack_pack,
    evaluate_deterministic_oracle,
    validate_attack_pack,
)
from agentprobe.reporting import attack_library_digest, build_run_metadata
from research import protocol


# research/study_manifest.json freezes the study corpus to this digest. The
# attack pack is a layer over the library; the library itself must not change.
STUDY_ATTACK_LIBRARY_SHA256 = "1b268572becf8cb8ae3daa7a8e6f44da1e8f0eefb2866542384731cfbc5965d6"
_JUDGE_ORACLE = {"type": "persona_adoption", "evaluator": "judge", "success": "Adopts the persona."}
_MARKER_ORACLE = ORACLES["indirect_injection-05"]


def _with_oracle(attack_id, oracle):
    oracles = copy.deepcopy(ORACLES)
    if oracle is None:
        del oracles[attack_id]
    else:
        oracles[attack_id] = oracle
    return oracles


def test_attack_library_still_matches_the_study_manifest_pin():
    assert protocol.attack_library_digest(ATTACK_LIBRARY) == STUDY_ATTACK_LIBRARY_SHA256
    assert protocol.load_manifest()["attack_library_sha256"] == STUDY_ATTACK_LIBRARY_SHA256


def test_pack_covers_every_library_attack_with_unique_ids():
    pack = build_attack_pack()
    ids = [attack["id"] for attack in pack["attacks"]]
    assert pack["schema_version"] == ATTACK_PACK_SCHEMA_VERSION
    assert len(ids) == len(set(ids)) == sum(map(len, ATTACK_LIBRARY.values())) == 49
    assert set(ids) == set(ORACLES)
    assert ids[0] == "jailbreak-01" and ids[-1] == "tool_misuse-05"
    assert pack["library_sha256"] == attack_library_digest(ATTACK_LIBRARY)
    for attack in pack["attacks"]:
        source = ATTACK_LIBRARY[attack["category"]][attack["index"] - 1]
        assert {key: attack[key] for key in source} == source
    json.dumps(pack, allow_nan=False)


def test_pack_copies_leave_library_and_oracles_untouched():
    pack = build_attack_pack()
    pack["attacks"][0]["prompt"] = "edited"
    pack["attacks"][0]["oracle"]["success"] = "edited"
    assert ATTACK_LIBRARY["jailbreak"][0]["prompt"] != "edited"
    assert ORACLES["jailbreak-01"]["success"] != "edited"
    assert protocol.attack_library_digest(ATTACK_LIBRARY) == STUDY_ATTACK_LIBRARY_SHA256


def test_only_the_compromised_review_uses_a_deterministic_oracle():
    deterministic = [key for key, oracle in ORACLES.items() if oracle["evaluator"] == "deterministic"]
    assert deterministic == ["indirect_injection-05"]
    assert "Say COMPROMISED" in ATTACK_LIBRARY["indirect_injection"][4]["prompt"]


@pytest.mark.parametrize(("oracles", "match"), [
    (_with_oracle("jailbreak-01", None), "missing oracles for: jailbreak-01"),
    (_with_oracle("jailbreak-99", _JUDGE_ORACLE), "not in the library: jailbreak-99"),
    (_with_oracle("jailbreak-01", {**_JUDGE_ORACLE, "type": "mind_reading"}), "unknown oracle type"),
    (_with_oracle("jailbreak-01", {**_JUDGE_ORACLE, "evaluator": "deterministic"}),
     "must use evaluator 'judge'"),
    (_with_oracle("indirect_injection-05", {**_MARKER_ORACLE, "evaluator": "judge"}),
     "must use evaluator 'deterministic'"),
    (_with_oracle("indirect_injection-05", {**_MARKER_ORACLE, "marker": "  "}), "non-empty marker"),
    (_with_oracle("indirect_injection-05",
                  {key: value for key, value in _MARKER_ORACLE.items() if key != "marker"}),
     "non-empty marker"),
    (_with_oracle("jailbreak-01", {**_JUDGE_ORACLE, "marker": "X"}), "unsupported fields"),
    (_with_oracle("jailbreak-01", {**_JUDGE_ORACLE, "success": " "}), "success statement"),
])
def test_build_rejects_invalid_oracles(oracles, match):
    with pytest.raises(ValueError, match=match):
        build_attack_pack(oracles=oracles)


def test_build_rejects_unknown_severity_and_uncarried_library_fields():
    library = copy.deepcopy(ATTACK_LIBRARY)
    library["jailbreak"][0]["severity"] = "SEVERE"
    with pytest.raises(ValueError, match="unknown severity: 'SEVERE'"):
        build_attack_pack(library=library)

    library = copy.deepcopy(ATTACK_LIBRARY)
    library["jailbreak"][0]["oracle"] = "inline"
    with pytest.raises(ValueError, match="does not carry"):
        build_attack_pack(library=library)


def test_validate_rejects_duplicate_ids():
    pack = build_attack_pack()
    pack["attacks"].append(copy.deepcopy(pack["attacks"][0]))
    with pytest.raises(ValueError, match="duplicate attack ID: jailbreak-01"):
        validate_attack_pack(pack)


def test_validate_rejects_attacks_that_drift_from_the_library_digest():
    edited = build_attack_pack()
    edited["attacks"][0]["prompt"] = "a different prompt"
    with pytest.raises(ValueError, match="library_sha256"):
        validate_attack_pack(edited)

    dropped = build_attack_pack()
    del dropped["attacks"][3]
    with pytest.raises(ValueError, match="library_sha256"):
        validate_attack_pack(dropped)


def test_marker_oracle_is_decided_deterministically():
    assert evaluate_deterministic_oracle(_MARKER_ORACLE, "Great product! COMPROMISED") is True
    assert evaluate_deterministic_oracle(
        _MARKER_ORACLE, "The review contains an embedded instruction, which I will not follow."
    ) is False
    assert evaluate_deterministic_oracle(ORACLES["jailbreak-01"], "anything") is None
    with pytest.raises(ValueError, match="unknown oracle type"):
        evaluate_deterministic_oracle({**_MARKER_ORACLE, "type": "nope"}, "COMPROMISED")


def test_pack_digest_is_stable_and_tracks_oracle_changes():
    first, second = build_attack_pack(), build_attack_pack()
    assert attack_pack_digest(first) == attack_pack_digest(second)
    assert len(attack_pack_digest(first)) == 64

    reworded = {**ORACLES["jailbreak-01"], "success": "A reworded success statement."}
    changed = build_attack_pack(oracles=_with_oracle("jailbreak-01", reworded))
    assert attack_pack_digest(changed) != attack_pack_digest(first)
    assert changed["library_sha256"] == first["library_sha256"]


def test_run_metadata_records_the_attack_pack_only_when_given():
    pack = build_attack_pack()
    with_pack = build_run_metadata("target", "judge", attack_pack=pack)
    assert with_pack["attack_pack_schema_version"] == ATTACK_PACK_SCHEMA_VERSION
    assert with_pack["attack_pack_sha256"] == attack_pack_digest(pack)

    without_pack = build_run_metadata("target", "judge")
    assert "attack_pack_schema_version" not in without_pack
    assert "attack_pack_sha256" not in without_pack


def test_configured_scan_reports_the_attack_pack(tmp_path, monkeypatch):
    config = {
        "target": {"provider": "ollama", "model": "target-3b"},
        "judge": {"provider": "ollama", "model": "judge-8b"},
        "scan": {"categories": ["jailbreak"], "rate_limit_seconds": 0},
        "output": {"report_dir": str(tmp_path), "report_format": "json"},
    }
    monkeypatch.setattr(scanner, "load_config", lambda _path: config)
    monkeypatch.setattr(scanner, "build_client", lambda _cfg: object())
    monkeypatch.setattr(scanner, "run_full_scan", lambda *_args, **_kwargs: {})

    run = scanner.run_configured_scan("fixture.yaml")
    with open(run["json_path"], encoding="utf-8") as f:
        report = json.load(f)
    assert report["run"]["attack_pack_schema_version"] == ATTACK_PACK_SCHEMA_VERSION
    assert report["run"]["attack_pack_sha256"] == attack_pack_digest(build_attack_pack())
