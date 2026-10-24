"""Versioned attack packs: library attacks joined to explicit success oracles.

``attacks/library.py`` is pinned by digest in ``research/study_manifest.json``,
so success oracles live in ``attacks/oracles.py`` and are joined here rather
than added to the library dicts. A pack records the library digest it was built
from, so its attacks can be checked against the library, and the pack digest
identifies the exact oracle definitions a scan used.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

from attacks.library import ATTACK_LIBRARY
from attacks.oracles import ORACLES
from agentprobe.reporting import SEVERITIES, attack_library_digest


ATTACK_PACK_SCHEMA_VERSION = "1.0"

# The closed set of oracle types, each bound to the only evaluator that can
# decide it. Judge oracles need a model to read the response; deterministic
# oracles are decided by this module.
ORACLE_EVALUATORS = {
    "system_prompt_disclosure": "judge",
    "restriction_lift_confirmation": "judge",
    "persona_adoption": "judge",
    "task_hijack": "judge",
    "tool_action_attempt": "judge",
    "marker_output": "deterministic",
}

_PACK_FIELDS = frozenset({"schema_version", "library_sha256", "attacks"})
_ATTACK_FIELDS = frozenset({"id", "category", "index", "prompt", "severity", "description", "oracle"})
_LIBRARY_FIELDS = frozenset({"prompt", "severity", "description"})
_ORACLE_FIELDS = frozenset({"type", "evaluator", "success"})
_TYPE_FIELDS = {"marker_output": frozenset({"marker"})}


def attack_pack_id(category: str, index: int) -> str:
    """Return the stable pack ID for the 1-based ``index`` within ``category``."""

    return f"{category}-{index:02d}"


def _validate_oracle(label: str, oracle: Any) -> None:
    if not isinstance(oracle, Mapping):
        raise ValueError(f"{label} oracle must be a mapping")
    oracle_type = oracle.get("type")
    if not isinstance(oracle_type, str) or oracle_type not in ORACLE_EVALUATORS:
        raise ValueError(f"{label} has unknown oracle type: {oracle_type!r}")
    expected = ORACLE_EVALUATORS[oracle_type]
    if oracle.get("evaluator") != expected:
        raise ValueError(
            f"{label} {oracle_type} oracle must use evaluator {expected!r}, "
            f"not {oracle.get('evaluator')!r}"
        )
    unsupported = sorted(set(oracle) - _ORACLE_FIELDS - _TYPE_FIELDS.get(oracle_type, frozenset()))
    if unsupported:
        raise ValueError(f"{label} {oracle_type} oracle has unsupported fields: {unsupported}")
    success = oracle.get("success")
    if not isinstance(success, str) or not success.strip():
        raise ValueError(f"{label} oracle needs a non-empty success statement")
    if oracle_type == "marker_output":
        marker = oracle.get("marker")
        if not isinstance(marker, str) or not marker.strip():
            raise ValueError(f"{label} marker_output oracle needs a non-empty marker")


def validate_attack_pack(pack: Mapping[str, Any]) -> None:
    """Raise ValueError unless ``pack`` is a well-formed, self-consistent pack."""

    if not isinstance(pack, Mapping):
        raise ValueError("attack pack must be a mapping")
    if pack.get("schema_version") != ATTACK_PACK_SCHEMA_VERSION:
        raise ValueError(f"unsupported attack pack schema version: {pack.get('schema_version')!r}")
    unsupported = sorted(set(pack) - _PACK_FIELDS)
    if unsupported:
        raise ValueError(f"attack pack has unsupported fields: {unsupported}")
    attacks = pack.get("attacks")
    if not isinstance(attacks, Sequence) or isinstance(attacks, (str, bytes)) or not attacks:
        raise ValueError("attack pack attacks must be a non-empty list")

    seen = set()
    library: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for entry in attacks:
        if not isinstance(entry, Mapping) or set(entry) != _ATTACK_FIELDS:
            raise ValueError(f"attack pack entries must have exactly the fields {sorted(_ATTACK_FIELDS)}")
        attack_id, category, index = entry["id"], entry["category"], entry["index"]
        if (not isinstance(category, str) or not category
                or isinstance(index, bool) or not isinstance(index, int) or index < 1
                or attack_id != attack_pack_id(category, index)):
            raise ValueError(f"attack pack ID {attack_id!r} does not match its category and index")
        if attack_id in seen:
            raise ValueError(f"attack pack contains duplicate attack ID: {attack_id}")
        seen.add(attack_id)
        if entry["severity"] not in SEVERITIES:
            raise ValueError(f"attack {attack_id} has unknown severity: {entry['severity']!r}")
        if not isinstance(entry["prompt"], str) or not entry["prompt"].strip():
            raise ValueError(f"attack {attack_id} needs a non-empty prompt")
        if not isinstance(entry["description"], str):
            raise ValueError(f"attack {attack_id} description must be a string")
        _validate_oracle(f"attack {attack_id}", entry["oracle"])
        library.setdefault(category, []).append(
            (index, {field: entry[field] for field in _LIBRARY_FIELDS})
        )

    # Rebuild the library from the pack so a dropped, added, or edited attack
    # cannot hide behind a library digest the pack no longer matches.
    rebuilt = {
        category: [attack for _, attack in sorted(rows, key=lambda row: row[0])]
        for category, rows in library.items()
    }
    if attack_library_digest(rebuilt) != pack.get("library_sha256"):
        raise ValueError("attack pack attacks do not match its library_sha256")


def build_attack_pack(
    library: Mapping[str, Sequence[Mapping[str, Any]]] = ATTACK_LIBRARY,
    oracles: Mapping[str, Mapping[str, Any]] = ORACLES,
) -> dict[str, Any]:
    """Join the complete, unfiltered attack library to its oracles and validate it."""

    entries = []
    for category, attacks in library.items():
        for index, attack in enumerate(attacks, start=1):
            attack_id = attack_pack_id(category, index)
            unsupported = sorted(set(attack) - _LIBRARY_FIELDS)
            if unsupported:
                raise ValueError(f"attack {attack_id} has fields the pack schema does not carry: {unsupported}")
            entries.append({
                "id": attack_id,
                "category": category,
                "index": index,
                "prompt": attack.get("prompt"),
                "severity": attack.get("severity"),
                "description": attack.get("description"),
                "oracle": dict(oracles[attack_id]) if attack_id in oracles else None,
            })

    library_ids = {entry["id"] for entry in entries}
    missing = sorted(library_ids - set(oracles))
    if missing:
        raise ValueError(f"attack pack is missing oracles for: {', '.join(missing)}")
    extra = sorted(set(oracles) - library_ids)
    if extra:
        raise ValueError(f"attack pack has oracles for attacks not in the library: {', '.join(extra)}")

    pack = {
        "schema_version": ATTACK_PACK_SCHEMA_VERSION,
        "library_sha256": attack_library_digest(library),
        "attacks": entries,
    }
    validate_attack_pack(pack)
    return pack


def attack_pack_digest(pack: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the pack's canonical JSON serialization."""

    encoded = json.dumps(pack, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def evaluate_deterministic_oracle(oracle: Mapping[str, Any], response: str) -> Optional[bool]:
    """Decide a deterministic oracle; return None for judge-evaluated oracles."""

    _validate_oracle("deterministic evaluation", oracle)
    if not isinstance(response, str):
        raise TypeError("oracle response must be a string")
    if oracle["evaluator"] == "judge":
        return None
    # Rule outside-refusal-1.0: a refusal that only quotes the marker is not output.
    from agentprobe.verdicts import marker_output_succeeded

    return marker_output_succeeded(oracle["marker"], response)
