"""Attack packs: the built-in library and external packs, loaded the same way.

An external pack is a directory::

    my-pack/
      manifest.yaml       schema_version, id, version, license, categories
      attacks/*.yaml      each a mapping with one key, ``attacks``: a list

Every attack carries ``id``, ``category``, ``prompt``, ``severity``,
``description``, and an ``oracle`` (the schema in ``agentprobe.attackpack``).
The built-in library is the first pack (``agentprobe-core``), so a scan has
one code path whether or not external packs are used, and a built-in-only
selection is byte-for-byte what it was before packs existed.

Packs are data, never code: files are read with ``yaml.safe_load`` under size
limits, and anything unexpected is refused rather than ignored. A pack's
digest covers its parsed, canonical content, so it does not depend on
whitespace or line endings. Scan provenance records each pack's id, version,
license, attack count, and digest, never where it was loaded from.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from agentprobe.attackpack import (
    ATTACK_PACK_SCHEMA_VERSION, _validate_oracle, attack_pack_digest, build_attack_pack,
)
from agentprobe.reporting import SEVERITIES
from agentprobe.signing import (
    INSTALL_HINT, SignatureError, TrustPolicy, check_signature, parse_public_key,
    read_signature,
)


PACK_SCHEMA_VERSION = "1.0"
BUILTIN_PACK_ID = "agentprobe-core"
BUILTIN_PACK_VERSION = "1.0.0"
BUILTIN_ALIASES = frozenset({"builtin", BUILTIN_PACK_ID})
PACKS_PATH_ENV = "AGENTPROBE_PACKS_PATH"
MANIFEST_NAME = "manifest.yaml"
ATTACKS_DIR = "attacks"
MAX_FILE_BYTES = 1_000_000
MAX_ATTACKS = 1000
PROMPT_LIMIT = 4000
TEXT_LIMIT = 500

_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_ATTACK_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_CATEGORY = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_MANIFEST_FIELDS = frozenset({"schema_version", "id", "version", "license", "categories"})
_ATTACK_FIELDS = frozenset({"id", "category", "prompt", "severity", "description", "oracle"})


class PackError(ValueError):
    """A pack could not be found, read, or validated."""


@dataclass(frozen=True)
class AttackPack:
    """A validated pack. ``attacks`` keep pack order; ``index`` is per category."""

    id: str
    version: str
    license: str
    categories: Tuple[str, ...]
    attacks: Tuple[Mapping[str, Any], ...]
    sha256: str
    builtin: bool = False
    signed: bool = False
    signer_key_id: Optional[str] = None
    verified: bool = False

    def attacks_in(self, category: str) -> List[Mapping[str, Any]]:
        return [attack for attack in self.attacks if attack["category"] == category]

    def provenance(self) -> Dict[str, Any]:
        """What a scan report records about this pack: identity, never location."""

        return {"id": self.id, "version": self.version, "schema_version": PACK_SCHEMA_VERSION,
                "license": self.license, "attacks": len(self.attacks), "sha256": self.sha256,
                "signed": self.signed, "signer_key_id": self.signer_key_id,
                "verified": self.verified}


def builtin_pack() -> AttackPack:
    """The bundled library and its oracles as a pack; its digest is attack_pack_sha256."""

    pack = build_attack_pack()
    attacks = tuple(
        {"id": entry["id"], "category": entry["category"], "index": entry["index"],
         "prompt": entry["prompt"], "severity": entry["severity"],
         "description": entry["description"], "oracle": entry["oracle"]}
        for entry in pack["attacks"]
    )
    categories = tuple(dict.fromkeys(attack["category"] for attack in attacks))
    return AttackPack(BUILTIN_PACK_ID, BUILTIN_PACK_VERSION, "MIT", categories, attacks,
                      attack_pack_digest(pack), builtin=True)


def _read_yaml(path: str, label: str) -> Any:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise PackError(f"{label} cannot be read: {exc.strerror or exc}") from exc
    if size > MAX_FILE_BYTES:
        raise PackError(f"{label} is larger than {MAX_FILE_BYTES} bytes")
    try:
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except (OSError, UnicodeDecodeError) as exc:
        raise PackError(f"{label} cannot be read as UTF-8 text: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PackError(f"{label} is not valid YAML: {' '.join(str(exc).split())}") from exc


def _text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PackError(f"{label} must be non-empty text")
    if len(value) > limit:
        raise PackError(f"{label} is longer than {limit} characters")
    return value


def validate_manifest(manifest: Any) -> Dict[str, Any]:
    """Return the checked manifest fields, or raise PackError."""

    if not isinstance(manifest, Mapping):
        raise PackError("manifest must be a mapping")
    unknown = sorted(str(key) for key in manifest if key not in _MANIFEST_FIELDS)
    if unknown:
        raise PackError(f"manifest has unknown fields: {', '.join(unknown)}")
    missing = sorted(_MANIFEST_FIELDS - set(manifest))
    if missing:
        raise PackError(f"manifest is missing fields: {', '.join(missing)}")
    if manifest["schema_version"] != PACK_SCHEMA_VERSION:
        raise PackError(f"manifest schema_version must be {PACK_SCHEMA_VERSION!r}, "
                        f"not {manifest['schema_version']!r}")
    pack_id = manifest["id"]
    if not isinstance(pack_id, str) or not _PACK_ID.match(pack_id):
        raise PackError(f"manifest id {pack_id!r} must be 2-63 lowercase letters, digits, or hyphens")
    if pack_id in BUILTIN_ALIASES:
        raise PackError(f"manifest id {pack_id!r} is reserved for the built-in pack")
    version = manifest["version"]
    if not isinstance(version, str) or not _VERSION.match(version):
        raise PackError(f"manifest version {version!r} must be MAJOR.MINOR.PATCH, as a quoted string")
    _text(manifest["license"], "manifest license", 100)
    categories = manifest["categories"]
    if not isinstance(categories, list) or not categories:
        raise PackError("manifest categories must be a non-empty list")
    for category in categories:
        if not isinstance(category, str) or not _CATEGORY.match(category):
            raise PackError(f"manifest category {category!r} must be lowercase snake_case")
    if len(set(categories)) != len(categories):
        raise PackError("manifest categories must not repeat")
    return dict(manifest)


def _validate_attack(entry: Any, label: str, categories: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        raise PackError(f"{label} must be a mapping")
    if set(entry) != _ATTACK_FIELDS:
        extra = sorted(str(key) for key in set(entry) - _ATTACK_FIELDS)
        missing = sorted(_ATTACK_FIELDS - set(entry))
        detail = "; ".join(part for part in (
            f"unknown fields: {', '.join(extra)}" if extra else "",
            f"missing fields: {', '.join(missing)}" if missing else "",
        ) if part)
        raise PackError(f"{label} must have exactly {sorted(_ATTACK_FIELDS)} ({detail})")
    attack_id = entry["id"]
    if not isinstance(attack_id, str) or not _ATTACK_ID.match(attack_id):
        raise PackError(f"{label} id {attack_id!r} must be lowercase letters, digits, - or _")
    label = f"attack {attack_id}"
    if entry["category"] not in categories:
        raise PackError(f"{label} category {entry['category']!r} is not listed in the manifest")
    if entry["severity"] not in SEVERITIES:
        raise PackError(f"{label} severity must be one of {', '.join(SEVERITIES)}")
    _text(entry["prompt"], f"{label} prompt", PROMPT_LIMIT)
    _text(entry["description"], f"{label} description", TEXT_LIMIT)
    try:
        _validate_oracle(label, entry["oracle"])
    except ValueError as exc:
        raise PackError(str(exc)) from exc
    return {field: entry[field] for field in
            ("id", "category", "prompt", "severity", "description")} | {
        "oracle": dict(entry["oracle"])}


def _apply_signature(pack: AttackPack, path: str, trust: TrustPolicy) -> AttackPack:
    """Record the pack's signature status under ``trust``, or refuse the pack.

    A signature that does not match the pack is refused in every mode but
    ``off``. In ``require`` mode an unsigned pack, a pack signed by an untrusted
    key, or a signature that cannot be checked is refused too.
    """

    try:
        document = read_signature(path)
    except SignatureError as exc:
        if trust.mode == "off":
            return pack
        raise PackError(f"pack {pack.id}: {exc}") from exc
    if trust.mode == "off":
        return replace(pack, signed=document is not None,
                       signer_key_id=document["key_id"] if document else None)
    if document is None:
        if trust.mode == "require":
            raise PackError(f"pack {pack.id} is not signed, and packs_trust mode is require")
        return pack
    intact, reason = check_signature(document, pack.id, pack.version, pack.sha256)
    if intact is False:
        raise PackError(f"pack {pack.id} fails its signature check: {reason}")
    trusted = trust.trusts(parse_public_key(document["public_key"]))
    if trust.mode == "require":
        if intact is None:
            raise PackError(f"pack {pack.id} cannot be verified without the 'cryptography' "
                            f"package: {INSTALL_HINT}")
        if not trusted:
            raise PackError(f"pack {pack.id} is signed by key {document['key_id']}, which "
                            "packs_trust does not list")
    return replace(pack, signed=True, signer_key_id=document["key_id"],
                   verified=bool(intact and trusted))


def load_pack(path: str, trust: Optional[TrustPolicy] = None) -> AttackPack:
    """Load and validate the pack directory at ``path``, then check its signature.

    ``trust`` defaults to ``warn`` with no trusted keys: a signature is still
    checked for integrity, but no pack counts as verified.
    """

    if not os.path.isdir(path):
        raise PackError(f"pack {path!r} is not a directory")
    manifest = validate_manifest(_read_yaml(os.path.join(path, MANIFEST_NAME), MANIFEST_NAME))
    attacks_dir = os.path.join(path, ATTACKS_DIR)
    if not os.path.isdir(attacks_dir):
        raise PackError(f"pack {manifest['id']} has no {ATTACKS_DIR}/ directory")
    names = sorted(os.listdir(attacks_dir))
    stray = [name for name in names if not name.endswith(".yaml")
             or not os.path.isfile(os.path.join(attacks_dir, name))]
    if stray:
        raise PackError(f"{ATTACKS_DIR}/ may hold only .yaml files; found: {', '.join(stray)}")
    if not names:
        raise PackError(f"pack {manifest['id']} has no attack files in {ATTACKS_DIR}/")

    attacks: List[Dict[str, Any]] = []
    for name in names:
        label = f"{ATTACKS_DIR}/{name}"
        document = _read_yaml(os.path.join(attacks_dir, name), label)
        if not isinstance(document, Mapping) or set(document) != {"attacks"}:
            raise PackError(f"{label} must be a mapping with exactly one key, attacks")
        entries = document["attacks"]
        if not isinstance(entries, list) or not entries:
            raise PackError(f"{label} attacks must be a non-empty list")
        for position, entry in enumerate(entries, start=1):
            attacks.append(_validate_attack(entry, f"{label} entry {position}",
                                            manifest["categories"]))
    if len(attacks) > MAX_ATTACKS:
        raise PackError(f"pack {manifest['id']} has more than {MAX_ATTACKS} attacks")
    seen = set()
    for attack in attacks:
        if attack["id"] in seen:
            raise PackError(f"pack {manifest['id']} repeats attack id {attack['id']!r}")
        seen.add(attack["id"])
    used = {attack["category"] for attack in attacks}
    unused = [category for category in manifest["categories"] if category not in used]
    if unused:
        raise PackError(f"manifest lists categories no attack uses: {', '.join(unused)}")

    content = {**manifest, "attacks": attacks}
    encoded = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    sha256 = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    counters: Dict[str, int] = {}
    indexed = []
    for attack in attacks:  # per-category index in pack order, like the built-in library
        counters[attack["category"]] = counters.get(attack["category"], 0) + 1
        indexed.append({**attack, "index": counters[attack["category"]]})
    pack = AttackPack(manifest["id"], manifest["version"], manifest["license"],
                      tuple(manifest["categories"]), tuple(indexed), sha256)
    return _apply_signature(pack, path, trust or TrustPolicy())


def _search_path() -> List[str]:
    return [entry for entry in os.environ.get(PACKS_PATH_ENV, "").split(os.pathsep) if entry]


def resolve_pack(spec: str, base_dir: Optional[str] = None,
                 trust: Optional[TrustPolicy] = None) -> AttackPack:
    """Load a pack by name ("builtin"), by path, or by name from AGENTPROBE_PACKS_PATH.

    A relative path is resolved against ``base_dir`` (the config file's folder
    for packs named in a config, the working directory for --pack).
    """

    if not isinstance(spec, str) or not spec.strip():
        raise PackError("a pack must be named by a non-empty string")
    if spec in BUILTIN_ALIASES:
        return builtin_pack()  # ships inside the package; its release is signed instead
    candidate = spec if os.path.isabs(spec) else os.path.join(base_dir or os.getcwd(), spec)
    if os.path.isdir(candidate):
        return load_pack(candidate, trust)
    if _PACK_ID.match(spec):
        for root in _search_path():
            located = os.path.join(root, spec)
            if os.path.isfile(os.path.join(located, MANIFEST_NAME)):
                return load_pack(located, trust)
    raise PackError(f"pack {spec!r} not found: not 'builtin', not a directory, and not "
                    f"in {PACKS_PATH_ENV}")


def ensure_unique(packs: Sequence[AttackPack]) -> List[AttackPack]:
    seen = set()
    for pack in packs:
        if pack.id in seen:
            raise PackError(f"pack {pack.id!r} is loaded more than once")
        seen.add(pack.id)
    return list(packs)


def load_packs(config_specs: Optional[Iterable[str]] = None, config_dir: Optional[str] = None,
               extra_specs: Iterable[str] = (),
               trust: Optional[TrustPolicy] = None) -> List[AttackPack]:
    """The packs for one scan: the config's list (default: built-in), then --pack additions."""

    specs = list(config_specs) if config_specs else ["builtin"]
    packs = [resolve_pack(spec, config_dir, trust) for spec in specs]
    packs += [resolve_pack(spec, None, trust) for spec in extra_specs]
    return ensure_unique(packs)


def available_packs(trust: Optional[TrustPolicy] = None) -> List[Tuple[str, Any]]:
    """(source, pack or PackError) for the built-in pack and every AGENTPROBE_PACKS_PATH pack."""

    found: List[Tuple[str, Any]] = [("built-in", builtin_pack())]
    for root in _search_path():
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if os.path.isfile(os.path.join(path, MANIFEST_NAME)):
                try:
                    found.append((path, load_pack(path, trust)))
                except PackError as exc:
                    found.append((path, exc))
    return found


__all__ = [
    "ATTACK_PACK_SCHEMA_VERSION", "AttackPack", "BUILTIN_PACK_ID", "PACK_SCHEMA_VERSION",
    "PACKS_PATH_ENV", "PackError", "available_packs", "builtin_pack", "ensure_unique",
    "load_pack", "load_packs", "resolve_pack", "validate_manifest",
]
