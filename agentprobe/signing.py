"""Signed attack packs: Ed25519 signatures over a pack's content digest.

A signed pack carries ``manifest.sig`` beside ``manifest.yaml``. It is a small
JSON document holding the signed fields (schema_version, algorithm, the
signer's public key and key id, the pack id and version, and the pack's
SHA-256 content digest), plus an Ed25519 signature over the canonical JSON of
those fields. The content digest already covers the manifest and every
attack, so changing a single byte of an attack invalidates the signature.

Two separate questions are answered for each pack:

* **Integrity:** does the signature verify, and does the signed digest match
  the pack as loaded? A failure means the pack changed after signing, and it
  is refused unless ``packs_trust`` mode is ``off``.
* **Trust:** is the signer's public key listed in ``packs_trust.keys``?

Everything is local: no network access, no license server. Signing and
signature verification need the optional ``cryptography`` package
(``pip install 'agentprobe-security[signing]'``). Key ids and trust-list
parsing work without it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple


SIGNATURE_FILE = "manifest.sig"
SIGNATURE_SCHEMA_VERSION = "1.0"
ALGORITHM = "ed25519"
TRUST_MODES = ("require", "warn", "off")
INSTALL_HINT = "pip install 'agentprobe-security[signing]'"
MAX_SIGNATURE_BYTES = 64_000
# DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it.
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_SIGNED_FIELDS = ("schema_version", "algorithm", "public_key", "key_id",
                  "pack_id", "pack_version", "pack_sha256")


class SignatureError(ValueError):
    """A key, signature file, or signing operation is unusable."""


class SigningUnavailable(SignatureError):
    """The optional ``cryptography`` package is not installed."""


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as exc:
        raise SigningUnavailable(
            f"pack signing needs the 'cryptography' package: {INSTALL_HINT}") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def key_id(raw_public_key: bytes) -> str:
    """A short, stable name for a public key: the first 16 hex chars of its SHA-256."""

    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def parse_public_key(text: str) -> bytes:
    """Raw 32-byte Ed25519 key from PEM (SubjectPublicKeyInfo) or raw base64."""

    if not isinstance(text, str) or not text.strip():
        raise SignatureError("a public key must be non-empty text")
    text = text.strip()
    try:
        if text.startswith("-----BEGIN PUBLIC KEY-----"):
            body = "".join(line.strip() for line in text.splitlines()
                           if line.strip() and not line.startswith("-----"))
            der = base64.b64decode(body, validate=True)
            if len(der) != 44 or not der.startswith(_SPKI_PREFIX):
                raise SignatureError("the PEM key is not an Ed25519 public key")
            return der[len(_SPKI_PREFIX):]
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        if isinstance(exc, SignatureError):
            raise
        raise SignatureError("a public key must be PEM or base64 of 32 raw bytes") from exc
    if len(raw) != 32:
        raise SignatureError("a raw base64 public key must decode to 32 bytes")
    return raw


@dataclass(frozen=True)
class TrustPolicy:
    """How packs' signatures are treated in one scan (config ``packs_trust``)."""

    mode: str = "warn"
    keys: FrozenSet[bytes] = frozenset()

    def trusts(self, raw_public_key: bytes) -> bool:
        return raw_public_key in self.keys


def trust_policy(block: Any) -> TrustPolicy:
    """Validate a ``packs_trust`` config block; an absent block means warn with no keys."""

    if block is None:
        return TrustPolicy()
    if not isinstance(block, Mapping):
        raise SignatureError("packs_trust must be a mapping with mode and keys")
    unknown = sorted(str(key) for key in block if key not in {"mode", "keys"})
    if unknown:
        raise SignatureError(f"packs_trust has unknown fields: {', '.join(unknown)}")
    mode = block.get("mode", "warn")
    if mode not in TRUST_MODES:
        raise SignatureError(f"packs_trust.mode must be one of {', '.join(TRUST_MODES)}")
    keys = block.get("keys", [])
    if not isinstance(keys, list):
        raise SignatureError("packs_trust.keys must be a list of public keys")
    return TrustPolicy(mode, frozenset(parse_public_key(key) for key in keys))


def _canonical(fields: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(fields), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def generate_keypair(prefix: str) -> Tuple[str, str, str]:
    """Write ``<prefix>.key`` (PEM PKCS8, mode 0600 where supported) and ``<prefix>.pub``.

    The public key is written as one line of raw base64, ready for
    ``packs_trust.keys``. Existing files are never overwritten.
    """

    _, serialization, private_type, _ = _crypto()
    private_path, public_path = f"{prefix}.key", f"{prefix}.pub"
    for path in (private_path, public_path):
        if os.path.exists(path):
            raise SignatureError(f"{path} already exists; refusing to overwrite a key")
    key = private_type.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    raw_public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass  # Windows and some filesystems cannot express POSIX modes.
    with open(public_path, "w", encoding="ascii", newline="\n") as handle:
        handle.write(base64.b64encode(raw_public).decode("ascii") + "\n")
    return private_path, public_path, key_id(raw_public)


def _load_private_key(path: str):
    _, serialization, private_type, _ = _crypto()
    try:
        with open(path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SignatureError(f"cannot read the private key {path}: {exc}") from exc
    if not isinstance(key, private_type):
        raise SignatureError(f"{path} is not an Ed25519 private key")
    return key


def sign_fields(pack_id: str, pack_version: str, pack_sha256: str,
                private_key_path: str) -> Dict[str, str]:
    """Return the manifest.sig document for a pack, signed with the given key."""

    _, serialization, _, _ = _crypto()
    key = _load_private_key(private_key_path)
    raw_public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    fields = {"schema_version": SIGNATURE_SCHEMA_VERSION, "algorithm": ALGORITHM,
              "public_key": base64.b64encode(raw_public).decode("ascii"),
              "key_id": key_id(raw_public), "pack_id": pack_id,
              "pack_version": pack_version, "pack_sha256": pack_sha256}
    signature = key.sign(_canonical(fields))
    return {**fields, "signature": base64.b64encode(signature).decode("ascii")}


def write_signature(pack_dir: str, document: Mapping[str, str]) -> str:
    path = os.path.join(pack_dir, SIGNATURE_FILE)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(document), indent=2, sort_keys=True) + "\n")
    return path


def read_signature(pack_dir: str) -> Optional[Dict[str, str]]:
    """The pack's manifest.sig as a checked dict, or None when the pack is unsigned."""

    path = os.path.join(pack_dir, SIGNATURE_FILE)
    if not os.path.exists(path):
        return None
    if os.path.getsize(path) > MAX_SIGNATURE_BYTES:
        raise SignatureError(f"{SIGNATURE_FILE} is larger than {MAX_SIGNATURE_BYTES} bytes")
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignatureError(f"{SIGNATURE_FILE} is not readable JSON: {exc}") from exc
    expected = set(_SIGNED_FIELDS) | {"signature"}
    if not isinstance(document, dict) or set(document) != expected:
        raise SignatureError(f"{SIGNATURE_FILE} must have exactly {sorted(expected)}")
    if not all(isinstance(document[name], str) and document[name] for name in expected):
        raise SignatureError(f"{SIGNATURE_FILE} fields must be non-empty strings")
    if (document["schema_version"] != SIGNATURE_SCHEMA_VERSION
            or document["algorithm"] != ALGORITHM):
        raise SignatureError(f"{SIGNATURE_FILE} must be schema {SIGNATURE_SCHEMA_VERSION}, "
                             f"algorithm {ALGORITHM}")
    return document


def check_signature(document: Mapping[str, str], pack_id: str, pack_version: str,
                    pack_sha256: str) -> Tuple[Optional[bool], str]:
    """(intact, reason). intact is None when cryptography is missing but nothing else failed."""

    if document["pack_id"] != pack_id or document["pack_version"] != pack_version:
        return False, "the signature is for a different pack or version"
    if document["pack_sha256"] != pack_sha256:
        return False, "the pack's content changed after it was signed"
    try:
        raw_public = parse_public_key(document["public_key"])
    except SignatureError as exc:
        return False, str(exc)
    if key_id(raw_public) != document["key_id"]:
        return False, "the key id does not match the signing key"
    try:
        invalid, _, _, public_type = _crypto()
    except SigningUnavailable:
        return None, f"the signature was not checked: {INSTALL_HINT}"
    try:
        signature = base64.b64decode(document["signature"], validate=True)
        public_type.from_public_bytes(raw_public).verify(
            signature, _canonical({name: document[name] for name in _SIGNED_FIELDS}))
    except (invalid, binascii.Error, ValueError):
        return False, "the signature does not verify"
    return True, "the signature verifies"
