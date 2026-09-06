"""Blinded export/import packets for independent human labeling.

The terminal labeler is useful for local work, but an independent annotator
should receive only the attack and target response.  This module separates the
human-facing packet from a private key that binds opaque item IDs back to the
frozen corpus.  The key must not be shared with the annotator.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import re
import tempfile
from io import StringIO
from typing import Mapping, Sequence

from research._common import canonical_digest
from research.protocol import expected_second_label_ids, manifest_digest


PACKET_SCHEMA_VERSION = "1.0"
PACKET_FIELDS = ("item_id", "attack_prompt", "response", "label", "note")
LABEL_FIELDS = (
    "response_id", "labeler", "label", "note", "category", "target_model",
    "corpus_sha256", "labeling_guide_sha256",
)
LABELS = frozenset({"COMPLIED", "PARTIAL", "REFUSED"})


def _atomic_text(path: str, text: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".agentprobe-label-packet-", dir=directory)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle, parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _payload_digest(rows: Sequence[Mapping[str, str]]) -> str:
    payload = [
        {
            "item_id": row["item_id"],
            "attack_prompt": row["attack_prompt"],
            "response": row["response"],
        }
        for row in sorted(rows, key=lambda row: row["item_id"])
    ]
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _selected_rows(corpus, labeler: str, manifest=None, subset=None, seed=None):
    if not isinstance(labeler, str) or not labeler.strip():
        raise ValueError("labeler must be a non-empty string")
    rows = list(corpus)
    if any(not isinstance(row, Mapping) for row in rows):
        raise ValueError("corpus contains a non-object row")
    if any(row.get("error") for row in rows):
        raise ValueError("cannot create a label packet while target errors remain in the corpus")
    ids = [row.get("response_id") for row in rows]
    if any(not isinstance(response_id, str) or not response_id for response_id in ids):
        raise ValueError("corpus contains a missing response_id")
    if len(ids) != len(set(ids)):
        raise ValueError("corpus contains duplicate response_id values")

    if manifest:
        labels = manifest["labels"]
        if labeler == labels["second"]:
            expected_subset = float(labels["second_overlap_fraction"])
            expected_seed = labels["second_subset_seed"]
            if subset is None:
                subset = expected_subset
            if seed is None:
                seed = expected_seed
            if float(subset) != expected_subset or seed != expected_seed:
                raise ValueError("label packet scope does not match the manifest")
    if seed is None:
        seed = 42
    if subset is not None:
        if not 0 < float(subset) <= 1:
            raise ValueError("subset must be greater than 0 and at most 1")
        selected_ids = expected_second_label_ids(rows, float(subset), int(seed))
        rows = [row for row in rows if row["response_id"] in selected_ids]
    return rows, subset, seed


def export_packet(packet_path: str, key_path: str, corpus, corpus_sha256: str,
                  labeler: str, manifest=None, subset=None, seed=None,
                  overwrite=False, labeling_guide_sha256: str | None = None
                  ) -> tuple[str, str, int]:
    """Write a blinded CSV packet and a private mapping key."""

    if os.path.exists(packet_path) or os.path.exists(key_path):
        if not overwrite:
            raise ValueError("label packet already exists; use --overwrite-packet or new paths")
    rows, subset, seed = _selected_rows(corpus, labeler, manifest, subset, seed)
    if labeling_guide_sha256 is None and manifest:
        labeling_guide_sha256 = manifest.get("labeling_guide_sha256")
    if labeling_guide_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", labeling_guide_sha256):
        raise ValueError("labeling_guide_sha256 must be a 64-character SHA-256 hex digest")
    order = list(rows)
    random.Random(int(seed)).shuffle(order)

    packet_rows = []
    key_items = {}
    for index, row in enumerate(order, start=1):
        item_id = f"item-{index:04d}"
        packet_rows.append({
            "item_id": item_id,
            "attack_prompt": str(row.get("attack_prompt", "")),
            "response": str(row.get("response", "")),
            "label": "",
            "note": "",
        })
        key_items[item_id] = {
            "response_id": row["response_id"],
            "category": row.get("category", ""),
            "target_model": row.get("target_model", ""),
        }

    packet_sha256 = _payload_digest(packet_rows)
    buffer = StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=PACKET_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(packet_rows)
    packet_text = buffer.getvalue()
    key = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "artifact_type": "agentprobe_label_packet_key",
        "labeler": labeler,
        "corpus_sha256": corpus_sha256,
        "protocol_manifest_sha256": manifest_digest(manifest) if manifest else None,
        "labeling_guide_sha256": labeling_guide_sha256,
        "packet_sha256": packet_sha256,
        "subset": subset,
        "subset_seed": seed,
        "items": key_items,
    }
    _atomic_text(packet_path, packet_text)
    _atomic_text(key_path, json.dumps(key, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    return packet_path, key_path, len(packet_rows)


def read_packet_answers(packet_path: str, key_path: str, corpus_sha256: str,
                        labeler: str | None = None, corpus=None,
                        expected_protocol_manifest_sha256: str | None = None,
                        expected_labeling_guide_sha256: str | None = None
                        ) -> list[dict[str, str]]:
    """Validate a returned packet and convert completed rows to label records."""

    key = _read_json(key_path)
    if key.get("schema_version") != PACKET_SCHEMA_VERSION:
        raise ValueError("unsupported label packet key schema")
    if key.get("artifact_type") != "agentprobe_label_packet_key":
        raise ValueError("invalid label packet key artifact")
    if key.get("corpus_sha256") != corpus_sha256:
        raise ValueError("label packet belongs to a different corpus")
    if (expected_protocol_manifest_sha256 is not None
            and key.get("protocol_manifest_sha256") != expected_protocol_manifest_sha256):
        raise ValueError("label packet belongs to a different protocol manifest")
    packet_guide_digest = key.get("labeling_guide_sha256")
    if (packet_guide_digest is not None
            and (not isinstance(packet_guide_digest, str)
                 or not re.fullmatch(r"[0-9a-f]{64}", packet_guide_digest))):
        raise ValueError("label packet key has an invalid labeling guide digest")
    if (expected_labeling_guide_sha256 is not None
            and packet_guide_digest != expected_labeling_guide_sha256):
        raise ValueError("label packet belongs to a different labeling guide")
    packet_labeler = key.get("labeler")
    if not isinstance(packet_labeler, str) or not packet_labeler.strip():
        raise ValueError("label packet key has an invalid labeler")
    if labeler is not None and labeler != packet_labeler:
        raise ValueError("requested labeler does not match the packet key")
    key_items = key.get("items")
    if not isinstance(key_items, dict) or not key_items:
        raise ValueError("label packet key has no items")
    key_response_ids = set()
    for item_id, item in key_items.items():
        if not isinstance(item_id, str) or not item_id.strip():
            raise ValueError("label packet key has an invalid item ID")
        if not isinstance(item, dict):
            raise ValueError(f"label packet key item {item_id!r} is not an object")
        response_id = item.get("response_id")
        if not isinstance(response_id, str) or not response_id:
            raise ValueError(f"label packet key item {item_id!r} has an invalid response_id")
        if response_id in key_response_ids:
            raise ValueError("label packet key maps multiple items to one response_id")
        key_response_ids.add(response_id)

    corpus_by_id = None
    if corpus is not None:
        if canonical_digest(corpus) != corpus_sha256:
            raise ValueError("provided corpus does not match the expected corpus digest")
        corpus_by_id = {}
        for source in corpus:
            if not isinstance(source, Mapping):
                raise ValueError("provided corpus contains a non-object row")
            response_id = source.get("response_id")
            if not isinstance(response_id, str) or not response_id:
                raise ValueError("provided corpus contains a missing response_id")
            if response_id in corpus_by_id:
                raise ValueError("provided corpus contains duplicate response_id values")
            corpus_by_id[response_id] = source

    with open(packet_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != PACKET_FIELDS:
            raise ValueError("label packet columns do not match the packet schema")
        rows = list(reader)
    for row in rows:
        if None in row or any(row.get(field) is None for field in PACKET_FIELDS):
            raise ValueError("label packet contains a malformed CSV row")
    item_ids = [row.get("item_id") for row in rows]
    if len(item_ids) != len(set(item_ids)) or any(item_id not in key_items for item_id in item_ids):
        raise ValueError("label packet contains duplicate or unknown item IDs")
    if set(item_ids) != set(key_items):
        raise ValueError("label packet is missing assigned items")
    if _payload_digest(rows) != key.get("packet_sha256"):
        raise ValueError("label packet text was changed; export a fresh packet")

    if corpus_by_id is not None:
        for row in rows:
            item = key_items[row["item_id"]]
            source = corpus_by_id.get(item["response_id"])
            if source is None:
                raise ValueError("label packet key references a response outside the corpus")
            if (str(source.get("attack_prompt", "")) != row["attack_prompt"]
                    or str(source.get("response", "")) != row["response"]):
                raise ValueError("label packet key does not match the frozen corpus text")
            if str(source.get("category", "")) != str(item.get("category", "")):
                raise ValueError("label packet key does not match the frozen corpus category")
            if str(source.get("target_model", "")) != str(item.get("target_model", "")):
                raise ValueError("label packet key does not match the frozen target model")

    output = []
    seen_response_ids = set()
    for row in rows:
        label = (row.get("label") or "").strip().upper()
        if not label:
            continue
        if label not in LABELS:
            raise ValueError(f"invalid human label for {row['item_id']}: {label!r}")
        item = key_items[row["item_id"]]
        response_id = item.get("response_id")
        if response_id in seen_response_ids:
            raise ValueError("label packet maps multiple answers to one response_id")
        seen_response_ids.add(response_id)
        output.append({
            "response_id": response_id,
            "labeler": packet_labeler,
            "label": label,
            "note": row.get("note", ""),
            "category": item.get("category", ""),
            "target_model": item.get("target_model", ""),
            "corpus_sha256": corpus_sha256,
            "labeling_guide_sha256": packet_guide_digest,
        })
    return output


def append_imported_labels(path: str, rows: Sequence[Mapping[str, str]], corpus_sha256: str) -> int:
    """Append packet answers, rejecting conflicting existing labels."""

    existing = {}
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != LABEL_FIELDS:
                raise ValueError("existing labels do not match the label schema")
            for row in reader:
                if None in row or any(row.get(field) is None for field in LABEL_FIELDS):
                    raise ValueError("existing labels contain a malformed CSV row")
                if row.get("corpus_sha256") != corpus_sha256:
                    raise ValueError("existing labels are missing or bound to another corpus")
                key = (row.get("response_id"), row.get("labeler"))
                if key in existing:
                    raise ValueError(f"existing labels contain duplicate key {key}")
                existing[key] = row.get("label")

    pending = []
    for row in rows:
        key = (row["response_id"], row["labeler"])
        if key in existing:
            if existing[key] != row["label"]:
                raise ValueError(f"packet conflicts with existing label for {key}")
            continue
        if key in {(item["response_id"], item["labeler"]) for item in pending}:
            raise ValueError(f"packet contains duplicate label key {key}")
        pending.append(dict(row))

    if not pending:
        return 0
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    fields = LABEL_FIELDS
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerows(pending)
        handle.flush()
        os.fsync(handle.fileno())
    return len(pending)
