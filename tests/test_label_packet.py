import csv
import json
import os

import pytest

from research._common import canonical_digest
from research.label_packet import (
    append_imported_labels,
    export_packet,
    read_packet_answers,
)


def _corpus():
    return [
        {
            "response_id": f"response-{index}",
            "category": "fixture",
            "attack_index": index,
            "severity": "HIGH",
            "target_model": "target-fixture",
            "attack_prompt": f"attack prompt {index}",
            "response": f"model response {index}",
            "keyword_verdict": "REFUSED",
        }
        for index in range(1, 4)
    ]


def _export(tmp_path):
    corpus = _corpus()
    digest = canonical_digest(corpus)
    packet = tmp_path / "friend.label-packet.csv"
    key = tmp_path / "friend.label-packet.csv.key.json"
    export_packet(str(packet), str(key), corpus, digest, "friend")
    return corpus, digest, packet, key


def test_export_is_blinded_and_round_trips_labels(tmp_path):
    corpus, digest, packet, key = _export(tmp_path)

    with packet.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == ("item_id", "attack_prompt", "response", "label", "note")
    assert all("response_id" not in row for row in rows)
    assert "keyword_verdict" not in packet.read_text(encoding="utf-8")
    assert "severity" not in packet.read_text(encoding="utf-8")
    assert os.stat(packet).st_mode & 0o777 == 0o600
    assert os.stat(key).st_mode & 0o777 == 0o600

    rows[0]["label"] = "COMPLIED"
    rows[1]["label"] = "PARTIAL"
    rows[1]["note"] = "hedged before providing a usable payload"
    with packet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)

    imported = read_packet_answers(str(packet), str(key), digest, labeler="friend", corpus=corpus)
    assert {row["label"] for row in imported} == {"COMPLIED", "PARTIAL"}
    assert {row["response_id"] for row in imported} == {"response-1", "response-2"}
    assert all(row["corpus_sha256"] == digest for row in imported)

    labels = tmp_path / "labels.csv"
    assert append_imported_labels(str(labels), imported, digest) == 2
    assert append_imported_labels(str(labels), imported, digest) == 0
    assert labels.read_text(encoding="utf-8").count("response-") == 2


def test_import_rejects_changed_packet_text(tmp_path):
    corpus, digest, packet, key = _export(tmp_path)
    text = packet.read_text(encoding="utf-8").replace("model response 1", "forged response")
    packet.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="text was changed"):
        read_packet_answers(str(packet), str(key), digest, corpus=corpus)


def test_import_rejects_wrong_corpus_and_tampered_private_mapping(tmp_path):
    corpus, digest, packet, key = _export(tmp_path)
    with pytest.raises(ValueError, match="different corpus"):
        read_packet_answers(str(packet), str(key), "0" * 64, corpus=corpus)

    key_data = json.loads(key.read_text(encoding="utf-8"))
    key_data["items"]["item-0001"]["response_id"] = "not-in-corpus"
    key.write_text(json.dumps(key_data), encoding="utf-8")
    with pytest.raises(ValueError, match="outside the corpus"):
        read_packet_answers(str(packet), str(key), digest, corpus=corpus)


def test_import_rejects_invalid_labels_and_conflicts(tmp_path):
    corpus, digest, packet, key = _export(tmp_path)
    rows = list(csv.DictReader(packet.open(newline="", encoding="utf-8")))
    rows[0]["label"] = "MAYBE"
    with packet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ValueError, match="invalid human label"):
        read_packet_answers(str(packet), str(key), digest, corpus=corpus)

    rows[0]["label"] = "REFUSED"
    with packet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    imported = read_packet_answers(str(packet), str(key), digest, corpus=corpus)
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "response_id,labeler,label,note,category,target_model,corpus_sha256\n"
        f"{imported[0]['response_id']},friend,COMPLIED,,,target-fixture,{digest}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="conflicts with existing label"):
        append_imported_labels(str(labels), imported, digest)


def test_import_rejects_malformed_csv_rows(tmp_path):
    corpus, digest, packet, key = _export(tmp_path)
    lines = packet.read_text(encoding="utf-8").splitlines()
    lines.insert(2, "extra-cell")
    packet.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed CSV"):
        read_packet_answers(str(packet), str(key), digest, corpus=corpus)


def test_manifest_backed_second_label_packet_uses_preregistered_subset(tmp_path):
    from research.protocol import expected_second_label_ids, load_manifest

    corpus = _corpus()
    manifest = load_manifest()
    digest = canonical_digest(corpus)
    packet = tmp_path / "friend.label-packet.csv"
    key = tmp_path / "friend.label-packet.csv.key.json"
    export_packet(
        str(packet), str(key), corpus, digest, manifest["labels"]["second"],
        manifest=manifest,
    )
    expected = expected_second_label_ids(
        corpus,
        manifest["labels"]["second_overlap_fraction"],
        manifest["labels"]["second_subset_seed"],
    )
    key_data = json.loads(key.read_text(encoding="utf-8"))
    assert len(key_data["items"]) == len(expected)
    assert key_data["subset_seed"] == manifest["labels"]["second_subset_seed"]
