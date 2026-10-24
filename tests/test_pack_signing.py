"""Signed attack packs: keys, signing, trust modes, tamper detection, provenance."""

import base64
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")

from agentprobe import scanner, signing  # noqa: E402
from agentprobe.cli import main  # noqa: E402
from agentprobe.config import validate_config  # noqa: E402
from agentprobe.customer_report import render_customer_report  # noqa: E402
from agentprobe.packs import PackError, load_pack, load_packs  # noqa: E402
from agentprobe.signing import (  # noqa: E402
    SignatureError, SigningUnavailable, TrustPolicy, generate_keypair, key_id,
    parse_public_key, sign_fields, trust_policy, write_signature,
)


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "packs" / "support-desk-sample"


@pytest.fixture
def keys(tmp_path):
    private, public, kid = generate_keypair(str(tmp_path / "publisher"))
    other_private, other_public, _ = generate_keypair(str(tmp_path / "someone-else"))
    return SimpleNamespace(private=private, public=Path(public).read_text().strip(), kid=kid,
                           other_private=other_private,
                           other_public=Path(other_public).read_text().strip())


@pytest.fixture
def signed_pack(tmp_path, keys):
    pack_dir = tmp_path / "pack"
    shutil.copytree(EXAMPLE, pack_dir)
    pack = load_pack(str(pack_dir), TrustPolicy("off"))
    write_signature(str(pack_dir), sign_fields(pack.id, pack.version, pack.sha256, keys.private))
    return pack_dir


def _trust(mode, *public_keys):
    return TrustPolicy(mode, frozenset(parse_public_key(key) for key in public_keys))


# ---------------------------------------------------------------- keys

def test_keygen_writes_a_private_and_public_key_and_never_overwrites(tmp_path, keys):
    private = Path(keys.private)
    assert private.read_text().startswith("-----BEGIN PRIVATE KEY-----")
    assert len(base64.b64decode(keys.public)) == 32
    assert keys.kid == key_id(parse_public_key(keys.public)) and len(keys.kid) == 16
    if os.name != "nt":  # NTFS has no POSIX mode bits
        assert private.stat().st_mode & 0o777 == 0o600
    with pytest.raises(SignatureError, match="refusing to overwrite"):
        generate_keypair(str(tmp_path / "publisher"))


def test_public_keys_parse_from_raw_base64_and_pem(keys):
    from cryptography.hazmat.primitives import serialization

    raw = parse_public_key(keys.public)
    key = serialization.load_pem_private_key(Path(keys.private).read_bytes(), password=None)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert parse_public_key(pem.decode("ascii")) == raw
    for bad in ("", "not base64!", base64.b64encode(b"short").decode()):
        with pytest.raises(SignatureError):
            parse_public_key(bad)


# ----------------------------------------------------------- verification

def test_signed_pack_verifies_only_against_a_trusted_key(signed_pack, keys):
    trusted = load_pack(str(signed_pack), _trust("warn", keys.public))
    assert (trusted.signed, trusted.signer_key_id, trusted.verified) == (True, keys.kid, True)
    untrusted = load_pack(str(signed_pack), _trust("warn", keys.other_public))
    assert (untrusted.signed, untrusted.verified) == (True, False)
    assert load_pack(str(signed_pack)).verified is False  # default: warn, no keys


def test_one_byte_changed_in_an_attack_file_fails_verification(signed_pack, keys):
    attack_file = signed_pack / "attacks" / "support.yaml"
    data = bytearray(attack_file.read_bytes())
    position = data.index(b"TICKET-MARKER-41") + len("TICKET-MARKER-4")
    data[position] = ord("2")
    attack_file.write_bytes(bytes(data))
    for mode in ("warn", "require"):
        with pytest.raises(PackError, match="content changed after it was signed"):
            load_pack(str(signed_pack), _trust(mode, keys.public))
    assert load_pack(str(signed_pack), _trust("off")).verified is False


def test_a_forged_or_swapped_signature_fails(signed_pack, keys):
    sig_path = signed_pack / "manifest.sig"
    document = json.loads(sig_path.read_text())
    forged = dict(document, signature=base64.b64encode(b"\0" * 64).decode())
    sig_path.write_text(json.dumps(forged))
    with pytest.raises(PackError, match="does not verify"):
        load_pack(str(signed_pack), _trust("warn", keys.public))
    swapped = dict(document, public_key=keys.other_public,
                   key_id=key_id(parse_public_key(keys.other_public)))
    sig_path.write_text(json.dumps(swapped))
    with pytest.raises(PackError, match="does not verify"):
        load_pack(str(signed_pack), _trust("warn", keys.other_public))
    sig_path.write_text(json.dumps(dict(document, key_id="0" * 16)))
    with pytest.raises(PackError, match="key id does not match"):
        load_pack(str(signed_pack), _trust("warn", keys.public))


def test_require_mode_refuses_unsigned_and_untrusted_packs(signed_pack, keys):
    with pytest.raises(PackError, match="not signed, and packs_trust mode is require"):
        load_pack(str(EXAMPLE), _trust("require", keys.public))
    with pytest.raises(PackError, match="which packs_trust does not list"):
        load_pack(str(signed_pack), _trust("require", keys.other_public))
    assert load_pack(str(signed_pack), _trust("require", keys.public)).verified is True
    builtin, = load_packs(["builtin"], trust=_trust("require", keys.public))
    assert builtin.builtin and not builtin.signed  # covered by the package's own release


def test_malformed_signature_files_are_refused_unless_trust_is_off(signed_pack, keys):
    (signed_pack / "manifest.sig").write_text("{not json")
    with pytest.raises(PackError, match="not readable JSON"):
        load_pack(str(signed_pack), _trust("warn", keys.public))
    assert load_pack(str(signed_pack), _trust("off")).signed is False


def test_without_cryptography_signing_fails_clearly_and_checks_degrade(signed_pack, keys,
                                                                       monkeypatch):
    def unavailable():
        raise SigningUnavailable(f"pack signing needs the 'cryptography' package: "
                                 f"{signing.INSTALL_HINT}")

    monkeypatch.setattr(signing, "_crypto", unavailable)
    with pytest.raises(SigningUnavailable, match=r"agentprobe-security\[signing\]"):
        sign_fields("p", "1.0.0", "0" * 64, keys.private)
    warned = load_pack(str(signed_pack), _trust("warn", keys.public))
    assert (warned.signed, warned.verified) == (True, False)
    with pytest.raises(PackError, match="cannot be verified without the 'cryptography'"):
        load_pack(str(signed_pack), _trust("require", keys.public))
    attack_file = signed_pack / "attacks" / "support.yaml"
    attack_file.write_text(attack_file.read_text().replace("41", "42"))
    with pytest.raises(PackError, match="content changed"):  # digest check needs no crypto
        load_pack(str(signed_pack), _trust("warn", keys.public))


# ------------------------------------------------------------- config

def test_packs_trust_config_is_validated(keys):
    base = {"target": {"provider": "ollama", "model": "t-3b"},
            "judge": {"provider": "ollama", "model": "j-8b"}}
    assert validate_config({**base, "packs_trust": {"mode": "require", "keys": [keys.public]}})
    assert trust_policy(None) == TrustPolicy()
    for block, message in (({"mode": "strict"}, "mode must be one of"),
                           ({"keys": "x"}, "keys must be a list"),
                           ({"keys": ["nope!"]}, "PEM or base64"),
                           ({"mode": "warn", "extra": 1}, "unknown fields: extra")):
        with pytest.raises(ValueError, match=message):
            validate_config({**base, "packs_trust": block})


# ------------------------------------------------- scans and reports

class _Refusing:
    def __init__(self):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    @staticmethod
    def create(**_kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content="I can't help with that, and I won't provide it."))])


def _config(tmp_path, pack_dir, trust_block):
    config = tmp_path / "scan.yaml"
    config.write_text(
        "target: {provider: ollama, model: target-3b, max_tokens: 32}\n"
        "judge: {provider: ollama, model: judge-8b, max_tokens: 16}\n"
        f"packs: [builtin, {json.dumps(str(pack_dir))}]\n"
        f"packs_trust: {json.dumps(trust_block)}\n"
        "scan: {categories: [tool_misuse], rate_limit_seconds: 0, retries: 0,"
        " retry_delay_seconds: 0}\n"
        f"output: {{report_format: json, report_dir: {json.dumps(str(tmp_path / 'r'))}}}\n",
        encoding="utf-8")
    return str(config)


@pytest.fixture
def fake_providers(monkeypatch):
    monkeypatch.setattr(scanner, "build_client", lambda _block: _Refusing())
    monkeypatch.setattr(scanner, "preflight_model", lambda *_args, **_kwargs: None)


def test_scan_provenance_and_report_show_the_verified_signer(tmp_path, signed_pack, keys,
                                                             fake_providers):
    run = scanner.run_configured_scan(_config(tmp_path, signed_pack,
                                              {"mode": "require", "keys": [keys.public]}))
    packs = {pack["id"]: pack for pack in run["report"]["run"]["attack_packs"]}
    assert packs["support-desk-sample"] == {**packs["support-desk-sample"], "signed": True,
                                            "signer_key_id": keys.kid, "verified": True}
    assert packs["agentprobe-core"]["signed"] is False
    assert run["pack_warnings"] == []
    page = render_customer_report(run["report"])
    assert f"signed by {keys.kid}, verified" in page


def test_scan_warns_about_unverified_packs_when_keys_are_configured(tmp_path, keys,
                                                                     fake_providers, capsys):
    config = _config(tmp_path, EXAMPLE, {"mode": "warn", "keys": [keys.public]})
    assert main(["scan", "--non-interactive", "--no-color", "--config", config]) == 0
    assert "Warning: attack pack support-desk-sample 1.0.0 is not signed" in (
        capsys.readouterr().out)


# --------------------------------------------------------------------- CLI

def test_cli_keygen_sign_and_validate(tmp_path, capsys):
    prefix = str(tmp_path / "k")
    assert main(["packs", "keygen", "--out", prefix]) == 0
    pack_dir = tmp_path / "pack"
    shutil.copytree(EXAMPLE, pack_dir)
    assert main(["packs", "sign", str(pack_dir), "--key", prefix + ".key"]) == 0
    assert (pack_dir / "manifest.sig").exists()
    capsys.readouterr()
    assert main(["packs", "validate", str(pack_dir), "--trust", prefix + ".pub"]) == 0
    assert "verified against a trusted key" in capsys.readouterr().out
    assert main(["packs", "validate", str(pack_dir)]) == 0
    assert "pass --trust" in capsys.readouterr().out
    assert main(["packs", "sign", str(pack_dir), "--key", str(tmp_path / "missing.key")]) == 2
    assert "agentprobe: signing error:" in capsys.readouterr().err
