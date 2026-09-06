"""Durable, resumable scan checkpoints.

Provider calls are slow, rate-limited, and sometimes interrupted by a process
restart.  A production scan must not lose every completed finding because the
last request failed or the terminal closed.  This module stores one completed
attack result at a time in a versioned, atomically replaced JSON document.

The checkpoint is deliberately bound to the selected target, judge, and
filtered attack-library digest.  Resuming a checkpoint with a different scan
definition is refused rather than silently combining incomparable evidence.
Checkpoint files may contain model responses, so they are created with a
private file mode and should be kept in a local, access-controlled directory.
"""

from __future__ import annotations

from copy import deepcopy
import datetime as _datetime
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from agentprobe.reporting import attack_library_digest


CHECKPOINT_SCHEMA_VERSION = "1.0"


class CheckpointError(ValueError):
    """Raised when a checkpoint is unsafe or incompatible with a scan."""


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(
        microsecond=0
    ).isoformat()


def attack_id(category: str, attack: Mapping[str, Any], position: int) -> str:
    """Return the stable evidence key used by a scan checkpoint."""

    index = attack.get("_library_index", position)
    if isinstance(index, bool) or not isinstance(index, int) or index < 1:
        raise CheckpointError(
            f"attack {category!r} has an invalid library index: {index!r}"
        )
    if not isinstance(category, str) or not category.strip():
        raise CheckpointError("attack category must be a non-empty string")
    return f"{category}:{index}"


def _serialize_row(category: str, row: Sequence[Any], position: int) -> Dict[str, Any]:
    if not isinstance(row, (tuple, list)) or len(row) != 6:
        raise CheckpointError("scan result rows must contain exactly six fields")
    attack, response, verdict, finding_severity, reason, method = row
    if not isinstance(attack, Mapping):
        raise CheckpointError("scan result attack must be a mapping")
    key = attack_id(category, attack, position)
    record = {
        "attack_id": key,
        "category": category,
        "attack": dict(attack),
        "response": response,
        "verdict": verdict,
        "finding_severity": finding_severity,
        "reason": reason,
        "method": method,
    }
    try:
        json.dumps(record, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CheckpointError(f"scan result is not JSON-serializable: {exc}") from exc
    return record


def _deserialize_row(record: Mapping[str, Any]) -> Tuple[dict, Any, Any, Any, Any, Any]:
    required = {
        "attack_id", "category", "attack", "response", "verdict",
        "finding_severity", "reason", "method",
    }
    if not isinstance(record, Mapping) or not required.issubset(record):
        raise CheckpointError("checkpoint contains an incomplete result record")
    if not isinstance(record["attack"], Mapping):
        raise CheckpointError("checkpoint result attack must be a mapping")
    return (
        dict(record["attack"]),
        record["response"],
        record["verdict"],
        record["finding_severity"],
        record["reason"],
        record["method"],
    )


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".agentprobe-checkpoint-", suffix=".json", dir=str(path.parent)
    )
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        # Persist the directory entry as well as the file contents when the
        # host filesystem supports directory handles.  This closes the small
        # power-loss window between replace() and directory metadata flush.
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Windows and some virtual filesystems do not permit directory
            # fsync; atomic replace and file fsync still provide the contract.
            pass
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


class ScanCheckpoint:
    """Create or resume an atomically persisted scan checkpoint."""

    def __init__(
        self,
        path: str,
        *,
        target_model: str,
        judge_model: str,
        attack_library: Mapping[str, Sequence[Mapping[str, Any]]],
        run_metadata: Optional[Mapping[str, Any]] = None,
        resume: bool = False,
    ) -> None:
        if not isinstance(path, str) or not path.strip():
            raise CheckpointError("checkpoint path must be a non-empty string")
        if not isinstance(target_model, str) or not target_model.strip():
            raise CheckpointError("target model must be a non-empty string")
        if not isinstance(judge_model, str) or not judge_model.strip():
            raise CheckpointError("judge model must be a non-empty string")

        self.path = Path(path)
        self.target_model = target_model
        self.judge_model = judge_model
        self.attack_digest = attack_library_digest(attack_library)
        self._attack_ids = self._validate_attack_ids(attack_library)
        self._expected_run_metadata = deepcopy(dict(run_metadata or {}))

        if resume:
            self.state = self._load()
            self._validate_compatibility()
        else:
            if self.path.exists():
                raise CheckpointError(
                    f"checkpoint already exists: {self.path}; use --resume or choose a new path"
                )
            self.state = {
                "schema_version": CHECKPOINT_SCHEMA_VERSION,
                "tool": "agentprobe",
                "status": "in_progress",
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
                "target_model": target_model,
                "judge_model": judge_model,
                "attack_library_sha256": self.attack_digest,
                "attack_ids": sorted(self._attack_ids),
                "run": deepcopy(dict(run_metadata or {})),
                "results": [],
            }
            _write_atomic(self.path, self.state)

        self._records = {}
        for record in self.state.get("results", []):
            if not isinstance(record, Mapping):
                raise CheckpointError("checkpoint results must be objects")
            key = record.get("attack_id")
            if not isinstance(key, str) or key in self._records:
                raise CheckpointError("checkpoint contains duplicate or invalid attack IDs")
            if key not in self._attack_ids:
                raise CheckpointError(f"checkpoint contains an unknown attack ID: {key}")
            self._records[key] = dict(record)

    @staticmethod
    def _validate_attack_ids(
        attack_library: Mapping[str, Sequence[Mapping[str, Any]]]
    ) -> frozenset[str]:
        if not isinstance(attack_library, Mapping) or not attack_library:
            raise CheckpointError("attack library must be a non-empty mapping")
        keys = []
        for category, attacks in attack_library.items():
            if not isinstance(attacks, Sequence) or isinstance(attacks, (str, bytes)):
                raise CheckpointError(f"attacks for {category!r} must be a sequence")
            for position, attack in enumerate(attacks, start=1):
                if not isinstance(attack, Mapping):
                    raise CheckpointError(f"attack {category}:{position} must be a mapping")
                keys.append(attack_id(category, attack, position))
        if len(keys) != len(set(keys)):
            raise CheckpointError("attack library contains duplicate evidence IDs")
        return frozenset(keys)

    def _load(self) -> Dict[str, Any]:
        try:
            with self.path.open(encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError as exc:
            raise CheckpointError(f"checkpoint not found: {self.path}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckpointError(f"cannot read checkpoint {self.path}: {exc}") from exc
        if not isinstance(state, dict):
            raise CheckpointError("checkpoint root must be a JSON object")
        return state

    def _validate_compatibility(self) -> None:
        if self.state.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            raise CheckpointError("checkpoint schema version is unsupported")
        if self.state.get("tool") != "agentprobe":
            raise CheckpointError("checkpoint was not produced by AgentProbe")
        if self.state.get("target_model") != self.target_model:
            raise CheckpointError("checkpoint target model does not match this scan")
        if self.state.get("judge_model") != self.judge_model:
            raise CheckpointError("checkpoint judge model does not match this scan")
        if self.state.get("attack_library_sha256") != self.attack_digest:
            raise CheckpointError("checkpoint attack library does not match this scan")
        expected_run = self._expected_run_metadata
        stored_run = self.state.get("run", {})
        if expected_run:
            if not isinstance(stored_run, Mapping):
                raise CheckpointError("checkpoint run metadata is invalid")
            for key, value in expected_run.items():
                # A new invocation naturally generates a new run ID.  Every
                # other supplied provenance field must match exactly.
                if key == "run_id":
                    continue
                if stored_run.get(key) != value:
                    raise CheckpointError(
                        f"checkpoint run metadata does not match for {key!r}"
                    )
        if self.state.get("status") not in {"in_progress", "complete"}:
            raise CheckpointError("checkpoint status is unsupported")
        if not isinstance(self.state.get("results"), list):
            raise CheckpointError("checkpoint results must be a list")

    def has(self, key: str) -> bool:
        return key in self._records

    def row(self, key: str) -> Tuple[dict, Any, Any, Any, Any, Any]:
        if key not in self._records:
            raise CheckpointError(f"no checkpointed result for {key}")
        return _deserialize_row(self._records[key])

    @property
    def run_metadata(self) -> Mapping[str, Any]:
        value = self.state.get("run", {})
        return value if isinstance(value, Mapping) else {}

    def record(self, category: str, row: Sequence[Any], position: int) -> None:
        record = _serialize_row(category, row, position)
        key = record["attack_id"]
        if key not in self._attack_ids:
            raise CheckpointError(f"result key is not part of this scan: {key}")
        if key in self._records:
            raise CheckpointError(f"result already checkpointed: {key}")
        self._records[key] = record
        self.state["results"] = list(self._records.values())
        self.state["updated_at"] = _utc_now()
        _write_atomic(self.path, self.state)

    def finalize(self) -> None:
        if set(self._records) != self._attack_ids:
            missing = sorted(self._attack_ids - set(self._records))
            raise CheckpointError(
                f"cannot finalize incomplete scan; missing {len(missing)} attack(s)"
            )
        self.state["status"] = "complete"
        self.state["updated_at"] = _utc_now()
        _write_atomic(self.path, self.state)
