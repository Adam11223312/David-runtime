import json
import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, Any

AUDIT_FILE = "data/audit.jsonl"
HEAD_FILE = "data/audit.head"


def _ensure_data_dir():
    os.makedirs("data", exist_ok=True)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_previous_hash() -> str:
    if not os.path.exists(HEAD_FILE):
        return "GENESIS"
    with open(HEAD_FILE, "r") as f:
        return f.read().strip()


def _set_head_hash(event_hash: str):
    with open(HEAD_FILE, "w") as f:
        f.write(event_hash)


def append_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Appends a tamper-evident audit event.
    Each event contains:
      - prev_hash
      - event_hash (sha256 of prev_hash + canonicalized event)
    """
    _ensure_data_dir()

    timestamp = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_previous_hash()

    event_record = {
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "event": event,
    }

    canonical = json.dumps(event_record, sort_keys=True)
    event_hash = _sha256(prev_hash + canonical)

    full_record = {
        **event_record,
        "event_hash": event_hash,
    }

    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(full_record) + "\n")

    _set_head_hash(event_hash)

    return full_record
