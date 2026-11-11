from __future__ import annotations

import hashlib
import json
from typing import Any

from . import db

DIFFICULTY = 3
GENESIS_PREVIOUS_HASH = "0" * 64


def _calculate_hash(index: int, timestamp: str, payload_json: str, previous_hash: str, nonce: int) -> str:
    material = f"{index}|{timestamp}|{payload_json}|{previous_hash}|{nonce}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def add_ledger_record(payload: dict[str, Any], timestamp: str) -> dict[str, Any]:
    blocks = db.get_blocks()
    index = len(blocks)
    previous_hash = blocks[-1]["block_hash"] if blocks else GENESIS_PREVIOUS_HASH
    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    nonce = 0
    prefix = "0" * DIFFICULTY
    while True:
        block_hash = _calculate_hash(index, timestamp, payload_json, previous_hash, nonce)
        if block_hash.startswith(prefix):
            break
        nonce += 1
    db.append_block(timestamp, payload_json, previous_hash, nonce, block_hash)
    return {"block_index": index, "timestamp": timestamp, "payload_json": payload_json,
            "previous_hash": previous_hash, "nonce": nonce, "block_hash": block_hash}


def verify_chain() -> tuple[bool, str]:
    blocks = db.get_blocks()
    previous_hash = GENESIS_PREVIOUS_HASH
    prefix = "0" * DIFFICULTY
    for expected_index, block in enumerate(blocks):
        if block["block_index"] != expected_index:
            return False, f"Nomor blok tidak berurutan pada blok {expected_index}."
        if block["previous_hash"] != previous_hash:
            return False, f"Previous hash tidak cocok pada blok {expected_index}."
        calculated = _calculate_hash(
            block["block_index"], block["timestamp"], block["payload_json"],
            block["previous_hash"], block["nonce"]
        )
        if calculated != block["block_hash"]:
            return False, f"Hash blok {expected_index} tidak valid. Data mungkin telah diubah."
        if not calculated.startswith(prefix):
            return False, f"Proof-of-work blok {expected_index} tidak memenuhi tingkat kesulitan."
        previous_hash = calculated
    return True, f"Blockchain valid. {len(blocks)} blok telah diverifikasi."
