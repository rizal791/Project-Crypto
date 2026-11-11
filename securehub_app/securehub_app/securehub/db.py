from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "securehub.db"


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db_session():
    con = connect()
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db() -> None:
    with db_session() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                public_key BLOB NOT NULL,
                private_key_nonce BLOB NOT NULL,
                private_key_enc BLOB NOT NULL,
                face_nonce BLOB,
                face_enc BLOB,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                created_at TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                wrapped_sender BLOB NOT NULL,
                wrapped_recipient BLOB NOT NULL,
                FOREIGN KEY(sender) REFERENCES users(username),
                FOREIGN KEY(recipient) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                filename TEXT NOT NULL,
                media_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                wrapped_sender BLOB NOT NULL,
                wrapped_recipient BLOB NOT NULL,
                FOREIGN KEY(sender) REFERENCES users(username),
                FOREIGN KEY(recipient) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS secure_notes (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                created_at TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                wrapped_key BLOB NOT NULL,
                FOREIGN KEY(owner) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                block_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );
            """
        )


def user_count() -> int:
    with db_session() as con:
        return int(con.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def get_user(username: str) -> dict[str, Any] | None:
    with db_session() as con:
        row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def list_users() -> list[str]:
    with db_session() as con:
        rows = con.execute("SELECT username FROM users ORDER BY username COLLATE NOCASE").fetchall()
        return [r[0] for r in rows]


def insert_user(record: dict[str, Any]) -> None:
    with db_session() as con:
        con.execute(
            """INSERT INTO users
            (username, password_salt, password_hash, key_salt, public_key,
             private_key_nonce, private_key_enc, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["username"], record["password_salt"], record["password_hash"],
                record["key_salt"], record["public_key"], record["private_key_nonce"],
                record["private_key_enc"], record.get("role", "user"), record["created_at"],
            ),
        )


def save_face_model(username: str, nonce: bytes, encrypted_model: bytes) -> None:
    with db_session() as con:
        con.execute(
            "UPDATE users SET face_nonce = ?, face_enc = ? WHERE username = ?",
            (nonce, encrypted_model, username),
        )


def get_setting(key: str) -> str | None:
    with db_session() as con:
        row = con.execute("SELECT setting_value FROM settings WHERE setting_key = ?", (key,)).fetchone()
        return row[0] if row else None


def set_setting(key: str, value: str) -> None:
    with db_session() as con:
        con.execute(
            "INSERT INTO settings(setting_key, setting_value) VALUES(?, ?) "
            "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value",
            (key, value),
        )


def insert_message(record: dict[str, Any]) -> None:
    with db_session() as con:
        con.execute(
            """INSERT INTO messages
            (id, sender, recipient, created_at, nonce, ciphertext, wrapped_sender, wrapped_recipient)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            tuple(record[k] for k in (
                "id", "sender", "recipient", "created_at", "nonce", "ciphertext",
                "wrapped_sender", "wrapped_recipient"
            )),
        )


def get_messages(username: str, box: str = "inbox") -> list[dict[str, Any]]:
    with db_session() as con:
        if box == "sent":
            rows = con.execute(
                "SELECT * FROM messages WHERE sender = ? ORDER BY created_at DESC", (username,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM messages WHERE recipient = ? ORDER BY created_at DESC", (username,)
            ).fetchall()
        return [dict(r) for r in rows]


def insert_file(record: dict[str, Any]) -> None:
    with db_session() as con:
        con.execute(
            """INSERT INTO files
            (id, sender, recipient, filename, media_type, created_at, nonce,
             ciphertext, wrapped_sender, wrapped_recipient)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            tuple(record[k] for k in (
                "id", "sender", "recipient", "filename", "media_type", "created_at",
                "nonce", "ciphertext", "wrapped_sender", "wrapped_recipient"
            )),
        )


def get_files(username: str, box: str = "inbox") -> list[dict[str, Any]]:
    with db_session() as con:
        column = "sender" if box == "sent" else "recipient"
        rows = con.execute(
            f"SELECT * FROM files WHERE {column} = ? ORDER BY created_at DESC", (username,)
        ).fetchall()
        return [dict(r) for r in rows]


def insert_note(record: dict[str, Any]) -> None:
    with db_session() as con:
        con.execute(
            """INSERT INTO secure_notes
            (id, owner, created_at, nonce, ciphertext, wrapped_key)
            VALUES (?, ?, ?, ?, ?, ?)""",
            tuple(record[k] for k in ("id", "owner", "created_at", "nonce", "ciphertext", "wrapped_key")),
        )


def get_notes(owner: str) -> list[dict[str, Any]]:
    with db_session() as con:
        rows = con.execute(
            "SELECT * FROM secure_notes WHERE owner = ? ORDER BY created_at DESC", (owner,)
        ).fetchall()
        return [dict(r) for r in rows]


def insert_asset(asset_id: str, owner: str, name: str, description: str, created_at: str) -> None:
    with db_session() as con:
        con.execute(
            "INSERT INTO assets(id, owner, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
            (asset_id, owner, name, description, created_at),
        )


def get_assets(owner: str | None = None) -> list[dict[str, Any]]:
    with db_session() as con:
        if owner:
            rows = con.execute("SELECT * FROM assets WHERE owner = ? ORDER BY created_at DESC", (owner,)).fetchall()
        else:
            rows = con.execute("SELECT * FROM assets ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def transfer_asset(asset_id: str, new_owner: str) -> None:
    with db_session() as con:
        con.execute("UPDATE assets SET owner = ? WHERE id = ?", (new_owner, asset_id))


def append_block(timestamp: str, payload_json: str, previous_hash: str, nonce: int, block_hash: str) -> None:
    with db_session() as con:
        next_index = int(con.execute("SELECT COALESCE(MAX(block_index), -1) + 1 FROM blocks").fetchone()[0])
        con.execute(
            "INSERT INTO blocks(block_index, timestamp, payload_json, previous_hash, nonce, block_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (next_index, timestamp, payload_json, previous_hash, nonce, block_hash),
        )


def get_blocks() -> list[dict[str, Any]]:
    with db_session() as con:
        rows = con.execute("SELECT * FROM blocks ORDER BY block_index ASC").fetchall()
        return [dict(r) for r in rows]
