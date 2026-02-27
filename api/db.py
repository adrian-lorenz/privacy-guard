from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from typing import Generator

import bcrypt

_DB_PATH = os.getenv("UI_DB_PATH", "ui.db")
_DEFAULT_ADMIN_PWD = os.getenv("UI_ADMIN_PASSWORD", "admin")


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user',
                created_at    TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL REFERENCES users(id),
                input_text      TEXT NOT NULL,
                anonymised_text TEXT NOT NULL,
                findings_json   TEXT NOT NULL DEFAULT '[]',
                pii_count       INTEGER NOT NULL DEFAULT 0,
                duration_ms     REAL,
                created_at      TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                key_hash     TEXT UNIQUE NOT NULL,
                key_prefix   TEXT NOT NULL,
                created_by   INTEGER REFERENCES users(id),
                created_at   TEXT DEFAULT (datetime('now')),
                last_used_at TEXT,
                is_active    INTEGER NOT NULL DEFAULT 1
            );
        """)
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            pw = bcrypt.hashpw(_DEFAULT_ADMIN_PWD.encode(), bcrypt.gensalt()).decode()
            con.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", pw, "admin"),
            )


def verify_login(username: str, password: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def save_scan(
    user_id: int,
    input_text: str,
    anonymised_text: str,
    findings_json: str,
    pii_count: int,
    duration_ms: float,
) -> None:
    with _conn() as con:
        con.execute(
            """INSERT INTO scans
               (user_id, input_text, anonymised_text, findings_json, pii_count, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                input_text,
                anonymised_text,
                findings_json,
                pii_count,
                duration_ms,
            ),
        )


def get_history(user_id: int | None = None, limit: int = 100) -> list[dict]:
    with _conn() as con:
        if user_id is not None:
            rows = con.execute(
                """SELECT s.id, u.username, s.input_text, s.anonymised_text,
                          s.findings_json, s.pii_count, s.duration_ms, s.created_at
                   FROM scans s JOIN users u ON s.user_id = u.id
                   WHERE s.user_id = ?
                   ORDER BY s.created_at DESC LIMIT ?""",
                (user_id, limit),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT s.id, u.username, s.input_text, s.anonymised_text,
                          s.findings_json, s.pii_count, s.duration_ms, s.created_at
                   FROM scans s JOIN users u ON s.user_id = u.id
                   ORDER BY s.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_pii_type_stats(user_id: int | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    with _conn() as con:
        if user_id is not None:
            rows = con.execute(
                "SELECT findings_json FROM scans WHERE user_id = ?", (user_id,)
            ).fetchall()
        else:
            rows = con.execute("SELECT findings_json FROM scans").fetchall()
    for row in rows:
        for f in json.loads(row["findings_json"]):
            t = f.get("pii_type", "UNKNOWN")
            counts[t] = counts.get(t, 0) + 1
    return counts


def get_daily_counts(days: int = 30, user_id: int | None = None) -> list[dict]:
    with _conn() as con:
        if user_id is not None:
            rows = con.execute(
                """SELECT date(created_at) AS day, COUNT(*) AS count
                   FROM scans
                   WHERE created_at >= datetime('now', ?) AND user_id = ?
                   GROUP BY day ORDER BY day""",
                (f"-{days} days", user_id),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT date(created_at) AS day, COUNT(*) AS count
                   FROM scans
                   WHERE created_at >= datetime('now', ?)
                   GROUP BY day ORDER BY day""",
                (f"-{days} days",),
            ).fetchall()
    return [dict(r) for r in rows]


def create_api_key(name: str, created_by: int) -> str:
    """Generate a new API key, persist its SHA-256 hash, return the full key (shown once)."""
    raw = "pg_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    key_prefix = raw[:12]  # "pg_" + 9 chars
    with _conn() as con:
        con.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES (?, ?, ?, ?)",
            (name, key_hash, key_prefix, created_by),
        )
    return raw


def list_api_keys() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            """SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used_at,
                      k.is_active, u.username AS created_by
               FROM api_keys k
               LEFT JOIN users u ON k.created_by = u.id
               ORDER BY k.created_at DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int) -> None:
    with _conn() as con:
        con.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))


def check_api_key(raw_key: str) -> bool:
    """Return True if the key is active; also updates last_used_at."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with _conn() as con:
        row = con.execute(
            "SELECT id FROM api_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,),
        ).fetchone()
        if row is None:
            return False
        con.execute(
            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
            (row["id"],),
        )
    return True


def get_totals(user_id: int | None = None) -> dict[str, int]:
    with _conn() as con:
        if user_id is not None:
            total_scans = con.execute(
                "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
            total_pii = con.execute(
                "SELECT COALESCE(SUM(pii_count), 0) FROM scans WHERE user_id = ?",
                (user_id,),
            ).fetchone()[0]
        else:
            total_scans = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_pii = con.execute(
                "SELECT COALESCE(SUM(pii_count), 0) FROM scans"
            ).fetchone()[0]
    return {"total_scans": int(total_scans), "total_pii": int(total_pii)}
