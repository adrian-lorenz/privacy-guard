from __future__ import annotations

import json
import os
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
            (user_id, input_text, anonymised_text, findings_json, pii_count, duration_ms),
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


def get_totals(user_id: int | None = None) -> dict[str, int]:
    with _conn() as con:
        if user_id is not None:
            total_scans = con.execute(
                "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
            total_pii = con.execute(
                "SELECT COALESCE(SUM(pii_count), 0) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
        else:
            total_scans = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_pii = con.execute(
                "SELECT COALESCE(SUM(pii_count), 0) FROM scans"
            ).fetchone()[0]
    return {"total_scans": int(total_scans), "total_pii": int(total_pii)}
