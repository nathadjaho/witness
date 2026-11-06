"""Append-only, hash-chained event ledger. Any edit to a past event breaks the chain."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

import config

_lock = threading.Lock()
GENESIS = "0" * 64


def _conn() -> sqlite3.Connection:
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


_db = None


def db() -> sqlite3.Connection:
    global _db
    if _db is None:
        _db = _conn()
        _db.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, seq INTEGER, t REAL,
          kind TEXT, data TEXT, prev_hash TEXT, hash TEXT);
        CREATE INDEX IF NOT EXISTS ev_run ON events(run_id, seq);
        CREATE TABLE IF NOT EXISTS runs(
          id TEXT PRIMARY KEY, created REAL, status TEXT, request TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS actions(
          id TEXT PRIMARY KEY, run_id TEXT, created REAL, kind TEXT, payload TEXT,
          status TEXT, decided REAL, reason TEXT);
        CREATE TABLE IF NOT EXISTS crm(
          id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, company TEXT, domain TEXT,
          score INTEGER, owner TEXT, notes TEXT, evidence TEXT, run_id TEXT);
        """)
    return _db


def _digest(prev: str, run_id: str, seq: int, t: float, kind: str, data: str) -> str:
    return hashlib.sha256(f"{prev}|{run_id}|{seq}|{t:.3f}|{kind}|{data}".encode()).hexdigest()


def append(run_id: str, kind: str, data: dict) -> dict:
    with _lock:
        c = db()
        row = c.execute("SELECT seq, hash FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1",
                        (run_id,)).fetchone()
        seq = (row["seq"] + 1) if row else 0
        prev = row["hash"] if row else GENESIS
        t = round(time.time(), 3)
        payload = json.dumps(data, sort_keys=True, default=str)
        h = _digest(prev, run_id, seq, t, kind, payload)
        c.execute("INSERT INTO events(run_id,seq,t,kind,data,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                  (run_id, seq, t, kind, payload, prev, h))
        c.commit()
    return {"seq": seq, "t": t, "kind": kind, "data": data, "hash": h, "prev_hash": prev}


def events(run_id: str, after: int = -1) -> list[dict]:
    rows = db().execute("SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq", (run_id, after)).fetchall()
    return [{"seq": r["seq"], "t": r["t"], "kind": r["kind"], "data": json.loads(r["data"]),
             "hash": r["hash"], "prev_hash": r["prev_hash"]} for r in rows]


def verify(run_id: str) -> dict:
    rows = db().execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
    prev = GENESIS
    for r in rows:
        if r["prev_hash"] != prev or _digest(prev, run_id, r["seq"], r["t"], r["kind"], r["data"]) != r["hash"]:
            return {"ok": False, "broken_at": r["seq"], "events": len(rows)}
        prev = r["hash"]
    return {"ok": True, "events": len(rows), "head": prev}
