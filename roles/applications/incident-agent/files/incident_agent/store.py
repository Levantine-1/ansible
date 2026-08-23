"""Durable state: the work queue, the action history, and API spend.

SQLite rather than JSON files on disk. Three reasons, all of which bit the
obvious alternative: the listener and multiple workers write concurrently
(JSON read-modify-write races and silently loses actions); the flap guard and
storm detector are *queries* over recent history, not lookups; and asking what
actually happened over the last week is a reporting question, not a lookup.

Everything here is stdlib -- sqlite3 ships with Python.

`incidents_since()` / `actions_since()` are not called by the agent itself.
They are the query surface for retrospective reporting, kept here so that
tooling reads history through the same schema the agent writes it with. The
database is also perfectly readable with plain `sqlite3` at
/var/lib/incident-agent/incidents.db.
"""
import json
import os
import sqlite3
import time

from . import config

_DB_PATH = os.path.join(config.STATE_DIR, "incidents.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint       TEXT,
    ticket_id         INTEGER,
    ticket_number     TEXT,
    alertname         TEXT,
    instance          TEXT,
    host              TEXT,
    service           TEXT,
    severity          TEXT,
    summary           TEXT,
    alert_json        TEXT,
    received_at       REAL,
    not_before        REAL,
    state             TEXT DEFAULT 'queued',
    outcome           TEXT,
    detail            TEXT,
    claimed_at        REAL,
    finished_at       REAL,
    parent_ticket_id  INTEGER,
    escalated         INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state, not_before);
CREATE INDEX IF NOT EXISTS idx_incidents_recent ON incidents(received_at);
CREATE INDEX IF NOT EXISTS idx_incidents_ticket ON incidents(ticket_id);

CREATE TABLE IF NOT EXISTS actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER,
    ts           REAL,
    alertname    TEXT,
    host         TEXT,
    action       TEXT,
    target       TEXT,
    result       TEXT,
    detail       TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_flap ON actions(alertname, host, ts);

CREATE TABLE IF NOT EXISTS api_usage (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  REAL,
    kind                TEXT,
    incident_id         INTEGER,
    input_tokens        INTEGER DEFAULT 0,
    output_tokens       INTEGER DEFAULT 0,
    cache_write_tokens  INTEGER DEFAULT 0,
    cache_read_tokens   INTEGER DEFAULT 0,
    cost_usd            REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON api_usage(ts);
"""


def connect():
    os.makedirs(config.STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL so the listener can enqueue while a worker holds a read -- the
    # default rollback journal blocks writers behind readers, which with a
    # multi-minute triage in flight would reject incoming alerts.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def enqueue(alert, ticket_id, ticket_number, host, service, not_before):
    """Record a new incident. Returns (incident_id, created).

    Deduplicated on fingerprint against anything still open: Alertmanager
    re-notifies every `repeat_interval` (4h) for an alert that is still
    firing, and the relay correctly reuses one ticket for those -- so without
    this the agent would re-triage and potentially re-restart the same
    unresolved problem every four hours.
    """
    labels = alert.get("labels", {})
    conn = connect()
    try:
        fingerprint = alert.get("fingerprint", "")
        if fingerprint:
            row = conn.execute(
                "SELECT id FROM incidents WHERE fingerprint = ? AND state IN ('queued','running') LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row:
                return row["id"], False

        cur = conn.execute(
            """INSERT INTO incidents
               (fingerprint, ticket_id, ticket_number, alertname, instance, host, service,
                severity, summary, alert_json, received_at, not_before, state)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'queued')""",
            (
                fingerprint,
                ticket_id,
                ticket_number,
                labels.get("alertname", "UnknownAlert"),
                labels.get("instance", ""),
                host,
                service,
                labels.get("severity", ""),
                alert.get("annotations", {}).get("summary", ""),
                json.dumps(alert),
                time.time(),
                not_before,

            ),
        )
        conn.commit()
        return cur.lastrowid, True
    finally:
        conn.close()


def claim_next(limit_running):
    """Atomically take the next incident whose grace period has expired.

    The UPDATE...WHERE state='queued' is the lock: two workers racing for the
    same row means one of them updates zero rows and moves on. Doing this with
    a SELECT followed by an UPDATE would let both claim it and restart the same
    service twice.
    """
    conn = connect()
    try:
        running = conn.execute("SELECT COUNT(*) c FROM incidents WHERE state='running'").fetchone()["c"]
        if running >= limit_running:
            return None
        now = time.time()
        row = conn.execute(
            "SELECT * FROM incidents WHERE state='queued' AND not_before <= ? ORDER BY received_at LIMIT 1",
            (now,),
        ).fetchone()
        if not row:
            return None
        updated = conn.execute(
            "UPDATE incidents SET state='running', claimed_at=? WHERE id=? AND state='queued'",
            (now, row["id"]),
        ).rowcount
        conn.commit()
        if not updated:
            return None
        return dict(row)
    finally:
        conn.close()


def finish(incident_id, outcome, detail="", escalated=False, parent_ticket_id=None):
    conn = connect()
    try:
        conn.execute(
            """UPDATE incidents SET state='done', outcome=?, detail=?, finished_at=?,
               escalated=?, parent_ticket_id=? WHERE id=?""",
            (outcome, detail[:8000], time.time(), 1 if escalated else 0, parent_ticket_id, incident_id),
        )
        conn.commit()
    finally:
        conn.close()


def requeue_stale(older_than_seconds=3600):
    """Recover incidents abandoned by a crashed or restarted worker.

    Without this a kill -9 mid-triage leaves a row stuck in 'running' forever,
    which both loses that incident and permanently consumes one of the two
    concurrency slots.
    """
    conn = connect()
    try:
        cutoff = time.time() - older_than_seconds
        n = conn.execute(
            "UPDATE incidents SET state='queued', claimed_at=NULL WHERE state='running' AND claimed_at < ?",
            (cutoff,),
        ).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def record_action(incident_id, alertname, host, action, target, result, detail=""):
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO actions (incident_id, ts, alertname, host, action, target, result, detail) VALUES (?,?,?,?,?,?,?,?)",
            (incident_id, time.time(), alertname, host, action, target, result, detail[:4000]),
        )
        conn.commit()
    finally:
        conn.close()


def recent_action_count(alertname, host, window_seconds):
    """How many times this (alert, host) has already been auto-actioned.

    Counts attempts, not successes -- a restart that failed twice is at least
    as strong a signal that restarting is the wrong answer as one that
    "worked" and did not stick.
    """
    conn = connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) c FROM actions WHERE alertname=? AND host=? AND ts >= ?",
            (alertname, host, time.time() - window_seconds),
        ).fetchone()
        return row["c"]
    finally:
        conn.close()


def distinct_hosts_alerting(window_seconds):
    """Hosts with an incident raised inside the window -- the storm signal."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT DISTINCT host FROM incidents WHERE received_at >= ? AND host IS NOT NULL",
            (time.time() - window_seconds,),
        ).fetchall()
        return [r["host"] for r in rows]
    finally:
        conn.close()


def storm_peers(window_seconds, exclude_incident_id):
    conn = connect()
    try:
        rows = conn.execute(
            """SELECT id, ticket_id, ticket_number, alertname, host, summary, received_at
               FROM incidents WHERE received_at >= ? AND id != ? ORDER BY received_at""",
            (time.time() - window_seconds, exclude_incident_id),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def host_history(host, seconds, exclude_incident_id=None):
    """Everything this host has done recently, for the escalation bundle.

    Front-loaded rather than left for the escalation tier to discover: "has
    this happened before, and what was tried" is one of the first questions any
    investigation asks, and answering it from local SQLite costs nothing while
    making Claude rediscover it costs API turns.
    """
    conn = connect()
    try:
        incidents = conn.execute(
            """SELECT id, alertname, ticket_number, outcome, received_at, detail
               FROM incidents WHERE host=? AND received_at >= ? AND id != COALESCE(?, -1)
               ORDER BY received_at DESC LIMIT 20""",
            (host, time.time() - seconds, exclude_incident_id),
        ).fetchall()
        actions = conn.execute(
            """SELECT ts, alertname, action, target, result FROM actions
               WHERE host=? AND ts >= ? ORDER BY ts DESC LIMIT 20""",
            (host, time.time() - seconds),
        ).fetchall()
        return [dict(r) for r in incidents], [dict(r) for r in actions]
    finally:
        conn.close()


def recent_incidents_for_host(host, window_seconds, exclude_incident_id):
    """Other recent incidents on the same host -- candidates for linking.

    Regardless of state (open or already closed) -- deliberately, as of
    2026-08-24; see triage.py's _link_related() for why linking only open
    peers was missing the common case of one outage tripping several
    distinct Prometheus targets in quick succession."""
    conn = connect()
    try:
        rows = conn.execute(
            """SELECT id, ticket_id, ticket_number, alertname, host, summary
               FROM incidents WHERE host=? AND received_at >= ? AND id != ?""",
            (host, time.time() - window_seconds, exclude_incident_id),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def record_usage(kind, incident_id, usage, cost):
    conn = connect()
    try:
        conn.execute(
            """INSERT INTO api_usage (ts, kind, incident_id, input_tokens, output_tokens,
               cache_write_tokens, cache_read_tokens, cost_usd) VALUES (?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                kind,
                incident_id,
                usage.get("input_tokens", 0),
                usage.get("output_tokens", 0),
                usage.get("cache_creation_input_tokens", 0),
                usage.get("cache_read_input_tokens", 0),
                cost,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def month_spend():
    """Estimated spend in the current calendar month.

    Calendar month, matching how the Anthropic Console's own spend limit
    resets -- a rolling 30-day window here would drift out of step with the
    hard cap and could refuse to work while real budget remained.
    """
    now = time.localtime()
    start = time.mktime((now.tm_year, now.tm_mon, 1, 0, 0, 0, 0, 0, -1))
    conn = connect()
    try:
        row = conn.execute("SELECT COALESCE(SUM(cost_usd), 0) s FROM api_usage WHERE ts >= ?", (start,)).fetchone()
        return row["s"]
    finally:
        conn.close()


def incidents_since(seconds):
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE received_at >= ? ORDER BY received_at",
            (time.time() - seconds,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def actions_since(seconds):
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM actions WHERE ts >= ? ORDER BY ts", (time.time() - seconds,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
