"""Database access layer.

Everything outside this module should read from the VIEWS (v_artifacts,
v_timeline, v_detections) and write through the functions here.
"""
import json
import logging
import sqlite3
from contextlib import contextmanager

from config import DATABASE_PATH
from database.schema import ALL_STATEMENTS

log = logging.getLogger(__name__)


def get_connection(path=None):
    conn = sqlite3.connect(str(path or DATABASE_PATH))
    # foreign_keys is OFF by default and must be set PER CONNECTION.
    # Without it, ON DELETE CASCADE silently does nothing and clear_source()
    # leaves orphaned events and detections behind.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def connection(path=None):
    """Commit on success, roll back on exception, always close."""
    conn = get_connection(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path=None):
    with connection(path) as conn:
        for stmt in ALL_STATEMENTS:
            conn.execute(stmt)
    log.info("database initialised at %s", path or DATABASE_PATH)


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------
def register_evidence(case_id, host, tool, source_path, sha256=None,
                      acquired_utc=None, tool_version=None, tool_cmdline=None,
                      size_bytes=None, os_name=None, status="ok", error=None,
                      conn=None):
    """Record an acquisition, return its source_id. Idempotent.

    Re-registering the same (case, host, path) UPDATES rather than duplicating,
    so re-running a stage refreshes hashes and status.

    This row is now load-bearing: case_id and host live ONLY here, so a wrong
    value mislabels every artifact derived from this source.
    """
    if not case_id or not host:
        raise ValueError("case_id and host are required "
                         "(they are the only copy of these facts)")

    own = conn is None
    conn = conn or get_connection()
    try:
        conn.execute(
            """INSERT INTO evidence
                 (case_id, host, os, tool, tool_version, tool_cmdline,
                  source_path, sha256, size_bytes, acquired_utc, status, error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(case_id, host, source_path) DO UPDATE SET
                 os           = COALESCE(excluded.os,           evidence.os),
                 tool         = COALESCE(excluded.tool,         evidence.tool),
                 tool_version = COALESCE(excluded.tool_version, evidence.tool_version),
                 tool_cmdline = COALESCE(excluded.tool_cmdline, evidence.tool_cmdline),
                 sha256       = COALESCE(excluded.sha256,       evidence.sha256),
                 size_bytes   = COALESCE(excluded.size_bytes,   evidence.size_bytes),
                 acquired_utc = COALESCE(excluded.acquired_utc, evidence.acquired_utc),
                 status       = excluded.status,
                 error        = excluded.error""",
            (case_id, host, os_name, tool, tool_version, tool_cmdline,
             str(source_path), sha256, size_bytes, acquired_utc, status, error))
        row = conn.execute(
            "SELECT source_id FROM evidence "
            "WHERE case_id=? AND host=? AND source_path=?",
            (case_id, host, str(source_path))).fetchone()
        if own:
            conn.commit()
        return row[0]
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# artifacts + events
# --------------------------------------------------------------------------
def clear_source(source_id, conn=None):
    """Delete everything derived from one acquisition.

    This is what makes ingest idempotent. INSERT OR IGNORE alone would keep the
    OLD row forever after you fix a spec bug, because the old row already owns
    the dedup key. Delete first, then re-insert.

    Requires PRAGMA foreign_keys=ON so events and detections cascade.
    """
    own = conn is None
    conn = conn or get_connection()
    try:
        n = conn.execute("DELETE FROM artifacts WHERE source_id = ?",
                         (source_id,)).rowcount
        if own:
            conn.commit()
        return n
    finally:
        if own:
            conn.close()


_INSERT_ARTIFACT = (
    "INSERT OR IGNORE INTO artifacts "
    "(source_id, artifact_type, description, is_noise, dedup_key, raw_data) "
    "VALUES (?,?,?,?,?,?)"
)

_INSERT_EVENT = (
    "INSERT OR IGNORE INTO events (artifact_id, ts_utc, ts_type, is_primary) "
    "VALUES (?,?,?,?)"
)


def insert_artifacts(records, conn=None):
    """Insert artifacts and their events. Returns (artifacts, events) inserted.

    Expected record shape (produced by normalizer.build_record):
        {"source_id": int,
         "artifact_type": str,
         "description": str,
         "is_noise": 0|1,
         "dedup_key": str,
         "raw_data": dict,
         "events": [(ts_type, ts_utc, is_primary), ...]}

    Rows go in one at a time because we need each artifact's rowid to attach
    its events; executemany() cannot give us those. In one transaction with WAL
    this still runs at roughly 100k rows/sec.

    IMPORTANT: after INSERT OR IGNORE, cursor.lastrowid is STALE when the row
    was ignored -- it still holds the previous successful insert's id. We check
    rowcount == 1 before trusting it, otherwise a duplicate's events would be
    attached to the wrong artifact.
    """
    own = conn is None
    conn = conn or get_connection()
    n_art = n_evt = 0
    try:
        cur = conn.cursor()
        for r in records:
            cur.execute(_INSERT_ARTIFACT, (
                r["source_id"], r["artifact_type"], r.get("description", ""),
                int(r.get("is_noise", 0)), r["dedup_key"],
                json.dumps(r.get("raw_data", {}), default=str),
            ))
            if cur.rowcount != 1:
                continue                       # duplicate: already stored
            artifact_id = cur.lastrowid
            n_art += 1
            for ts_type, ts_utc, is_primary in r.get("events", []):
                if not ts_utc:
                    continue
                cur.execute(_INSERT_EVENT,
                            (artifact_id, ts_utc, ts_type, int(is_primary)))
                n_evt += cur.rowcount
        if own:
            conn.commit()
        return n_art, n_evt
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# detections
# --------------------------------------------------------------------------
def insert_detections(rows, conn=None):
    """rows: [{"artifact_id", "engine", "rule_id", "rule_title", "severity",
               "score", "attack": [...], "matched_on"}, ...]"""
    own = conn is None
    conn = conn or get_connection()
    try:
        before = conn.total_changes
        conn.executemany(
            """INSERT OR IGNORE INTO detections
                 (artifact_id, engine, rule_id, rule_title,
                  severity, score, attack, matched_on)
               VALUES (?,?,?,?,?,?,?,?)""",
            [(d["artifact_id"], d["engine"], d["rule_id"], d.get("rule_title"),
              d.get("severity"), int(d.get("score", 0)),
              json.dumps(d.get("attack", [])), d.get("matched_on"))
             for d in rows])
        n = conn.total_changes - before
        if own:
            conn.commit()
        return n
    finally:
        if own:
            conn.close()


def clear_detections(case_id, engine=None, conn=None):
    """Detections no longer carry case_id, so scope through artifacts+evidence.

    This is the operation you run fifty times an afternoon while tuning rules,
    and it never touches the artifacts table. Evidence is written once.
    """
    own = conn is None
    conn = conn or get_connection()
    try:
        sql = """DELETE FROM detections WHERE detection_id IN (
                   SELECT d.detection_id FROM detections d
                   JOIN artifacts a ON a.id = d.artifact_id
                   JOIN evidence  v ON v.source_id = a.source_id
                   WHERE v.case_id = ?"""
        params = [case_id]
        if engine:
            sql += " AND d.engine = ?"
            params.append(engine)
        sql += ")"
        n = conn.execute(sql, params).rowcount
        if own:
            conn.commit()
        return n
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# health check -- run after every ingest
# --------------------------------------------------------------------------
def stats(case_id):
    with connection() as conn:
        one = lambda s, p=(): conn.execute(s, p).fetchone()
        return {
            "evidence": one("SELECT COUNT(*) FROM evidence WHERE case_id=?",
                            (case_id,))[0],
            "hosts": [r[0] for r in conn.execute(
                "SELECT DISTINCT host FROM evidence WHERE case_id=? ORDER BY 1",
                (case_id,))],
            "artifacts": one("SELECT COUNT(*) FROM v_artifacts WHERE case_id=?",
                             (case_id,))[0],
            "events": one("SELECT COUNT(*) FROM v_timeline WHERE case_id=?",
                          (case_id,))[0],
            # artifacts with no parseable timestamp: they exist but never reach
            # the timeline. A large number here means GENERIC_TS is incomplete.
            "no_timestamp": one("SELECT COUNT(*) FROM v_artifacts "
                                "WHERE case_id=? AND timestamp_utc IS NULL",
                                (case_id,))[0],
            "noise": one("SELECT COUNT(*) FROM v_artifacts "
                         "WHERE case_id=? AND is_noise=1", (case_id,))[0],
            "detections": one("SELECT COUNT(*) FROM v_detections WHERE case_id=?",
                              (case_id,))[0],
            "by_type": conn.execute(
                "SELECT artifact_type, COUNT(*) c FROM v_artifacts "
                "WHERE case_id=? GROUP BY 1 ORDER BY c DESC", (case_id,)).fetchall(),
            "range": one("SELECT MIN(ts_utc), MAX(ts_utc) FROM v_timeline "
                         "WHERE case_id=?", (case_id,)),
        }
