"""MiniDFIR schema.

Design rules this schema follows:

1. A fact is stored ONCE. host and case_id live in `evidence` only; every
   artifact reaches them through source_id. Two copies of the same fact can
   disagree, and then there is no right answer.

2. When one row can have MANY of something, that something gets its own table.
   An artifact has many timestamps  -> events
   An artifact matches many rules   -> detections

3. Derived-and-materialised columns are allowed where they buy something an
   index needs: `is_noise` (else 13 LIKE '%x%' scans per query) and
   `dedup_key` (else a UNIQUE index over a 1000-char description).

4. Query ergonomics come from VIEWS, not from duplicated columns. A view is
   inlined by SQLite, so `SELECT ... FROM v_artifacts WHERE case_id=?` is
   optimised exactly as if you had written the join by hand.
"""

# --------------------------------------------------------------------------
# tables
# --------------------------------------------------------------------------
EVIDENCE_TABLE = """
CREATE TABLE IF NOT EXISTS evidence (
    source_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL,
    host          TEXT NOT NULL,
    os            TEXT,
    tool          TEXT,
    tool_version  TEXT,              -- reproducibility: EZ Tools maps change output
    tool_cmdline  TEXT,              -- exactly what was run
    source_path   TEXT NOT NULL,
    sha256        TEXT,
    size_bytes    INTEGER,
    acquired_utc  TEXT,
    imported_utc  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    status        TEXT NOT NULL DEFAULT 'ok',   -- ok | partial | failed
    error         TEXT
);
"""

# 7 columns. case_id, host, os and tool all come from evidence via source_id.
ARTIFACTS_TABLE = """
CREATE TABLE IF NOT EXISTS artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     INTEGER NOT NULL REFERENCES evidence(source_id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL,
    description   TEXT,
    is_noise      INTEGER NOT NULL DEFAULT 0,
    dedup_key     TEXT NOT NULL,
    raw_data      TEXT
);
"""

# One row per timestamp. THIS is the timeline.
# is_primary marks the single timestamp that best represents the artifact,
# replacing artifacts.timestamp_utc + artifacts.primary_ts_type.
EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    ts_utc      TEXT NOT NULL,
    ts_type     TEXT NOT NULL,
    is_primary  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(artifact_id, ts_type)
);
"""

# No case_id: reachable through artifact_id. detections is a small table, so
# the extra join costs nothing.
DETECTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS detections (
    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id  INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    engine       TEXT NOT NULL,      -- internal | correlation | yara | sigma
    rule_id      TEXT NOT NULL,
    rule_title   TEXT,
    severity     TEXT,               -- info | low | medium | high | critical
    score        INTEGER NOT NULL DEFAULT 0,
    attack       TEXT,               -- JSON array of technique IDs
    matched_on   TEXT,               -- which field/value fired: explainability
    detected_utc TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""

# --------------------------------------------------------------------------
# indexes
# --------------------------------------------------------------------------
INDEXES = [
    # one evidence row per (case, host, path); makes register_evidence idempotent
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_unique ON evidence(case_id, host, source_path);",
    "CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id, host);",

    # dedup_key already encodes case_id and host, so one column is enough
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_dedup ON artifacts(dedup_key);",
    "CREATE INDEX IF NOT EXISTS idx_artifacts_source ON artifacts(source_id);",
    "CREATE INDEX IF NOT EXISTS idx_artifacts_type   ON artifacts(artifact_type);",
    "CREATE INDEX IF NOT EXISTS idx_artifacts_noise  ON artifacts(is_noise);",

    "CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts_utc);",
    "CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact_id);",
    # partial index: v_artifacts joins on is_primary=1, this makes it a lookup
    "CREATE INDEX IF NOT EXISTS idx_events_primary  ON events(artifact_id) WHERE is_primary = 1;",

    "CREATE UNIQUE INDEX IF NOT EXISTS idx_det_unique ON detections(artifact_id, rule_id, engine);",
    "CREATE INDEX IF NOT EXISTS idx_det_artifact ON detections(artifact_id);",
    "CREATE INDEX IF NOT EXISTS idx_det_severity ON detections(severity);",
]

# --------------------------------------------------------------------------
# views  -- query these, never the raw tables
# --------------------------------------------------------------------------

# Looks like the old wide artifacts table. LEFT JOIN on events so artifacts
# with NO parseable timestamp still appear (they just have timestamp_utc NULL)
# instead of vanishing from every query.
ARTIFACTS_VIEW = """
CREATE VIEW IF NOT EXISTS v_artifacts AS
SELECT a.id,
       a.source_id,
       a.artifact_type,
       a.description,
       a.is_noise,
       a.dedup_key,
       a.raw_data,
       v.case_id,
       v.host,
       v.os,
       v.tool          AS source,
       e.ts_utc        AS timestamp_utc,
       e.ts_type       AS primary_ts_type
FROM artifacts a
JOIN evidence v ON v.source_id = a.source_id
LEFT JOIN events e ON e.artifact_id = a.id AND e.is_primary = 1;
"""

# The timeline: one row per timestamp, not per artifact.
# The detections aggregate is a subquery computed once, not correlated per row.
TIMELINE_VIEW = """
CREATE VIEW IF NOT EXISTS v_timeline AS
SELECT e.ts_utc,
       e.ts_type,
       e.is_primary,
       a.id            AS artifact_id,
       a.artifact_type,
       a.description,
       a.is_noise,
       v.case_id,
       v.host,
       COALESCE(d.hits, 0)  AS hits,
       COALESCE(d.score, 0) AS score
FROM events e
JOIN artifacts a ON a.id = e.artifact_id
JOIN evidence v  ON v.source_id = a.source_id
LEFT JOIN (SELECT artifact_id, COUNT(*) AS hits, SUM(score) AS score
           FROM detections GROUP BY artifact_id) d ON d.artifact_id = a.id;
"""

# Findings with their evidence attached, for the report.
DETECTIONS_VIEW = """
CREATE VIEW IF NOT EXISTS v_detections AS
SELECT d.detection_id,
       d.artifact_id,
       d.engine,
       d.rule_id,
       d.rule_title,
       d.severity,
       d.score,
       d.attack,
       d.matched_on,
       d.detected_utc,
       a.artifact_type,
       a.description,
       v.case_id,
       v.host,
       (SELECT ts_utc FROM events WHERE artifact_id = a.id AND is_primary = 1) AS timestamp_utc
FROM detections d
JOIN artifacts a ON a.id = d.artifact_id
JOIN evidence v  ON v.source_id = a.source_id;
"""

VIEWS = [ARTIFACTS_VIEW, TIMELINE_VIEW, DETECTIONS_VIEW]

ALL_STATEMENTS = [EVIDENCE_TABLE, ARTIFACTS_TABLE, EVENTS_TABLE,
                  DETECTIONS_TABLE] + INDEXES + VIEWS
