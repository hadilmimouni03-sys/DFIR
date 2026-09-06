import logging
from datetime import datetime, timezone
from pathlib import Path

from config import MAX_YARA_FILE_MB, YARA_RULES_DIR
from database.database import (clear_detections, connection, insert_artifacts,
                               insert_detections, register_evidence)
from normalization.normalizer import build_record

log = logging.getLogger(__name__)

MEMORY_ONLY_SUFFIX = ("_memory", "memory")

SEVERITIES = ("info", "low", "medium", "high", "critical")
DEFAULT_SCORE = {"info": 5, "low": 10, "medium": 25, "high": 40, "critical": 70}


def _rule_files(rules_dir, for_memory=False):
    """Which .yar files belong to this surface."""
    out = []
    for p in sorted(Path(rules_dir).rglob("*.yar")) + \
             sorted(Path(rules_dir).rglob("*.yara")):
        is_memory = any(m in p.name.lower() for m in MEMORY_ONLY_SUFFIX)
        if is_memory == for_memory:
            out.append(p)
    return out


def compile_rules(rules_dir=None, for_memory=False):

    try:
        import yara
    except ImportError:
        log.warning("yara-python not installed; skipping the file YARA scan "
                    "(pip install yara-python)")
        return None, {}

    rules_dir = Path(rules_dir or YARA_RULES_DIR)
    paths = _rule_files(rules_dir, for_memory=for_memory)
    if not paths:
        available = sorted(p.name for p in Path(rules_dir).rglob("*.yar"))
        log.error("NO %s RULESETS in %s -- the file scan will match nothing. "
                  "Present but not applicable to this surface: %s. "
                  "Add a file ruleset, or run `main.py rules` to import one.",
                  "MEMORY" if for_memory else "FILE", rules_dir,
                  available or "(none at all)")
        return None, {}

    filepaths = {p.stem: str(p) for p in paths}
    try:
        compiled = yara.compile(filepaths=filepaths)
    except Exception as e:
  
        log.error("YARA compilation FAILED, no file scanning will happen: %s",
                  str(e)[:300])
        log.error("check each ruleset: python main.py rules --validate")
        return None, {}

    log.info("compiled %d ruleset(s): %s", len(filepaths),
             ", ".join(sorted(filepaths)))
    return compiled, filepaths


def _meta(match):

    meta = getattr(match, "meta", {}) or {}

    severity = str(meta.get("severity", "high")).lower()
    if severity not in SEVERITIES:
        severity = "high"

    try:
        score = int(meta.get("score", DEFAULT_SCORE[severity]))
    except (TypeError, ValueError):
        score = DEFAULT_SCORE[severity]

    attack = [t.strip().upper()
              for t in str(meta.get("attack", "")).replace(";", ",").split(",")
              if t.strip()]

    return severity, score, attack, meta


def scan_directory(case_id, host, raw_dir, rules_dir=None, reset=True,
                   max_file_mb=None):

    compiled, rulesets = compile_rules(rules_dir, for_memory=False)
    if compiled is None:
        return {"scanned": 0, "hits": 0, "skipped": 0}

    raw_dir = Path(raw_dir)
    if not raw_dir.exists():
        log.warning("yara: %s does not exist", raw_dir)
        return {"scanned": 0, "hits": 0, "skipped": 0}

    source_id = register_evidence(case_id, host, "yara", raw_dir,
                                  tool_version=",".join(sorted(rulesets)))
    if reset:
        clear_detections(case_id, engine="yara")

    limit = (max_file_mb or MAX_YARA_FILE_MB) * 1024 * 1024
    scanned = skipped = 0
    artifacts, pending = [], []

    for path in raw_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > limit:
                skipped += 1
                continue
            matches = compiled.match(str(path), timeout=60)
        except (OSError, PermissionError) as e:
            log.debug("unreadable %s: %s", path, e)
            skipped += 1
            continue
        except Exception as e:              # yara.TimeoutError and friends
            log.debug("yara error on %s: %s", path, e)
            skipped += 1
            continue

        scanned += 1
        if not matches:
            continue

        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime,
                                           timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        except (OSError, OverflowError):
            mtime = None

        for m in matches:
            severity, score, attack, meta = _meta(m)
            namespace = getattr(m, "namespace", "") or "?"

            rec = build_record({
                "artifact_type": "yara_file_hit",
                "source": "yara",
                "host": host,
                "timestamps": [("file_modified", mtime)] if mtime else [],
                "description": f"YARA {m.rule} [{namespace}] matched {path}",
                "raw_data": {
                    "rule": m.rule,
                    "ruleset": namespace,
                    "path": str(path),
                    "tags": list(getattr(m, "tags", []) or []),
                    "meta": {k: str(v) for k, v in meta.items()},
                },
            }, path, len(artifacts), source_id, case_id)

            artifacts.append(rec)
            pending.append({
                "rule_id": f"YARA-{m.rule}",
                "rule_title": f"{m.rule} ({namespace})",
                "severity": severity, "score": score, "attack": attack,
                "matched_on": str(path)[:400],
                "dedup_key": rec["dedup_key"],
            })

    if not artifacts:
        log.info("yara: %d files scanned, %d skipped, no hits", scanned, skipped)
        return {"scanned": scanned, "hits": 0, "skipped": skipped}

    with connection() as conn:
        insert_artifacts(artifacts, conn=conn)

        # look ids back up by dedup_key: an artifact may already exist from a
        # previous run, in which case insert_artifacts ignored it
        keys = [p["dedup_key"] for p in pending]
        lookup = {}
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            q = ",".join("?" * len(chunk))
            lookup.update(dict(conn.execute(
                f"SELECT dedup_key, id FROM artifacts WHERE dedup_key IN ({q})",
                chunk)))

        dets = [{"artifact_id": lookup[p["dedup_key"]], "case_id": case_id,
                 "engine": "yara",
                 **{k: v for k, v in p.items() if k != "dedup_key"}}
                for p in pending if p["dedup_key"] in lookup]
        n = insert_detections(dets, conn=conn)

    no_attack = sum(1 for p in pending if not p["attack"])
    log.info("yara: %d files scanned, %d skipped, %d hits", scanned, skipped, n)
    if no_attack:
        log.info("  %d hit(s) came from rules with no ATT&CK id -- they appear "
                 "as unmapped findings in the report", no_attack)
    return {"scanned": scanned, "hits": n, "skipped": skipped}