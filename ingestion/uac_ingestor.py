"""Ingest a UAC collection.

Structurally identical to kape_ingestor: register the evidence, wipe what this
source produced last time, walk the files, build_record() each row, batch
insert. The only difference is that UAC files are raw text so each one needs a
parser, whereas KAPE hands you CSVs.

Takes either the .tar.gz UAC produced or an already-extracted directory.
"""
import fnmatch
import logging
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from config import BATCH_SIZE
from database.database import (clear_source, connection, insert_artifacts,
                               register_evidence)
from normalization.linux_specs import LINUX_SPECS
from normalization.normalizer import (build_record, parse_failures,
                                      reset_parse_failures)
from ingestion.browser_ingestor import ingest_browsers

log = logging.getLogger(__name__)

IGNORE = [
    "uac.log*", "*.sha256", "*.md5", "hash_executables/*",
    "live_response/hardware/*", "live_response/packages/*",
    "chkrootkit/*", "memory_dump/*",
]


def _extract(archive):
    tmp = Path(tempfile.mkdtemp(prefix="uac_"))
    log.info("extracting %s -> %s", Path(archive).name, tmp)
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            # never let a crafted archive write outside tmp
            target = (tmp / member.name).resolve()
            if not str(target).startswith(str(tmp.resolve())):
                log.warning("skipped path traversal entry: %s", member.name)
                continue
            if member.issym() or member.islnk():
                continue
            tar.extract(member, tmp)
    inner = [p for p in tmp.iterdir() if p.is_dir()]
    return inner[0] if len(inner) == 1 else tmp


def _collection_time(root):
    for candidate in ("uac.log", "uac.log.stderr"):
        f = root / candidate
        if f.exists():
            return datetime.fromtimestamp(f.stat().st_mtime,
                                          timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    try:
        return datetime.fromtimestamp(root.stat().st_mtime,
                                      timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    except OSError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _match(rel, pattern):
    return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.lstrip("*/"))


def _parser_for(rel):
    for pattern, parser in LINUX_SPECS:
        if _match(rel, pattern):
            return parser, pattern
    return None, None


def ingest_uac(source, case_id, host, source_id=None, collected_utc=None,
               max_bodyfile_rows=None):
    source = Path(source)
    if not source.exists():
        log.error("uac: %s does not exist", source)
        return {"files": 0, "artifacts": 0, "events": 0}

    root = _extract(source) if source.is_file() else source
    if source_id is None:
        source_id = register_evidence(case_id, host, "uac", source,
                                      os_name="linux", acquired_utc=collected_utc)

    collected_utc = collected_utc or _collection_time(root)
    reset_parse_failures()
    totals = {"files": 0, "artifacts": 0, "events": 0}
    unmatched = []

    with connection() as conn:
        removed = clear_source(source_id, conn=conn)
        if removed:
            log.info("re-ingest: removed %d previous artifacts", removed)

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = str(path.relative_to(root)).replace("\\", "/").lower()
            if any(fnmatch.fnmatch(rel, p) for p in IGNORE):
                continue

            parser, pattern = _parser_for(rel)
            if parser is None:
                unmatched.append(rel)
                continue

            kwargs = {}
            if parser.__name__ in ("parse_ps", "parse_network"):
                kwargs["collected_utc"] = collected_utc

            batch, rows, art, evt = [], 0, 0, 0
            try:
                for i, rec in enumerate(parser(path, host, **kwargs)):
                    if max_bodyfile_rows and rec["artifact_type"] == "file_entry" \
                            and i >= max_bodyfile_rows:
                        break
                    batch.append(build_record(rec, path, i, source_id, case_id))
                    rows += 1
                    if len(batch) >= BATCH_SIZE:
                        a, e = insert_artifacts(batch, conn=conn)
                        art, evt, batch = art + a, evt + e, []
                if batch:
                    a, e = insert_artifacts(batch, conn=conn)
                    art, evt = art + a, evt + e
            except (OSError, UnicodeDecodeError) as exc:
                log.warning("%s: unreadable (%s), skipped", rel, exc)
                continue

            totals["files"] += 1
            totals["artifacts"] += art
            totals["events"] += evt
            if rows:
                log.info("%-56s %7d rows -> %6d artifacts %6d events",

                         rel[-56:], rows, art, evt)

    try:
        browsers = ingest_browsers(root, case_id, host)
        totals["artifacts"] += browsers.get("artifacts", 0)
        totals["events"] += browsers.get("events", 0)
    except ImportError:
        log.debug("browser_ingestor not available")

    if unmatched:
        log.warning("%d collected file(s) matched no parser. Top paths:",
                    len(unmatched))
        for u in unmatched[:15]:
            log.warning("    %s", u)
    failures = parse_failures()
    if failures:
        log.warning("timestamp fields that never parsed: %s", failures)
    return totals
