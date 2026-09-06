import logging
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import BATCH_SIZE
from database.database import (clear_source, connection, insert_artifacts,
                               register_evidence)
from normalization.normalizer import build_record

log = logging.getLogger(__name__)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
EPOCH_1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)
FMT = "%Y-%m-%d %H:%M:%S.%f"


def _epoch_time(value, epoch):
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    try:
        return (epoch + timedelta(microseconds=micros)).strftime(FMT)
    except (OverflowError, OSError, ValueError):
        return None


def chrome_time(value):
    return _epoch_time(value, EPOCH_1601)


def firefox_time(value):
    return _epoch_time(value, EPOCH_1970)


def _open_copy(db_path, name):
    """Copy before opening. Opening a SQLite DB in place creates WAL/journal
    files and MODIFIES THE EVIDENCE. Correct forensic practice; say so in the
    report."""
    tmp = Path(tempfile.mkdtemp(prefix="minidfir_")) / name
    shutil.copy2(db_path, tmp)
    # sidecar WAL/SHM files hold recent, uncommitted history -- copy them too
    for suffix in ("-wal", "-shm"):
        side = Path(str(db_path) + suffix)
        if side.exists():
            shutil.copy2(side, str(tmp) + suffix)
    return sqlite3.connect(f"file:{tmp}?mode=ro", uri=True), tmp


def _cleanup(tmp):
    try:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    except OSError:
        pass


def _flush(batch, conn):
    art = evt = 0
    for k in range(0, len(batch), BATCH_SIZE):
        a, e = insert_artifacts(batch[k:k + BATCH_SIZE], conn=conn)
        art, evt = art + a, evt + e
    return art, evt


_CHROME_DOWNLOADS = ("SELECT target_path, tab_url, start_time, total_bytes, "
                     "danger_type FROM downloads")
_CHROME_VISITS = ("SELECT u.url, u.title, v.visit_time "
                  "FROM urls u JOIN visits v ON v.url = u.id")
_FF_DOWNLOADS = """
    SELECT p.url, a.content, a.dateAdded
    FROM moz_annos a
    JOIN moz_places p ON p.id = a.place_id
    JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id
    WHERE t.name = 'downloads/destinationFileURI'"""
_FF_VISITS = ("SELECT p.url, p.title, v.visit_date "
              "FROM moz_places p JOIN moz_historyvisits v ON v.place_id = p.id")


def _ingest_one(db, case_id, host, browser, tool, downloads_sql, visits_sql,
                conv, dl_row, visit_row):
    source_id = register_evidence(case_id, host, tool, db)
    try:
        conn_db, tmp = _open_copy(db, f"_{browser}.db")
    except (OSError, shutil.Error) as e:
        log.warning("could not copy %s: %s", db, e)
        return 0, 0

    batch, n_dl = [], 0
    try:
        for i, row in enumerate(conn_db.execute(downloads_sql)):
            batch.append(build_record(dl_row(row, host, conv), db, i,
                                      source_id, case_id))
        n_dl = len(batch)
        for j, row in enumerate(conn_db.execute(visits_sql)):
            batch.append(build_record(visit_row(row, host, conv), db,
                                      1_000_000 + j, source_id, case_id))
    except sqlite3.Error as e:
        log.warning("skipped %s: %s", db, e)
        return 0, 0
    finally:
        conn_db.close()
        _cleanup(tmp)

    with connection() as conn:
        clear_source(source_id, conn=conn)
        art, evt = _flush(batch, conn)
    log.info("%s: %d downloads, %d visits -> %d artifacts",
             browser, n_dl, len(batch) - n_dl, art)
    return art, evt


def _chrome_dl(row, host, conv):
    path, url, start, size, danger = row
    return {"artifact_type": "browser_download", "source": "browser", "host": host,
            "timestamps": [("download_start", conv(start))],
            "description": f"[chrome] {path} from {url} ({size} bytes, danger={danger})",
            "raw_data": {"path": path, "url": url, "bytes": size, "danger": danger}}


def _chrome_visit(row, host, conv):
    url, title, visit_time = row
    return {"artifact_type": "browser_visit", "source": "browser", "host": host,
            "timestamps": [("visit", conv(visit_time))],
            "description": f"[chrome] {url} - {title}",
            "raw_data": {"url": url, "title": title}}


def _ff_dl(row, host, conv):
    url, dest, start = row
    return {"artifact_type": "browser_download", "source": "browser", "host": host,
            "timestamps": [("download_start", conv(start))],
            "description": f"[firefox] {dest} from {url}",
            "raw_data": {"path": dest, "url": url}}


def _ff_visit(row, host, conv):
    url, title, visit_date = row
    return {"artifact_type": "browser_visit", "source": "browser", "host": host,
            "timestamps": [("visit", conv(visit_date))],
            "description": f"[firefox] {url} - {title}",
            "raw_data": {"url": url, "title": title}}


CHROMIUM_DIRS = ("chrome", "chromium", "brave", "microsoft-edge",
                 "vivaldi", "opera", "edge")


def ingest_browsers(raw_dir, case_id, host="unknown"):
    art = evt = 0
    raw_dir = Path(raw_dir)

    for db in sorted(raw_dir.rglob("History")):
        if not db.is_file():
            continue
        low = str(db).lower()
        family = next((d for d in CHROMIUM_DIRS if d in low), None)
        if family is None:
            continue
        a, e = _ingest_one(db, case_id, host, family, f"browser_{family}",
                           _CHROME_DOWNLOADS, _CHROME_VISITS, chrome_time,
                           _chrome_dl, _chrome_visit)
        art, evt = art + a, evt + e

    for db in sorted(raw_dir.rglob("places.sqlite")):
        if db.is_file():
            a, e = _ingest_one(db, case_id, host, "firefox", "browser_firefox",
                               _FF_DOWNLOADS, _FF_VISITS, firefox_time,
                               _ff_dl, _ff_visit)
            art, evt = art + a, evt + e

    return {"artifacts": art, "events": evt}
