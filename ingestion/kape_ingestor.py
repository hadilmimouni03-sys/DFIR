import logging
import re
from pathlib import Path

from config import BATCH_SIZE
from database.database import (clear_source, connection, insert_artifacts,
                               register_evidence)
from ingestion.csv_importer import read_csv          
from normalization.normalizer import (build_record, normalize_by_spec,
                                      normalize_generic, parse_failures,
                                      reset_parse_failures)
from normalization.specs import SKIP, SKIP_UNLESS_MFT, SPECS

log = logging.getLogger(__name__)


def get_spec(filename):
    for pattern, spec in SPECS.items():
        if re.search(pattern, filename, re.I):
            return spec, pattern
    return None, None


def ingest_folder(parsed_dir, case_id, host, source_id=None,
                  include_mft=False, os_name="windows"):
    parsed_dir = Path(parsed_dir)
    if not parsed_dir.exists():
        log.error("ingest: %s does not exist", parsed_dir)
        return {"files": 0, "artifacts": 0, "events": 0}

    if source_id is None:
        source_id = register_evidence(case_id, host, "kape", parsed_dir,
                                      os_name=os_name)

    reset_parse_failures()
    skip = list(SKIP) + ([] if include_mft else list(SKIP_UNLESS_MFT))
    totals = {"files": 0, "artifacts": 0, "events": 0, "generic": [], "skipped": []}

    with connection() as conn:
        # idempotent: wipe what this source produced last time, then re-insert.
        removed = clear_source(source_id, conn=conn)
        if removed:
            log.info("re-ingest: removed %d previous artifacts", removed)

        for csv_path in sorted(parsed_dir.rglob("*.csv")):
            if any(re.search(p, csv_path.name, re.I) for p in skip):
                totals["skipped"].append(csv_path.name)
                continue

            spec, _ = get_spec(csv_path.name)
            if spec is None:
                totals["generic"].append(csv_path.name)

            batch, rows, art, evt = [], 0, 0, 0
            for i, row in read_csv(csv_path):
                rec = (normalize_by_spec(row, spec, host) if spec
                       else normalize_generic(row, csv_path.name, host))
                batch.append(build_record(rec, csv_path, i, source_id, case_id))
                rows += 1
                if len(batch) >= BATCH_SIZE:
                    a, e = insert_artifacts(batch, conn=conn)
                    art, evt, batch = art + a, evt + e, []
            if batch:
                a, e = insert_artifacts(batch, conn=conn)
                art, evt = art + a, evt + e

            totals["files"] += 1
            totals["artifacts"] += art
            totals["events"] += evt
            log.info("%-52s %7d rows -> %7d artifacts %7d events (%s)",
                     csv_path.name, rows, art, evt, "spec" if spec else "generic")

    # Visibility: these two lists are how you find artifacts you are losing.
    if totals["generic"]:
        log.warning("%d file(s) had no spec and fell back to generic parsing: %s",
                    len(totals["generic"]), ", ".join(totals["generic"][:10]))
    failures = parse_failures()
    if failures:
        log.warning("timestamp columns that never parsed: %s", failures)
    return totals
