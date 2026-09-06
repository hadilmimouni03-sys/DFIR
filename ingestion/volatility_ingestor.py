"""Ingest Volatility3 JSON output."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from config import BATCH_SIZE
from database.database import (clear_source, connection, insert_artifacts,
                               register_evidence)
from normalization.normalizer import build_record
from normalization.specs import VOL_SPECS

log = logging.getLogger(__name__)


def ingest_volatility(vol_dir, case_id, host="unknown", acquired_utc=None,
                      source_id=None):
    vol_dir = Path(vol_dir)
    if source_id is None:
        source_id = register_evidence(case_id, host, "volatility", vol_dir,
                                      acquired_utc=acquired_utc)

    fallback = acquired_utc or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    totals = {"artifacts": 0, "events": 0}

    with connection() as conn:
        clear_source(source_id, conn=conn)
        for name, spec in VOL_SPECS.items():
            f = vol_dir / f"{name}.json"
            if not f.exists():
                continue
            try:
                rows = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                log.warning("%s: unreadable (%s), skipped", name, e)
                continue
            if not isinstance(rows, list):
                log.warning("%s: expected a JSON array, skipped", name)
                continue

            batch = []
            for i, r in enumerate(rows):
                ts = [(label, r.get(col)) for label, col in spec["ts"] if r.get(col)]
                if not ts:
                    ts = [("acquired", fallback)]
                rec = {"artifact_type": spec["type"], "source": "memory",
                       "host": host, "timestamps": ts,
                       "description": spec["desc"](r), "raw_data": dict(r)}
                if spec.get("enrich"):
                    rec["raw_data"]["_enrich"] = spec["enrich"](r)
                batch.append(build_record(rec, f, i, source_id, case_id))

            art = evt = 0
            for k in range(0, len(batch), BATCH_SIZE):
                a, e = insert_artifacts(batch[k:k + BATCH_SIZE], conn=conn)
                art, evt = art + a, evt + e
            totals["artifacts"] += art
            totals["events"] += evt
            log.info("%-10s %6d rows -> %6d artifacts", name, len(rows), art)
    
    return totals
