import hashlib
import re
import json
from datetime import datetime, timezone

from normalization.specs import (GENERIC_TS, GENERIC_TS_EXCLUDE,
                                 INTERESTING_COLUMNS, NOISE_PATTERNS, PRIMARY_TS)

CANONICAL = "%Y-%m-%dT%H:%M:%S.%fZ"

# FIX (P0-3): "%m/%d/%Y" is GONE. It silently turns 04/03/2024 into April 3rd
# when the source meant March 4th. A parse failure is visible; a wrong month is
# not. Pin your EZ Tools output with --dt "yyyy-MM-dd HH:mm:ss.fffffff" instead.
FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S%z",
]

_SENTINELS = {"", "null", "n/a", "-", "0",
              "1601-01-01 00:00:00", "1601-01-01t00:00:00",
              "0001-01-01 00:00:00", "0001-01-01t00:00:00",
              "1970-01-01 00:00:00", "1970-01-01t00:00:00"}

_MIN_YEAR = 1900         
_MAX_YEAR = 2100

_parse_failures = {}    


REDUNDANT_RAW_FIELDS = {"SourceFile",}


def _trim(raw):
    return {k: v for k, v in raw.items()
            if v not in (None, "", [], {}) and k not in REDUNDANT_RAW_FIELDS}


def normalize_timestamp(tmp, field=None):
    
    if tmp is None:
        return None
    v = str(tmp).strip()
    if v.lower() in _SENTINELS:
        return None
    v = v.removesuffix("Z").removesuffix("z").strip()   # not rstrip: that eats all trailing Z
    if not v:
        return None

    if "." in v:
        head, _, tail = v.partition(".")
        frac = ""
        rest = ""
        for i, c in enumerate(tail):
            if c.isdigit():
                frac += c
            else:
                rest = tail[i:]
                break
        v = head + ("." + frac[:6] if frac else "") + rest

    dt = None
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        for fmt in FORMATS:
            try:
                dt = datetime.strptime(v, fmt)
                break
            except ValueError:
                continue

    if dt is None:
        _parse_failures[field or "?"] = _parse_failures.get(field or "?", 0) + 1
        return None

    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

    if not (_MIN_YEAR <= dt.year <= _MAX_YEAR):
        return None
    return dt.strftime(CANONICAL)


def parse_failures():
    
    return dict(sorted(_parse_failures.items(), key=lambda kv: -kv[1]))


def reset_parse_failures():
    _parse_failures.clear()

def pick(row, *names, default=None):
    
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            return v
    return default


def _cols(spec_ts):
    for label, cols in spec_ts:
        yield label, ((cols,) if isinstance(cols, str) else tuple(cols))


def normalize_by_spec(row, spec, host="unknown", source="windows_kape"):
    rec = {
        "artifact_type": spec["type"](row),
        "source": source,
        "host": host,
        "timestamps": [(label, pick(row, *cols)) for label, cols in _cols(spec["ts"])],
        "description": spec["desc"](row),
        "raw_data": dict(row),
    }
    enrich = spec.get("enrich")
    if enrich:
        rec["raw_data"]["_enrich"] = enrich(row)
    return rec


def normalize_generic(row, filename, host="unknown", source="windows_kape"):
    stem = re.sub(r"^\d{14}_|_Output|\.csv$", "", filename, flags=re.I)
    stem = re.sub(r"__[A-Za-z]_[\w_]+$", "", stem).lower()
    artifact_type = "unparsed_" + stem

    timestamps = [(col.lower(), row.get(col))
                  for col in GENERIC_TS
                  if col not in GENERIC_TS_EXCLUDE and row.get(col)]

    bits = [f"{k}={row[k]}" for k in INTERESTING_COLUMNS if row.get(k)]
    if len(bits) < 3:
        bits = [f"{k}={v}" for k, v in list(row.items())[:6]
            if v and k != "_meta"]
    description = ", ".join(bits[:8])

    return {
        "artifact_type": artifact_type,
        "source": source,
        "host": host,
        "timestamps": timestamps,
        "description": description[:300],
        "raw_data": dict(row),
    }

def is_noise(text):

    low = str(text).lower()
    back = low.replace("/", "\\")
    fwd = low.replace("\\", "/")
    return int(any(p in back or p in fwd for p in NOISE_PATTERNS))

def dedup_key(case_id, host, artifact_type, timestamp_utc, description, raw=None):

    parts = [str(case_id), str(host), str(artifact_type),
             str(timestamp_utc or ""), str(description or "")]
    if raw:
        parts.append(json.dumps({k: v for k, v in raw.items() if k != "_meta"},
                                sort_keys=True, default=str))
    return hashlib.sha1("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def build_record(rec, source_file, row_index, source_id, case_id="default"):
    timestamps = {}
    for ts_type, raw in rec["timestamps"]:
        tmp = normalize_timestamp(raw, field=ts_type)
        if tmp:
            timestamps[ts_type] = tmp

    primary = PRIMARY_TS.get(rec["artifact_type"])
    if primary not in timestamps:
        primary = min(timestamps, key=timestamps.get) if timestamps else None

    description = (rec["description"] or "")[:1000]
    ts_utc = timestamps.get(primary)

    raw = _trim(rec["raw_data"])
    raw["_meta"] = {"src": str(source_file), "row": row_index}

    return {
        "case_id": case_id,
        "source_id": source_id,
        "host": rec["host"],
        "artifact_type": rec["artifact_type"],
        "source": rec["source"],
        "timestamp_utc": ts_utc,
        "primary_ts_type": primary,
        "description": description,
        "is_noise": is_noise(description),
        "dedup_key": dedup_key(case_id, rec["host"], rec["artifact_type"], ts_utc, description, raw=raw),
        "raw_data": raw,
        "events": [(label, tmp, int(label == primary))
                   for label, tmp in sorted(timestamps.items(),
                                              key=lambda kv: kv[1])],
    }
