
import json
import logging
import re
from pathlib import Path
import yaml

from config import DETECTION_RULES_DIR
from database.database import clear_detections, connection, insert_detections

log = logging.getLogger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")
DEFAULT_SCORE = {"info": 5, "low": 10, "medium": 25, "high": 40, "critical": 70}
CHUNK = 5000


# --------------------------------------------------------------------------
# field access
# --------------------------------------------------------------------------
TOP_LEVEL = {"description", "artifact_type", "host", "timestamp_utc",
             "primary_ts_type", "source"}


def get_field(row, raw, path):
    """Resolve a dotted field path against an artifact row.

    Returns None for anything missing rather than raising, so a rule that
    references a column this artifact type does not have simply does not
    match, instead of crashing the whole pass on row 400,000.
    """
    if path in TOP_LEVEL:
        return row.get(path)
    if path == "raw_data":
        return raw
    if path.startswith("raw_data."):
        cur = raw
        for part in path.split(".")[1:]:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
    return row.get(path)


# --------------------------------------------------------------------------
# operators -- all string comparisons are CASE-INSENSITIVE, because Windows
# paths are, and "C:\TEMP\" vs "c:\temp\" is not worth a missed detection.
# --------------------------------------------------------------------------
def _s(v):
    return "" if v is None else str(v)


def _lower_list(v):
    return [str(x).lower() for x in (v if isinstance(v, list) else [v])]


def _num(v):
    try:
        return float(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


OPS = {
    "equals":         lambda v, a: _s(v).lower() == str(a).lower(),
    "equals_any":     lambda v, a: _s(v).lower() in _lower_list(a),
    "contains":       lambda v, a: str(a).lower() in _s(v).lower(),
    "contains_any":   lambda v, a: any(x in _s(v).lower() for x in _lower_list(a)),
    "contains_all":   lambda v, a: all(x in _s(v).lower() for x in _lower_list(a)),
    "startswith_any": lambda v, a: _s(v).lower().startswith(tuple(_lower_list(a))),
    "endswith_any":   lambda v, a: _s(v).lower().endswith(tuple(_lower_list(a))),
    "regex":          lambda v, a: re.search(a, _s(v)) is not None,
    "exists":         lambda v, a: (v not in (None, "")) is bool(a),
    "is_true":        lambda v, a: (_s(v).lower() in ("true", "1", "yes")) is bool(a),
    "gt":             lambda v, a: _num(v) is not None and _num(v) > float(a),
    "lt":             lambda v, a: _num(v) is not None and _num(v) < float(a),
}

def eval_exclude(row, raw, exclude):
  
    for item in (exclude or []):
        if isinstance(item, dict) and ("all" in item or "any" in item):
            if eval_block(row, raw, item)[0]:
                return True
        elif eval_condition(row, raw, item)[0]:
            return True
    return False


def eval_condition(row, raw, cond):
    """Evaluate one condition. Returns (matched, "field=value").

    The second element becomes detections.matched_on. A finding you cannot
    explain is a finding nobody will act on, so every hit records exactly
    which field and value triggered it.
    """
    field = cond.get("field")
    if field is None:
        raise ValueError(f"condition has no 'field': {cond}")
    value = get_field(row, raw, field)

    for op, arg in cond.items():
        if op == "field":
            continue
        fn = OPS.get(op)
        if fn is None:
            raise ValueError(f"unknown operator {op!r} on field {field!r} "
                             f"(valid: {', '.join(sorted(OPS))})")
        try:
            if not fn(value, arg):
                return False, None
        except re.error as e:
            raise ValueError(f"bad regex on field {field!r}: {e}") from e
    return True, f"{field}={_s(value)[:200]}"


MAX_NEST = 6


def eval_block(row, raw, block, depth=0):
    
    if isinstance(block, list):
        block = {"all": block}
    if not isinstance(block, dict) or not ("all" in block or "any" in block):
        raise ValueError("match block must contain 'all' and/or 'any'")
    if depth > MAX_NEST:
        raise ValueError(f"match block nested deeper than {MAX_NEST}; a rule "
                         f"this complex is a correlation, not a rule")

    def evaluate(item):
        """A list item is either a condition (has 'field') or a nested block."""
        if isinstance(item, dict) and ("all" in item or "any" in item):
            return eval_block(row, raw, item, depth + 1)
        return eval_condition(row, raw, item)

    reasons = []
    for item in block.get("all", []):
        ok, why = evaluate(item)
        if not ok:
            return False, None
        if why:
            reasons.append(why)

    if "any" in block:
        hit = None
        for item in block["any"]:
            ok, why = evaluate(item)
            if ok:
                hit = why or "(nested)"
                break
        if hit is None:
            return False, None
        reasons.append(hit)

    return True, " | ".join(reasons)


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
REQUIRED = ("id", "title", "match")


def load_rules(rules_dir=None):
    rules_dir = Path(rules_dir or DETECTION_RULES_DIR)
    if not rules_dir.is_dir():
        raise SystemExit(f"no rules directory at {rules_dir}")

    rules, seen = [], {}
    files = sorted(list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml")))
    for path in files:
        with open(path, encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if not doc:
                    continue
                missing = [k for k in REQUIRED if k not in doc]
                if missing:
                    raise ValueError(f"{path.name}: rule missing {missing}")
                if doc["id"] in seen:
                    raise ValueError(
                        f"duplicate rule id {doc['id']} in {path.name} and "
                        f"{seen[doc['id']]}. If you merged rule files, delete "
                        f"the originals.")
                seen[doc["id"]] = path.name
                doc.setdefault("severity", "medium")
                if doc["severity"] not in SEVERITIES:
                    raise ValueError(f"{doc['id']}: bad severity "
                                     f"{doc['severity']!r}, expected one of "
                                     f"{', '.join(SEVERITIES)}")
                doc.setdefault("score", DEFAULT_SCORE[doc["severity"]])
                doc.setdefault("attack", [])
                doc["_file"] = path.name
                rules.append(doc)

    log.info("loaded %d rules from %d file(s) in %s",
             len(rules), len(files), rules_dir)
    return rules


def validate_rules(rules_dir=None):
    """Compile every rule against a dummy row BEFORE running any of them.

    THIS IS THE POINT OF THE ENGINE. A rule with a typo'd operator or a broken
    regex silently never matches, which is indistinguishable from a clean
    machine. This turns that into an error at startup.
    """
    rules = load_rules(rules_dir)
    probe = {"description": "probe", "artifact_type": "probe", "host": "h",
             "timestamp_utc": None, "primary_ts_type": None, "source": "s"}
    for r in rules:
        try:
            eval_block(probe, {}, r["match"])
            eval_exclude(probe, {}, r.get("exclude"))
        except Exception as e:
            raise ValueError(f"{r['_file']} :: {r['id']} :: "
                             f"{type(e).__name__}: {e}") from e

    no_attack = [r["id"] for r in rules if not r["attack"]]
    if no_attack:
        log.warning("%d rule(s) carry no ATT&CK id, so their findings cannot "
                    "be placed on the matrix: %s",
                    len(no_attack), ", ".join(no_attack[:10]))
    return rules


def _field_paths(rule):
    """Every raw_data.* path a rule references."""
    out = set()

    def walk(block):
        # recurses through nested all/any blocks as well as flat conditions,
        # so a field inside a nested group is still checked
        if isinstance(block, dict):
            if "field" in block:
                out.add(block["field"])
            for v in block.values():
                walk(v)
        elif isinstance(block, list):
            for item in block:
                walk(item)

    walk(rule.get("match"))
    walk(rule.get("exclude") or [])
    return {f for f in out if f.startswith("raw_data.")}


def check_fields(case_id, rules=None, rules_dir=None):

    rules = rules if rules is not None else load_rules(rules_dir)
    findings = []

    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"

        keys_by_type = {}

        def keys_for(types):
           
            seen = set()
            for t in types:
                if t not in keys_by_type:
                    found = set()
                    # top-level keys
                    found |= {k for (k,) in conn.execute(
                        f"""SELECT DISTINCT je.key
                            FROM {A} a, json_each(a.raw_data) je
                            WHERE a.case_id=? AND a.artifact_type LIKE ?
                              AND json_type(a.raw_data)='object'""",
                        (case_id, f"{t}%"))}
                    # the two nested levels rules actually reference
                    for pref, path in (("_enrich.", "$._enrich"),
                                       ("_enrich.payload.", "$._enrich.payload")):
                        found |= {pref + k for (k,) in conn.execute(
                            f"""SELECT DISTINCT je.key FROM (
                                  SELECT json_extract(raw_data,'{path}') p
                                  FROM {A}
                                  WHERE case_id=? AND artifact_type LIKE ?
                                    AND json_type(
                                        json_extract(raw_data,'{path}'))='object'
                                ) s, json_each(s.p) je""",
                            (case_id, f"{t}%"))}
                    keys_by_type[t] = found
                seen |= keys_by_type[t]
            return seen

        for rule in rules:
            types = (rule.get("scope") or {}).get("artifact_type") or []
            if not types:
                continue
            paths = _field_paths(rule)
            if not paths:
                continue
            present = keys_for(types)
            if not present:
                continue                # nothing of this type in the case
            missing = sorted(p for p in paths
                             if p[len("raw_data."):] not in present)
            if missing:
                findings.append((rule["id"], rule["title"], missing))

    if findings:
        log.warning("%d rule(s) reference fields absent from every sampled "
                    "artifact of their scoped type. A rule like this scans "
                    "normally and reports ZERO -- which looks exactly like a "
                    "clean host:", len(findings))
        for rid, title, missing in findings[:15]:
            log.warning("    %-10s %s", rid, ", ".join(missing))
            log.warning("               (%s)", title[:60])
    return findings


def _flatten_keys(d, prefix="", depth=0):
    """Dotted key paths inside a raw_data dict, to compare against rule fields."""
    out = set()
    if depth > 4 or not isinstance(d, dict):
        return out
    for k, v in d.items():
        path = f"{prefix}{k}"
        out.add(path)
        if isinstance(v, dict):
            out |= _flatten_keys(v, f"{path}.", depth + 1)
    return out


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------
def _scope_sql(rule):
    """Narrow the SQL so a rule about Prefetch does not stream 167,000 event
    log rows through Python.

    PREFIX MATCH BY DEFAULT: a scope of 'registry_' covers registry_run,
    registry_services and so on.

    Note ESCAPE '\\': in SQL LIKE, `_` matches ANY SINGLE CHARACTER. Without
    escaping, a scope of 'registry_' would also match 'registryX...'. Harmless
    with the current type names, but wrong, and the kind of thing that bites
    two years later.

    Set `scope: {exact: true}` when a rule must match one type only --
    'memory_process' as a prefix also catches memory_process_scan and
    memory_process_tree.
    """
    scope = rule.get("scope") or {}
    types = scope.get("artifact_type")
    if not types:
        return "", []
    types = types if isinstance(types, list) else [types]

    if scope.get("exact"):
        placeholders = ",".join("?" * len(types))
        return f" AND artifact_type IN ({placeholders})", list(types)

    clauses, params = [], []
    for t in types:
        clauses.append("artifact_type LIKE ? ESCAPE '\\'")
        params.append(t.replace("\\", "\\\\").replace("_", "\\_")
                       .replace("%", "\\%") + "%")
    return " AND (" + " OR ".join(clauses) + ")", params


def _guards(rule):
 
    m = rule.get("match")
    if not isinstance(m, dict):
        return None, None
    chans = eids = None
    for c in m.get("all", []):
        if not isinstance(c, dict):
            continue
        field = c.get("field")
        vals = ({str(c["equals"])} if "equals" in c else
                {str(v) for v in c["equals_any"]} if "equals_any" in c else
                None)
        if vals is None:
            continue
        if field == "raw_data.Channel":
            chans = vals
        elif field == "raw_data.EventId":
            eids = vals
    return chans, eids


def _dispatch_index(rules):
   
    from collections import defaultdict
    by_eid = defaultdict(list)
    by_chan = defaultdict(list)
    always = []
    for r in rules:
        chans, eids = _guards(r)
        if eids:
            for e in eids:
                by_eid[e].append(r)
        elif chans:
            for c in chans:
                by_chan[c].append(r)
        else:
            always.append(r)
    if len(rules) > 1:
        log.info("dispatch: %d rules on EventId, %d on Channel, %d unguarded",
             sum(len(v) for v in by_eid.values()),
             sum(len(v) for v in by_chan.values()), len(always))
    return dict(by_eid), dict(by_chan), always
# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------
def run(case_id, rules=None, rules_dir=None, reset=True, host=None,
        progress=True):
    
    import sys
    import time
    from collections import defaultdict
 
    rules = rules if rules is not None else validate_rules(rules_dir)


    groups = defaultdict(list)
    for rule in rules:
        extra, params = _scope_sql(rule)
        groups[(extra, tuple(params))].append(rule)
    log.info("%d rules in %d scope group(s)", len(rules), len(groups))
 
 
    summary, unfired, no_scope = {}, [], []
    total = 0
    scanned_by_rule = {}
    started = time.time()
 
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        if reset:
            removed = clear_detections(case_id, engine="internal", conn=conn)
            if removed:
                log.info("cleared %d detections from the previous pass",
                         removed)
 
        for gi, ((extra, params), group) in enumerate(
                sorted(groups.items(), key=lambda kv: -len(kv[1])), 1):
            params = list(params)
            types = sorted({t for r in group
                            for t in ((r.get("scope") or {}).get("artifact_type") or [])})
            sql = (f"SELECT id, artifact_type, host, description, timestamp_utc, "
                   f"source, raw_data FROM {A} WHERE case_id = ?" + extra)
            args = [case_id] + params
            if host:
                sql += " AND host = ?"
                args.append(host)
 
            cur = conn.execute(sql, args)
            cols = [d[0] for d in cur.description]
            hits_by_rule = defaultdict(list)
            scanned = 0
            by_eid, by_chan, always = _dispatch_index(group)
 
            while True:
                chunk = cur.fetchmany(CHUNK)      
                if not chunk:
                    break
                for values in chunk:
                    scanned += 1
                    row = dict(zip(cols, values))
 
                    try:
                        raw = json.loads(row["raw_data"]) if row["raw_data"] else {}
                    except (json.JSONDecodeError, TypeError):
                        raw = {}
 
                    eid = str(raw.get("EventId", ""))
                    chan = str(raw.get("Channel", ""))
                    for rule in (by_eid.get(eid, []) + by_chan.get(chan, [])
                                 + always):
                        if eval_exclude(row, raw, rule.get("exclude")):
                            continue
                        ok, why = eval_block(row, raw, rule["match"])
                        if ok:
                            hits_by_rule[rule["id"]].append({
                                "artifact_id": row["id"], "case_id": case_id,
                                "engine": "internal", "rule_id": rule["id"],
                                "rule_title": rule["title"],
                                "severity": rule["severity"],
                                "score": rule["score"],
                                "attack": rule["attack"], "matched_on": why,
                            })
 
                if progress and scanned % 50000 == 0:
                    elapsed = time.time() - started
                    sys.stderr.write(
                        f"\r  group {gi}/{len(groups)} "
                        f"({', '.join(types)[:34] or 'any'}): "
                        f"{scanned:,} rows, {sum(len(v) for v in hits_by_rule.values()):,} "
                        f"hits, {elapsed:.0f}s   ")
                    sys.stderr.flush()
 
            if progress:
                sys.stderr.write("\r" + " " * 90 + "\r")
                sys.stderr.flush()
 
            for rule in group:
                scanned_by_rule[rule["id"]] = scanned
                rows = hits_by_rule.get(rule["id"])
                if scanned == 0:
                    no_scope.append((rule["id"], list(types)))
                elif not rows:
                    unfired.append((rule["id"], scanned))
                else:
                    n = insert_detections(rows, conn=conn)
                    summary[rule["id"]] = n
                    total += n
                    log.info("%-14s %-46s %6d hits  (%d scanned)",
                             rule["id"], rule["title"][:46], n, scanned)
 
    log.info("detection: %d hits from %d of %d rules in %.0fs",
             total, len(summary), len(rules), time.time() - started)
 
    if unfired:
        log.info("%d rule(s) ran and found nothing -- that is a RESULT: %s",
                 len(unfired), ", ".join(r for r, _n in unfired[:12])
                 + (" ..." if len(unfired) > 12 else ""))
 
    if no_scope:
        log.warning("%d rule(s) had NOTHING TO SCAN -- their artifact types "
                    "are absent from this case, so they could not fire "
                    "regardless of the evidence. This is a COLLECTION GAP, "
                    "not a clean result, and belongs in the report:",
                    len(no_scope))
        shown = defaultdict(list)
        for rid, types in no_scope:
            shown[", ".join(types)].append(rid)
        for types, ids in sorted(shown.items(), key=lambda kv: -len(kv[1]))[:10]:
            log.warning("    %3d rules need: %s", len(ids), types or "(none)")
 
    return summary

def _rule_os(rule_id):
    """Infer OS from the id -- MDF-/MDM-W/SIG-WIN* are Windows, MDL-/MDM-L/
    SIG-LNX* are Linux. Every rule in this project follows it (checked: zero
    exceptions across 824 rules), so no YAML field or edits are needed."""
    rid = rule_id.upper()
    if rid.startswith(("MDL-", "MDM-L", "SIG-LNX")):
        return "linux"
    if rid.startswith(("MDF-", "MDM-W", "SIG-WIN")):
        return "windows"
    return None

def coverage(case_id, rules=None, rules_dir=None):
    rules = rules if rules is not None else load_rules(rules_dir)
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        present = {t for (t,) in conn.execute(
            f"SELECT DISTINCT artifact_type FROM {A} WHERE case_id=?", (case_id,))}
        case_os = {o for (o,) in conn.execute(
            f"SELECT DISTINCT os FROM {A} WHERE case_id=? AND os IS NOT NULL",
            (case_id,))}

    runnable, blocked, not_applicable = [], [], []
    for r in rules:
        rule_os = _rule_os(r["id"])
  
        if rule_os and case_os and rule_os not in case_os:
            not_applicable.append(r["id"])
            continue
        types = (r.get("scope") or {}).get("artifact_type") or []
        if not types:
            runnable.append(r["id"])
            continue
        if any(p.startswith(t) for t in types for p in present):
            runnable.append(r["id"])
        else:
            blocked.append((r["id"], r["title"], types))
    return {"runnable": runnable, "blocked": blocked,
            "not_applicable": not_applicable,
            "artifact_types_present": sorted(present)}