import json
import logging
from collections import defaultdict

from database.database import connection

log = logging.getLogger(__name__)

SEV_ORDER = ["info", "low", "medium", "high", "critical"]

_PID_TYPES = ("memory_process", "memory_process_scan", "memory_process_tree",
              "memory_cmdline", "memory_injection", "memory_network",
              "memory_service", "memory_yara_hit", "memory_shell_history",
              "memory_environment", "memory_loaded_library",
              "memory_open_file", "memory_process_spoof")


def _artifacts_view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"


def _identity(artifact_type, raw):
  
    if not isinstance(raw, dict):
        return None

    payload = (raw.get("_enrich") or {}).get("payload") or {}

    if payload:
        guid = payload.get("ProcessGuid") or payload.get("SourceProcessGuid")
        pid = payload.get("ProcessId") or payload.get("SourceProcessId")
        name = payload.get("Image") or payload.get("SourceImage") or ""
        if guid:
            return (f"guid:{guid}", str(pid or "?"), str(name), True)
        if pid:
            return (f"pid:{pid}", str(pid), str(name), False)

    if artifact_type.startswith(_PID_TYPES):
        pid = raw.get("PID") or raw.get("pid")
        if pid not in (None, ""):
            name = (raw.get("ImageFileName") or raw.get("COMM")
                    or raw.get("Process") or raw.get("Name") or "")
            return (f"pid:{pid}", str(pid), str(name), False)

    if artifact_type == "process":
        pid = raw.get("pid")
        if pid not in (None, ""):
            return (f"pid:{pid}", str(pid), str(raw.get("command", ""))[:60], False)

    return None


def clusters(case_id, host=None, min_rules=1):
   
    with connection() as conn:
        A = _artifacts_view(conn)
        sql = f"""
            SELECT d.rule_id, d.rule_title, d.severity, d.score, d.attack,
                   d.engine, d.matched_on, a.artifact_type, a.timestamp_utc,
                   a.description, a.raw_data
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ?"""
        params = [case_id]
        if host:
            sql += " AND a.host = ?"
            params.append(host)
        rows = conn.execute(sql, params).fetchall()

    groups, unclustered = defaultdict(list), 0

    for (rule_id, title, severity, score, attack, engine, matched_on,
         atype, ts, desc, raw_json) in rows:
        try:
            raw = json.loads(raw_json) if raw_json else {}
        except (json.JSONDecodeError, TypeError):
            raw = {}

        ident = _identity(atype, raw)
        if ident is None:
            unclustered += 1
            continue

        key, pid, name, has_guid = ident
        try:
            techniques = json.loads(attack) if attack else []
        except (json.JSONDecodeError, TypeError):
            techniques = [t.strip() for t in str(attack).split(",") if t.strip()]

        groups[key].append({
            "rule_id": rule_id, "title": title, "severity": severity,
            "score": score or 0, "attack": [t.upper() for t in techniques],
            "engine": engine, "artifact_type": atype, "timestamp": ts,
            "description": desc, "matched_on": matched_on,
            "pid": pid, "name": name, "has_guid": has_guid,
        })

    out = []
    for key, hits in groups.items():
        names = {h["name"] for h in hits if h["name"]}
        techniques = sorted({t for h in hits for t in h["attack"]})
        rules = sorted({h["rule_id"] for h in hits})
        worst = max(hits, key=lambda h: SEV_ORDER.index(h["severity"])
                    if h["severity"] in SEV_ORDER else 0)["severity"]

        by_signal = {}
        for h in hits:
            key_sig = ",".join(h["attack"]) or f"rule:{h['rule_id']}"
            by_signal[key_sig] = max(by_signal.get(key_sig, 0), h["score"])
        score = sum(by_signal.values())

        stamps = sorted(h["timestamp"] for h in hits if h["timestamp"])

        out.append({
            "key": key,
            "pid": hits[0]["pid"],
            "names": sorted(names) or ["(unknown)"],
            "has_guid": hits[0]["has_guid"],
            "score": score,
            "severity": worst,
            "rule_count": len(rules),
            "hit_count": len(hits),
            "rules": rules,
            "attack": techniques,
            "first_seen": stamps[0] if stamps else None,
            "last_seen": stamps[-1] if stamps else None,
            "hits": sorted(hits, key=lambda h: h["timestamp"] or ""),
        })

    out = [c for c in out if c["rule_count"] >= min_rules]
    out.sort(key=lambda c: (-c["score"], -c["rule_count"]))
    return {"clusters": out, "unclustered": unclustered,
            "total_detections": len(rows)}


def show(case_id, host=None, top=15, min_rules=2, verbose=False):
    result = clusters(case_id, host, min_rules=min_rules)
    cl, un, total = result["clusters"], result["unclustered"], result["total_detections"]
    clustered = total - un

    print(f"\n{'='*76}")
    print(f"PROCESS CLUSTERS -- {case_id}")
    print(f"{'='*76}")
    print(f"  {total:,} detections: {clustered:,} carry a process identity, "
          f"{un:,} do not")
    if total:
        print(f"  ({100*clustered/total:.0f}% clusterable -- registry, Prefetch, "
              f"USN, LNK and browser artifacts have no PID, and nothing is "
              f"inferred for them)")
    print(f"  {len(cl)} process(es) flagged by {min_rules}+ distinct rule(s)\n")

    if not cl:
        print("  No process was flagged by more than one rule.")
        print("  That is a GOOD result: findings are scattered rather than")
        print("  converging on any single process. Re-run with --min-rules 1")
        print("  to see every flagged process.")
        return result

    for c in cl[:top]:
        guid_note = "" if c["has_guid"] else "   [PID only -- may be reused]"
        print(f"  {'-'*72}")
        print(f"  PID {c['pid']:<8} {', '.join(c['names'])[:44]:<44} "
              f"score {c['score']}")
        print(f"  {c['severity'].upper():<10} {c['rule_count']} rules, "
              f"{c['hit_count']} hits{guid_note}")
        if c["first_seen"]:
            print(f"  {c['first_seen']}  ..  {c['last_seen']}")
        if c["attack"]:
            print(f"  ATT&CK: {' -> '.join(c['attack'][:8])}")
        print()
        for h in c["hits"][:12 if verbose else 6]:
            print(f"    {(h['timestamp'] or '?')[:19]}  {h['rule_id']:<11} "
                  f"{h['title'][:48]}")
            if verbose and h["matched_on"]:
                print(f"                         {h['matched_on'][:70]}")
        if len(c["hits"]) > (12 if verbose else 6):
            print(f"    ... {len(c['hits']) - (12 if verbose else 6)} more")
        print()

    if len(cl) > top:
        print(f"  ... {len(cl)-top} more clusters")

    print(f"  {'-'*72}")
    print("  A process flagged by SEVERAL DIFFERENT TECHNIQUES is worth more")
    print("  than one flagged many times by near-duplicate rules -- the score")
    print("  sums once per ATT&CK technique, not once per rule or per hit.")
    return result


def coverage(case_id):

    r = clusters(case_id, min_rules=1)
    total = r["total_detections"]
    return {
        "total_detections": total,
        "clustered": total - r["unclustered"],
        "unclustered": r["unclustered"],
        "processes": len(r["clusters"]),
        "multi_rule_processes": len([c for c in r["clusters"]
                                     if c["rule_count"] >= 2]),
        "guid_backed": len([c for c in r["clusters"] if c["has_guid"]]),
    }
