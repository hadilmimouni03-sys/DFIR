import argparse
import json
import hashlib
import re
import sys
from collections import Counter
from pathlib import Path
import logging
log = logging.getLogger(__name__)
try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")
 
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import DETECTION_RULES_DIR 


LOGSOURCES = {

    ("windows", "process_creation"): {
        "ns": "WINPROC",
        "scope": ["event_log", "memory_cmdline"],
        "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "1"}],
    },
    ("windows", "registry_event"): {
        "ns": "WINREG",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals_any": ["12", "13", "14"]}],
    },
    ("windows", "registry_set"): {
        "ns": "WINREG",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "13"}],
    },
    ("windows", "registry_add"): {
        "ns": "WINREG",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "12"}],
    },
    ("windows", "file_event"): {
        "ns": "WINFILE",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "11"}],
    },
    ("windows", "image_load"): {
        "ns": "WINIMG",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "7"}],
        "needs": "Sysmon EventID 7",
    },
    ("windows", "network_connection"): {
        "ns": "WINNET",
        "scope": ["event_log", "memory_network"],
        "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "3"}],
    },
    ("windows", "dns_query"): {
        "ns": "WINDNS",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "22"}],
    },
    ("windows", "process_access"): {
        "ns": "WINPACC",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "10"}],
        "needs": "Sysmon EventID 10",
    },
    ("windows", "create_remote_thread"): {
        "ns": "WINTHRD",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals": "8"}],
    },
    ("windows", "ps_script"): {
        "ns": "WINPS",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.EventId", "equals_any": ["4104", "4103"]}],
    },
    ("windows", "security"): {
        "ns": "WINSEC",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.Channel", "equals": "Security"}],
    },
    ("windows", "system"): {
        "ns": "WINSYS",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.Channel", "equals": "System"}],
    },
    ("windows", "application"): {
        "ns": "WINAPP",
        "scope": ["event_log"], "prefix": "raw_data._enrich.payload.",
        "guard": [{"field": "raw_data.Channel", "equals": "Application"}],
    },

    ("linux", "process_creation"): {
        "ns": "LNXPROC",
        "scope": ["auditd", "process", "memory_cmdline", "shell_history"],
        "prefix": "raw_data.", "guard": [],
    },
    ("linux", "auditd"): {
        "ns": "LNXAUD",
        "scope": ["auditd"], "prefix": "raw_data.", "guard": [],
    },
    ("linux", "file_event"): {
        "ns": "LNXFILE",
        "scope": ["auditd", "file_entry", "persistence_file"],
        "prefix": "raw_data.", "guard": [],
    },
    ("linux", "network_connection"): {
        "ns": "LNXNET",
        "scope": ["network_connection", "memory_network"],
        "prefix": "raw_data.", "guard": [],
    },
    ("linux", "syslog"): {
        "ns": "LNXLOG",
        "scope": ["auth_log", "journal"], "prefix": "raw_data.", "guard": [],
    },
    ("linux", "sshd"): {
        "ns": "LNXSSH",
        "scope": ["auth_log", "journal"], "prefix": "raw_data.", "guard": [],
    },
    ("linux", "auth"): {
        "ns": "LNXAUTH",
        "scope": ["auth_log", "journal"], "prefix": "raw_data.", "guard": [],
    },
    ("linux", "cron"): {
        "ns": "LNXCRON",
        "scope": ["cron_job", "journal"], "prefix": "raw_data.", "guard": [],
    },
    ("linux", "sudo"): {
        "ns": "LNXSUDO",
        "scope": ["auth_log", "journal"], "prefix": "raw_data.", "guard": [],
    },
}


MODIFIERS = {
    "": "equals_any", "contains": "contains_any", "startswith": "startswith_any",
    "endswith": "endswith_any", "re": "regex", "all": "contains_all",
}
 
# Modifiers with no equivalent. Listed explicitly so a refusal names the
# reason rather than saying "unsupported".
UNSUPPORTED_MODIFIERS = {
    "base64": "base64-encoded match; the framework stores decoded payloads",
    "base64offset": "base64 offset variants",
    "utf16": "utf16 encoding variants", "utf16le": "utf16 encoding variants",
    "wide": "wide-string encoding variants",
    "cidr": "CIDR range match; no range operator",
    "lt": "numeric less-than on a Sigma field", "gt": "numeric greater-than",
    "cased": "case-sensitive match; all comparisons here are case-insensitive",
    "expand": "placeholder expansion requires a Sigma pipeline",
    "fieldref": "field-to-field comparison; belongs in correlate.py",
}
 
 
class Refused(Exception):
    """Raised with the exact reason a rule cannot be translated exactly."""
 
 
# --------------------------------------------------------------------------
# condition parsing
# --------------------------------------------------------------------------
COND_TOKEN = re.compile(r"\s+")
 
 
def parse_condition(cond, detection):
    """Sigma `condition:` -> (match_block, exclude_list).
 
    ONLY an explicit allowlist of shapes. Anything else raises Refused with
    its reason, because an approximation here produces a rule that scans and
    matches nothing.
 
    Supported:
        selection
        selection and not filter
        selection and not 1 of filter_*
        all of selection_*                        [and not 1 of filter_*]
        1 of selection_*  /  any of selection_*   [and not ...]
        selection_a and selection_b               [and not ...]
        selection_a or selection_b                [and not ...]
    """
    cond = " ".join(str(cond).split()).lower()
 
    for bad, why in (("|", "aggregation"), ("count(", "aggregation"),
                     ("near ", "temporal proximity"), (" by ", "aggregation"),
                     ("timeframe", "time window")):
        if bad in cond:
            raise Refused(f"condition uses {why} ({bad.strip()!r}); "
                          f"that is a correlation, not a single-row rule")
 
    # split off the exclusion tail
    excl_names = []
    m = re.search(r"\s+and\s+not\s+(.+)$", cond)
    if m:
        tail, cond = m.group(1), cond[:m.start()]
        for part in re.split(r"\s+and\s+not\s+|\s+and\s+", tail):
            part = part.strip()
            g = re.fullmatch(r"(?:1|any|all)\s+of\s+([\w*]+)", part)
            if g:
                excl_names.append(g.group(1))
            elif re.fullmatch(r"[\w*]+", part):
                excl_names.append(part)
            else:
                raise Refused(f"exclusion clause {part!r} is not a plain "
                              f"selection or `N of filter_*`")
 
    if " not " in cond:
        raise Refused("negation inside the main condition; only a trailing "
                      "`and not ...` is translatable")
 
    def expand(pattern):

        pattern = pattern.strip().strip("()").strip()
        if "*" in pattern:
            rx = re.compile(pattern.replace("*", ".*") + "$")
            hits = [k for k in detection if rx.match(k.lower())]
            if not hits:
                raise Refused(f"pattern {pattern!r} matches no selection block")
            return hits
        for k in detection:
            if k.lower() == pattern:
                return [k]
        raise Refused(f"selection {pattern!r} not found in the detection block")
 
    cond = cond.strip()
    groups, joiner = None, None
 
    g = re.fullmatch(r"(?:all)\s+of\s+([\w*]+)", cond)
    if g:
        groups, joiner = expand(g.group(1)), "all"
    if groups is None:
        g = re.fullmatch(r"(?:1|any)\s+of\s+([\w*]+)", cond)
        if g:
            groups, joiner = expand(g.group(1)), "any"
    if groups is None and re.fullmatch(r"[\w]+", cond):
        groups, joiner = expand(cond), "all"
    if groups is None and " or " in cond and " and " not in cond:
        groups, joiner = [], "any"
        for part in cond.split(" or "):
            groups += expand(part.strip())
    if groups is None and " and " in cond and " or " not in cond:
        groups, joiner = [], "all"
        for part in cond.split(" and "):
            groups += expand(part.strip())
 
    if groups is None:
        raise Refused(f"condition shape {cond!r} is outside the supported set; "
                      f"translating it exactly is not possible, and an "
                      f"approximation would scan and match nothing")
 
    return groups, joiner, excl_names
 
 
# --------------------------------------------------------------------------
# selection -> conditions
# --------------------------------------------------------------------------
def convert_selection(block, prefix):
    """One Sigma selection block -> a list of conditions ANDed together.
 
    A selection that is a LIST of maps means OR between them, which becomes a
    nested `any:` block -- expressible only because the engine now supports
    nesting.
    """
    if isinstance(block, list):
        alternatives = [{"all": convert_selection(b, prefix)} for b in block]
        return [{"any": alternatives}] if len(alternatives) > 1 else \
            alternatives[0]["all"]
 
    if not isinstance(block, dict):
        raise Refused(f"selection is a {type(block).__name__}, expected a map")
 
    out = []
    for key, value in block.items():
        parts = key.split("|")
        field, mods = parts[0], [p.lower() for p in parts[1:]]
 
        for mod in mods:
            if mod in UNSUPPORTED_MODIFIERS:
                raise Refused(f"field `{key}` uses the {mod!r} modifier: "
                              f"{UNSUPPORTED_MODIFIERS[mod]}")
 
        base = next((m for m in mods
                     if m in ("contains", "startswith", "endswith", "re")), "")
        if "all" in mods:
            if base not in ("", "contains"):
                raise Refused(f"field `{key}` uses `{base}|all`; the engine "
                              f"has no {base}_all operator")
            op = "contains_all"
        else:
            op = MODIFIERS[base]
 
        if value is None:
            out.append({"field": prefix + field, "exists": False})
            continue
 
        values = value if isinstance(value, list) else [value]
        if any(v is None for v in values):
            raise Refused(f"field `{key}` mixes null with values; the null "
                          f"means 'field absent' and cannot be ORed here")
 
        values = [str(v) for v in values]
        if op == "regex":
            if len(values) > 1:
                out.append({"field": prefix + field,
                            "regex": "(?:" + "|".join(values) + ")"})
            else:
                out.append({"field": prefix + field, "regex": values[0]})
        else:
            out.append({"field": prefix + field, op: values})
    return out
 
 
LEVEL_MAP = {"critical": ("critical", 85), "high": ("high", 65),
             "medium": ("medium", 40), "low": ("low", 20),
             "informational": ("info", 10)}
LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2,
              "high": 3, "critical": 4}


def mapped_techniques():
   
    from detection.engine import load_rules
    from mitre.attack_mapper import COVERAGE
    ids = set()
    for r in load_rules():
        if r["id"].startswith("SIG-"):      # never feed imports back in
            continue
        ids |= {str(t).upper() for t in (r.get("attack") or [])}
    for techs in COVERAGE.values():
        ids |= {str(t).upper() for t in techs}
    return ids

 
def translate(doc, path, rule_id):
    ls = doc.get("logsource") or {}
    product = str(ls.get("product", "")).lower()
    category = str(ls.get("category") or ls.get("service") or "").lower()
 
    spec = LOGSOURCES.get((product, category))
    if spec is None:
        raise Refused(f"logsource {product}/{category} has no artifact mapping; "
                      f"this framework does not collect that telemetry, or the "
                      f"mapping is not written yet")
 
    detection = doc.get("detection") or {}
    cond = detection.get("condition")
    if not cond:
        raise Refused("no condition")
    if isinstance(cond, list):
        raise Refused("multiple conditions (a Sigma rule collection)")
 
    groups, joiner, excl_names = parse_condition(cond, detection)
    prefix = spec["prefix"]
 
    blocks = []
    for name in groups:
        conds = convert_selection(detection[name], prefix)
        blocks.append({"all": conds} if len(conds) > 1 else conds[0])
 
    if joiner == "all":
        inner = {"all": (spec["guard"] or []) + blocks}
    else:
        inner = {"all": (spec["guard"] or []) + [{"any": blocks}]} \
            if spec["guard"] else {"any": blocks}
 
    exclude = []
    for name in excl_names:
        for k in list(detection):
            if k.lower() == name or (
                    "*" in name and re.fullmatch(name.replace("*", ".*"), k.lower())):
                exclude.extend(convert_selection(detection[k], prefix))
 
    level = str(doc.get("level", "medium")).lower()
    severity, score = LEVEL_MAP.get(level, ("medium", 40))
 
    techniques = sorted({t.split("attack.")[1].upper()
                         for t in (doc.get("tags") or [])
                         if str(t).lower().startswith("attack.t")})
 
    fps = [str(x) for x in (doc.get("falsepositives") or [])
           if str(x).lower() not in ("unknown", "none")]
 
    description = (
        f"Translated from SigmaHQ `{path}` (status: {doc.get('status','?')}, "
        f"level: {level}).\n\n{doc.get('description','').strip()}\n\n"
        f"Severity and exclusions are SigmaHQ's, not self-assigned -- they are "
        f"argued over across many environments, which is the point of importing "
        f"rather than authoring.\n")
    if fps:
        description += "\nDocumented false positives:\n" + \
            "".join(f"  - {f}\n" for f in fps)
    if spec.get("needs"):
        description += (f"\nREQUIRES {spec['needs']}, which a default Sysmon "
                        f"config does not log. Verify with `main.py gaps` "
                        f"before trusting a zero result.\n")
 
    rule = {
        "id": rule_id,
        "title": doc.get("title", "")[:110],
        "severity": severity,
        "score": score,
        "attack": techniques,
        "description": description,
        "scope": {"artifact_type": spec["scope"]},
        "match": inner,
        "sigma_source": str(path),
        "sigma_licence": "DRL-1.1",
        "sigma_level": level,
        "sigma_status": doc.get("status", ""),
    }
    if spec.get("needs"):
        rule["requires_telemetry"] = spec["needs"]
    
    if exclude:
        rule["exclude"] = exclude
    return rule
 
 
# --------------------------------------------------------------------------
def verify(rules, case_id):
  
    from detection.engine import _flatten_keys, _field_paths
    from database.database import connection
 
    ok, unverifiable = [], []
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        cache = {}
 
        def keys_for(t):
            if t not in cache:
                found = {k for (k,) in conn.execute(
                    f"""SELECT DISTINCT je.key
                        FROM {A} a, json_each(a.raw_data) je
                        WHERE a.case_id=? AND a.artifact_type LIKE ?
                          AND json_type(a.raw_data)='object'""",
                    (case_id, f"{t}%"))}
                for pref, path in (("_enrich.", "$._enrich"),
                                   ("_enrich.payload.", "$._enrich.payload")):
                    found |= {pref + k for (k,) in conn.execute(
                        f"""SELECT DISTINCT je.key FROM (
                              SELECT json_extract(raw_data,'{path}') p FROM {A}
                              WHERE case_id=? AND artifact_type LIKE ?
                                AND json_type(
                                    json_extract(raw_data,'{path}'))='object'
                            ) s, json_each(s.p) je""",
                        (case_id, f"{t}%"))}
                cache[t] = found
            return cache[t]
 
        for rule in rules:
            present = set()
            for t in rule["scope"]["artifact_type"]:
                present |= keys_for(t)
            if not present:
                rule["verification"] = (
                    f"not verified: no "
                    f"{'/'.join(rule['scope']['artifact_type'][:2])} "
                    f"artifacts in {case_id}")
                ok.append(rule)
                continue
            missing = sorted(p[len("raw_data."):] for p in _field_paths(rule)
                             if p[len("raw_data."):] not in present)
            if missing:
                unverifiable.append((rule, f"fields absent from all "
                                           f"{len(present)} keys present on "
                                           f"this artifact type: "
                                           f"{', '.join(missing[:4])}"))
            else:
                rule["verification"] = f"verified against {case_id}"
                ok.append(rule)
    return ok, unverifiable
 
 
def translate_corpus(sigma_dir, out_dir=None, verify_case=None,
                     statuses=("stable", "test"), prefix="SIG",
                     techniques=None, all_techniques=False, min_level=None):
   
    root = Path(sigma_dir) / "rules"
    if not root.is_dir():
        raise SystemExit(f"no rules/ under {sigma_dir}. Fetch it first: "
                         f"python main.py rules")

    if not all_techniques and techniques is None:
        techniques = mapped_techniques()
    want = (None if all_techniques or not techniques
            else {f"attack.{str(t).lower()}" for t in techniques})
    floor = LEVEL_RANK.get(str(min_level).lower()) if min_level else None
    log.info("filter: %s technique(s), status %s, min level %s",
             "ALL" if want is None else len(want), list(statuses),
             min_level or "any")

    translated, refused, seen_titles = [], [], set()
    considered = 0

    for f in sorted(root.rglob("*.yml")):
        try:
            docs = [d for d in yaml.safe_load_all(
                f.read_text(encoding="utf-8", errors="replace")) if d]
        except yaml.YAMLError as e:
            refused.append((str(f), f"unparseable YAML: {str(e)[:60]}"))
            continue

        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            if str(doc.get("status", "")).lower() not in statuses:
                continue
            tags = {str(t).lower() for t in (doc.get("tags") or [])}
            if want and not (tags & want):
                continue
            if floor is not None and LEVEL_RANK.get(
                    str(doc.get("level", "medium")).lower(), 2) < floor:
                continue
            title = doc.get("title", "")

            considered += 1
            rel = f.relative_to(Path(sigma_dir))
            try:
                ls = doc.get("logsource") or {}
                spec = LOGSOURCES.get(
                    (str(ls.get("product", "")).lower(),
                     str(ls.get("category") or ls.get("service") or "").lower()))
                ns = (spec or {}).get("ns", "GEN")
                uid = str(doc.get("id", "")) or title
                rule_id = (f"{prefix}-{ns}-"
                           f"{hashlib.blake2b(uid.encode('utf-8'), digest_size=4)
                              .hexdigest().upper()}")
                rule = translate(doc, rel, rule_id)
                translated.append(rule)
            except Refused as e:
                refused.append((str(rel), str(e)))
            except Exception as e:
                refused.append((str(rel), f"{type(e).__name__}: {str(e)[:70]}"))

    kept, unverifiable = translated, []
    if verify_case:
        kept, unverifiable = verify(translated, verify_case)

    out_dir = Path(out_dir or DETECTION_RULES_DIR)
    out_path = out_dir / "sigma_derived.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = (f"# Generated by detection/sigma_translate.py from SigmaHQ.\n"
              f"# {len(kept)} rules translated EXACTLY; {len(refused)} refused\n"
              f"# because their condition shape, field modifier or logsource\n"
              f"# could not be translated without approximating -- and an\n"
              f"# approximation compiles, validates, scans and matches nothing.\n"
              f"# Severity and exclusions are SigmaHQ's, under DRL-1.1.\n\n")
    out_path.write_text(
        header + "\n---\n".join(
            yaml.safe_dump(r, sort_keys=False, allow_unicode=True, width=100)
            for r in kept), encoding="utf-8")

    refusal_log = out_dir.parent / "sigma_refused.txt"
    refusal_log.write_text(
        "\n".join(f"{p}\n    {r}" for p, r in refused), encoding="utf-8")

    reasons = Counter(r.split(";")[0].split(":")[0][:64] for _p, r in refused)
    log.info("sigma: %d considered, %d translated, %d refused, %d unverifiable",
             considered, len(translated), len(refused), len(unverifiable))
    for reason, count in reasons.most_common(8):
        log.info("    refused %4d  %s", count, reason)
    if unverifiable:
        log.warning("%d translated rule(s) were NOT written: their fields "
                    "appear in no artifact of the scoped type in %s. Such a "
                    "rule scans normally and reports zero, which looks exactly "
                    "like a clean host.", len(unverifiable), verify_case)

    return {
        "sigma_considered": considered,
        "sigma_translated": len(kept),
        "sigma_refused": len(refused),
        "sigma_unverifiable": len(unverifiable),
        "sigma_rules_file": str(out_path),
        "sigma_refusals_file": str(refusal_log),
        "sigma_refusal_reasons": dict(reasons.most_common(10)),
    }


def main():
  
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma", required=True, help="path to a SigmaHQ clone")
    ap.add_argument("--technique", action="append", dest="techniques",
                    metavar="TID",
                    help="repeatable, e.g. --technique t1490 --technique "
                         "t1547.001. Default: every technique we already map.")
    ap.add_argument("--all-techniques", action="store_true",
                    help="import the whole corpus -- this is what produced "
                         "1,668 rules and 48,000 detections")
    ap.add_argument("--min-level", choices=list(LEVEL_RANK),
                    help="drop Sigma rules below this level")
    ap.add_argument("--verify", metavar="CASE",
                    help="verify against a real case before writing")
    ap.add_argument("--out", help="override the rules directory")
    ap.add_argument("--status", nargs="*", default=["stable", "test"],
                    help="SigmaHQ marks only ~2%% of rules stable, so keep "
                         "test unless you want 32 rules")
    a = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    stats = translate_corpus(a.sigma, a.out, verify_case=a.verify,
                             techniques=a.techniques,
                             all_techniques=a.all_techniques,
                             min_level=a.min_level,
                             statuses=tuple(a.status))
 
if __name__ == "__main__":
    main()
