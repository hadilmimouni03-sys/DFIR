#!/usr/bin/env python3
"""
MiniDFIR -- detection test.

    python tests/detection_test.py --case CASE01                 # check only
    python tests/detection_test.py --case CASE01 --run           # run detection
    python tests/detection_test.py --case CASE01 --run --yara    # + file YARA

Without --run it changes nothing: it verifies the known bugs are fixed, checks
which rules CAN fire against this evidence, and stops. Run that first -- there
is no point running 67 rules if two of them are structurally dead.

Works for any case, Windows or Linux.
"""
import argparse
import inspect
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import logging  # noqa: E402
logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

ap = argparse.ArgumentParser()
ap.add_argument("--case", required=True)
ap.add_argument("--host")
ap.add_argument("--run", action="store_true", help="actually run detection")
ap.add_argument("--yara", action="store_true", help="also scan collected files")
args = ap.parse_args()
CASE, HOST = args.case, args.host

from database.database import connection  # noqa: E402

problems = []


def head(n, t):
    print(f"\n{'='*72}\n{n}. {t}\n{'='*72}")


def check(ok, label, detail=""):
    if not ok:
        problems.append(label)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" +
          (f"\n         {detail}" if detail else ""))


def view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"


# =====================================================================
head(1, "KNOWN BUGS -- are they actually fixed?")
# =====================================================================
# These two silently distort results rather than crashing, which is why they
# are worth a check rather than a comment.

from normalization.specs import PRIMARY_TS, VOL_SPECS  # noqa: E402

# --- the _mz newline bug: MDF-0009 can never fire without this ---------
try:
    from normalization.specs import _mz
    probe_ok = _mz({"Hexdump": "\n4d 5a 90 00 03 00 00 00"})
    probe_no = _mz({"Hexdump": "\n90 90 90 90"})
    check(probe_ok and not probe_no,
          "_mz() strips the leading newline Volatility renders",
          "" if probe_ok else
          "returns False on a real MZ header. MDF-0009 CANNOT FIRE, and that "
          "looks identical to a clean machine.\n"
          "         Fix: strip \\n \\r \\t as well as spaces before the "
          "startswith check.")
except ImportError:
    check(False, "_mz not importable from specs.py")

# --- duplicate PRIMARY_TS key -----------------------------------------
spec_file = (ROOT / "normalization" / "specs.py").read_text(encoding="utf-8")
import re  # noqa: E402
ts_block = re.search(r"PRIMARY_TS = \{(.*?)\n\}", spec_file, re.S)
dupes = []
if ts_block:
    keys = re.findall(r'^\s*"(\w+)":', ts_block.group(1), re.M)
    dupes = [k for k, n in Counter(keys).items() if n > 1]
check(not dupes, "no duplicate keys in PRIMARY_TS",
      "" if not dupes else
      f"{dupes} defined twice -- the LAST wins, so the timestamp you chose is "
      f"silently overridden and min(timestamps) is used instead.")

# --- the ATT&CK mapper knows every technique the rules use -------------
from detection.engine import load_rules  # noqa: E402
from mitre.attack_mapper import TECHNIQUES  # noqa: E402

rules = load_rules()
used = {t.upper() for r in rules for t in r.get("attack", [])}
unnamed = sorted(used - set(TECHNIQUES))
check(not unnamed, f"every technique a rule uses has a name ({len(used)} used)",
      "" if not unnamed else
      f"{unnamed} will appear in the report as bare ids with no name")


# =====================================================================
head(2, "RULES -- do they all compile?")
# =====================================================================
from detection.engine import validate_rules  # noqa: E402

try:
    rules = validate_rules()
    check(True, f"{len(rules)} rules valid")
except Exception as e:
    check(False, "rule validation failed", str(e)[:300])
    print("\n  Cannot continue. If this is a duplicate id, the old split rule "
          "files\n  are still in rules/detection/ alongside the merged ones.")
    sys.exit(1)

by_file = Counter(r["_file"] for r in rules)
for f, n in sorted(by_file.items()):
    print(f"    {f:<28} {n:>3} rules")

sev = Counter(r["severity"] for r in rules)
print(f"\n  severity: " + "  ".join(f"{s}={sev.get(s,0)}"
      for s in ("critical", "high", "medium", "low", "info")))


# =====================================================================
head(3, "COVERAGE -- which rules CAN fire against this evidence?")
# =====================================================================
# The distinction that matters most in the whole test: a rule that runs and
# finds nothing is a RESULT. A rule with nothing to scan is a COLLECTION GAP,
# and mistaking the second for the first is how you report a clean machine
# you never actually examined.

from detection.engine import coverage  # noqa: E402

cov = coverage(CASE)
print(f"  artifact types in this case: {len(cov['artifact_types_present'])}")
print(f"  rules that CAN fire:         {len(cov['runnable'])}")
print(f"  rules with NOTHING to scan:  {len(cov['blocked'])}")

if cov["blocked"]:
    print("\n  blocked rules (their artifact types are absent):")
    by_reason = defaultdict(list)
    for rid, title, types in cov["blocked"]:
        by_reason[", ".join(types)].append(rid)
    for types, ids in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
        print(f"    {len(ids):>3} rules need: {types[:58]}")
        print(f"         {', '.join(ids[:8])}"
              f"{' ...' if len(ids) > 8 else ''}")
    print("\n  ^ this list IS your report's limitations section. Each line is")
    print("    a capability you have but did not exercise on this host.")


# =====================================================================
head(4, "RUN DETECTION")
# =====================================================================
if not args.run:
    print("  skipped (pass --run)")
else:
    from detection import correlate, engine
    fired = engine.run(CASE, rules=rules, host=HOST)
    print()
    corr = correlate.run_all(CASE)

    if args.yara:
        print()
        try:
            from config import evidence_dir
            from detection.yara_scanner import scan_directory
            for os_name in ("windows", "linux"):
                raw = evidence_dir(CASE, HOST or "", os_name) / "raw"
                if HOST and raw.is_dir():
                    runs = sorted(p for p in raw.iterdir() if p.is_dir())
                    target = runs[-1] if runs else raw
                    print(f"  scanning {target}")
                    scan_directory(CASE, HOST, target)
        except ImportError as e:
            print(f"  yara scan skipped: {e}")


# =====================================================================
head(5, "RESULTS")
# =====================================================================
with connection() as c:
    A = view(c)
    rows = c.execute(f"""
        SELECT d.rule_id, d.rule_title, d.severity, d.engine, COUNT(*)
        FROM detections d JOIN {A} a ON a.id = d.artifact_id
        WHERE a.case_id = ? GROUP BY 1,2,3,4""", (CASE,)).fetchall()

if not rows:
    print("  no detections.")
    print("  If section 3 showed runnable rules, this is a real result: the")
    print("  ruleset examined the evidence and found nothing matching.")
else:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda r: (order.get(r[2], 9), -r[4]))
    print(f"  {'rule':<12} {'sev':<9} {'hits':>7}  {'engine':<12} title")
    print("  " + "-" * 86)
    for rid, title, severity, engine_name, n in rows:
        flag = "  <-- noisy" if n > 200 else ""
        print(f"  {rid:<12} {severity:<9} {n:>7}  {engine_name:<12} "
              f"{str(title)[:40]}{flag}")
    print("  " + "-" * 86)
    print(f"  {'TOTAL':<12} {'':<9} {sum(r[4] for r in rows):>7}")

    sev_count = Counter()
    for _r, _t, s, _e, n in rows:
        sev_count[s] += n
    print(f"\n  by severity: " + "  ".join(
        f"{s}={sev_count.get(s,0)}" for s in
        ("critical", "high", "medium", "low", "info") if sev_count.get(s)))


# =====================================================================
head(6, "ATT&CK")
# =====================================================================
from mitre import attack_mapper  # noqa: E402

summary = attack_mapper.summary(CASE)
report = attack_mapper.coverage_report(CASE)
print(f"  techniques detected: {report['detected']}")
print(f"  examined, nothing found: {report['examined_clean']}")
print(f"  detections with NO ATT&CK id: {report['unmapped_detections']} "
      f"(from {report['unmapped_rules']} rules)")

for tactic in sorted(summary):
    print(f"\n  {tactic}")
    for tid, tname, info in summary[tactic][:6]:
        print(f"    {tid:<12} {info['hits']:>5} hits  {tname[:50]}")

if report["unmapped_detections"]:
    print("\n  Unmapped detections are REAL FINDINGS that cannot be placed on")
    print("  the matrix -- usually imported YARA rules, whose meta carries a")
    print("  reference rather than a technique id. Say so in the report rather")
    print("  than letting the coverage figure under-count.")


# =====================================================================
head(7, "NEXT")
# =====================================================================
if problems:
    print(f"  {len(problems)} problem(s) above:")
    for p in problems:
        print(f"    - {p}")
    print()
print(f"  triage the hits:   python tools\\triage.py --case {CASE}")
print(f"  tune one rule:     python tools\\triage.py --case {CASE} "
      f"--rule <ID> --suggest")
print(f"  generate report:   python main.py report --case {CASE} "
      f"--analyst \"your name\"")
print("\n  Start with the NOISIEST rule, not the most severe. A rule with 800")
print("  hits is telling you about the environment; one with 3 might be")
print("  telling you about an intrusion.")