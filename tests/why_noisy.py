"""Is this rule broad because SIGMA is broad, or because WE broke it?

    python tests/why_noisy.py CASE01
    python tests/why_noisy.py CASE01 --rule SIG-WINPROC-01891CBD

THE QUESTION
-------------
A rule firing 7,665 times tells you nothing on its own. Two very different
causes produce the same number:

  BROAD BY DESIGN   Sigma wrote a wide rule. "PowerShell made a network
                    connection" is real and fires a lot. It is context, not
                    an alert, and the fix is a severity change.

  BROAD BY DEFECT   The translation lost a constraint. Usually Sigma's
                    `filter` block, which becomes our `exclude` -- and an
                    exclusion on a field this evidence does not populate
                    returns False and SILENTLY FAILS TO EXCLUDE.

Tuning them the same way is how a framework becomes useless: you suppress
Sigma's real rules to hide your own translation defects.

THE MECHANISM, CORRECTED
--------------------------
An earlier version of this file claimed the bug was a vacuous MATCH via a
negation like `not_contains` on an absent field. That is wrong for this
engine: OPS has no negation operator, and eval_condition raises ValueError on
an unknown one, so validate_rules() rejects such a rule at load time. The bug
class cannot occur in `match`.

It occurs in `exclude`, and it runs the other way:

    get_field returns None for an absent path
    _s(None)                                    -> ""
    "".startswith(("c:\\program files\\",))     -> False

The exclusion evaluates False, does not exclude, and the row is kept. So a
file_event rule (guard EventId = 11) carrying a filter on ParentImage -- a
field EID 11 does not have -- behaves as though Sigma had written no filter.
Every dropped or inert filter makes a rule fire MORE.

That is why this measures the two halves SEPARATELY:

    match_selectivity   what the DETECTION narrows, ignoring exclusions
    exclusion_effect    what the FILTER actually removes

  match_selectivity   exclusion_effect          verdict
  ~0%                 any                       DEFECT: the selection was lost
  healthy             0% AND the rule HAS one   DEFECT: the filter is inert
  healthy             >0%                       working; breadth is Sigma's

The middle row is the one worth catching, and a single combined number cannot
distinguish it from the last.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.database import connection
from detection.engine import (_guards, _scope_sql, eval_block, eval_exclude,
                              get_field, load_rules)

# Columns eval_condition reads from the ROW, not from raw_data. `description`
# is the important one: hand-written rules reference it constantly, and
# resolving it inside the parsed JSON finds nothing -- which made MDF-0021
# report 0.0% population and get flagged as a defect while firing 182 times.
ROW_COLUMNS = ("id", "artifact_type", "host", "description", "timestamp_utc",
               "source", "raw_data")


def _fields_in(block, out=None):
    """Every field path a match or exclude block references, at any depth."""
    out = out if out is not None else set()
    if isinstance(block, dict):
        if "field" in block:
            out.add(block["field"])
        for k in ("all", "any"):
            for sub in block.get(k, []):
                _fields_in(sub, out)
    elif isinstance(block, list):
        for sub in block:
            _fields_in(sub, out)
    return out


def _strip_guard(rule):
    """The match block WITHOUT the logsource guard.

    The guard is what LOGSOURCES prepended: a Channel or EventId equality at
    the top level of `all`. Everything else is the detection Sigma wrote, and
    it is that part whose selectivity we want.
    """
    m = rule.get("match")
    if not isinstance(m, dict) or "all" not in m:
        return m, []
    guard, rest = [], []
    for c in m["all"]:
        if (isinstance(c, dict)
                and c.get("field") in ("raw_data.Channel", "raw_data.EventId")
                and ("equals" in c or "equals_any" in c)):
            guard.append(c)
        else:
            rest.append(c)
    return ({"all": rest} if rest else None), guard


def _populated(row, raw, path):
    """Is this field populated on this artifact?

    Uses the ENGINE's get_field so row columns and raw_data paths resolve the
    same way the rule sees them. Reimplementing the lookup is how the previous
    version decided `description` was absent from 324,242 rows that have it.
    """
    try:
        return get_field(row, raw, path) not in (None, "")
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", nargs="?", default="CASE01")
    ap.add_argument("--rule", help="one rule id")
    ap.add_argument("--min-hits", type=int, default=50)
    ap.add_argument("--sample", type=int, default=20000,
                    help="rows sampled per rule; exact when the guard selects "
                         "fewer than this")
    args = ap.parse_args()

    rules = {r["id"]: r for r in load_rules()}

    # Stale-comparison guard: `hits` comes from the last detect run, the rules
    # come from disk NOW. If the rules were re-translated since, they do not
    # correspond and every number below is meaningless.
    derived = Path("rules/yaml/sigma_derived.yaml")
    if not derived.exists():
        derived = Path("rules/yaml_sigma/sigma_derived.yaml")

    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"

        last = conn.execute(f"""
            SELECT MAX(d.detected_utc) FROM detections d
            JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ?""", (args.case,)).fetchone()[0]
        if derived.exists() and last:
            import datetime
            mtime = datetime.datetime.utcfromtimestamp(
                derived.stat().st_mtime).strftime("%Y-%m-%dT%H:%M:%SZ")
            if mtime > str(last):
                print(f"\n  WARNING: {derived.name} was written at {mtime}, "
                      f"AFTER the last detection at {last}.\n"
                      f"  The hit counts below came from a DIFFERENT ruleset. "
                      f"Re-run detect first.\n")

        fired = dict(conn.execute(f"""
            SELECT d.rule_id, COUNT(*) FROM detections d
            JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ? AND d.engine = 'internal'
            GROUP BY 1 ORDER BY 2 DESC""", (args.case,)))

        fired = ({k: v for k, v in fired.items() if k == args.rule}
                 if args.rule else
                 {k: v for k, v in fired.items() if v >= args.min_hits})
        if not fired:
            print(f"no rules above {args.min_hits} hits in {args.case}")
            return 0

        print(f"\n{'='*86}")
        print(f"WHY IS THIS NOISY? -- {len(fired)} rule(s) above "
              f"{args.min_hits} hits in {args.case}")
        print(f"{'='*86}")
        print("  match%  what the DETECTION narrows, exclusions IGNORED")
        print("  excl%   what the EXCLUSION then removes")
        print("  An exclusion at 0% on a rule that HAS one is inert: the field")
        print("  it tests is absent, so Sigma's filter is doing nothing.\n")

        verdicts, rows_out = Counter(), []

        for rid, hits in list(fired.items())[:40]:
            rule = rules.get(rid)
            if not rule:
                continue

            chans, eids = _guards(rule)
            detection, _guard = _strip_guard(rule)
            excl = rule.get("exclude") or []

            # reuse the ENGINE's scope SQL rather than reimplementing the LIKE
            # escaping -- the previous version omitted the \\ and % escapes
            extra, params = _scope_sql(rule)
            where = [f"case_id = ?"] + ([extra.replace(" AND ", "", 1)]
                                        if extra else [])
            params = [args.case] + list(params)
            if eids:
                where.append("json_extract(raw_data,'$.EventId') IN ("
                             + ",".join("?" * len(eids)) + ")")
                params += sorted(eids)
            elif chans:
                where.append("json_extract(raw_data,'$.Channel') IN ("
                             + ",".join("?" * len(chans)) + ")")
                params += sorted(chans)

            clause = " AND ".join(where)
            guard_rows = conn.execute(
                f"SELECT COUNT(*) FROM {A} WHERE {clause}", params).fetchone()[0]
            if not guard_rows:
                continue

            sample = conn.execute(
                f"SELECT {', '.join(ROW_COLUMNS)} FROM {A} WHERE {clause} "
                f"LIMIT ?", params + [args.sample]).fetchall()

  
            det_hits = excluded = 0
            m_fields = sorted(_fields_in(detection) if detection else [])
            e_fields = sorted(_fields_in(excl))
       
            pop_match = Counter({f: 0 for f in m_fields})
            pop_excl = Counter({f: 0 for f in e_fields})

            for values in sample:
                row = dict(zip(ROW_COLUMNS, values))
                try:
                    raw = json.loads(row["raw_data"]) if row["raw_data"] else {}
                except (json.JSONDecodeError, TypeError):
                    raw = {}

                for f in m_fields:
                    if _populated(row, raw, f):
                        pop_match[f] += 1
                for f in e_fields:
                    if _populated(row, raw, f):
                        pop_excl[f] += 1

                # the two halves, measured SEPARATELY
                if detection and not eval_block(row, raw, detection)[0]:
                    continue
                det_hits += 1
                if eval_exclude(row, raw, excl):
                    excluded += 1

            n = len(sample) or 1
            match_sel = 1 - det_hits / n
            excl_eff = excluded / max(det_hits, 1)
            exact = guard_rows <= args.sample

            # ---- verdict -----------------------------------------------
            # Thresholds are deliberately strict. A previous version called
            # 4,330 hits on 14,944 rows "narrowing normally"; FLARE-VM did not
            # disable storage write-protect 4,330 times.
            if not detection:
                v = "DEFECT: guard only, no detection left"
            elif match_sel < 0.05:
                v = "DEFECT: the match is vacuous, the selection was lost"
            elif excl and excl_eff == 0 and pop_excl and \
                    max(pop_excl.values()) / n < 0.05:
                v = "DEFECT: the exclusion is INERT -- its fields are absent"
            elif excl and excl_eff == 0:
                v = "SUSPECT: the exclusion never fires on this evidence"
            elif not excl and match_sel < 0.80:
                v = "SUSPECT: wide, and Sigma's filter was not carried over"
            elif match_sel < 0.80:
                v = "broad -- read the original Sigma rule"
            else:
                v = "working; breadth is Sigma's, a severity question"

            verdicts[v.split(":")[0].split(" --")[0]] += 1
            rows_out.append((rid, hits, guard_rows, match_sel, excl_eff,
                             bool(excl), exact, v, pop_match, pop_excl, n, rule))

        print(f"  {'rule':<26} {'hits':>7} {'guard':>9} {'match%':>8} "
              f"{'excl%':>7}  verdict")
        print("  " + "-" * 84)
        for (rid, hits, gr, ms, ee, has_e, exact, v, _pm, _pe, _n,
             _r) in rows_out:
            star = "" if exact else "~"
            print(f"  {rid:<26} {hits:>7,} {gr:>8,}{star} {ms:>7.1%} "
                  f"{(f'{ee:.1%}' if has_e else '  none'):>7}  {v}")

        print(f"\n{'-'*86}\n  {dict(verdicts)}")
        if any(not r[6] for r in rows_out):
            print(f"  ~ = the guard selects more than {args.sample:,} rows, so "
                  f"match%/excl% are sampled, not exact")

        bad = [r for r in rows_out
               if r[7].startswith(("DEFECT", "SUSPECT"))]
        if bad:
            print(f"\n{'='*86}\nOURS TO FIX -- not Sigma's breadth\n{'='*86}")
            for (rid, hits, gr, ms, ee, has_e, exact, v, pm, pe, n,
                 rule) in bad[:8]:
                print(f"\n  {rid}   {hits:,} hits of {gr:,} guarded rows")
                print(f"    {v}")
                print(f"    source: {rule.get('sigma_source', 'hand-written')}")
                if pe:
                    print(f"    EXCLUSION field population:")
                    for f, c in sorted(pe.items(), key=lambda kv: kv[1]):
                        frac = c / n
                        flag = ("   <-- INERT: this exclusion can never fire, "
                                "so Sigma's filter does nothing here"
                                if frac < 0.05 else "")
                        print(f"      {frac:>7.1%}  {f}{flag}")
                elif has_e:
                    print(f"    the rule HAS an exclude but it references no "
                          f"resolvable field")
                else:
                    print(f"    the rule has NO exclude at all -- check whether "
                          f"the Sigma source has a filter block that was "
                          f"dropped")
                if pm:
                    print(f"    MATCH field population:")
                    for f, c in sorted(pm.items(), key=lambda kv: kv[1])[:5]:
                        frac = c / n
                        flag = ("   <-- absent, so this rule can barely fire"
                                if frac < 0.05 else "")
                        print(f"      {frac:>7.1%}  {f}{flag}")
            print(f"\n  Compare one against its Sigma original:")
            print(f"    python tests/diff_test_sigma.py --id {bad[0][0]}")

        print(f"""
{'='*86}
WHAT TO DO
{'='*86}
  DEFECT / SUSPECT rows are ours. The usual cause is an exclusion whose
  field this evidence does not populate: it evaluates False, fails to
  exclude, and Sigma's filter does nothing. Check the Sigma source for a
  `filter` block and confirm it survived translation.

  'working' rows are a SEVERITY question, not a bug. Sigma ships wide
  context rules deliberately. Demote them or scope them out of the alerting
  tier -- do not treat them as translation errors.

  Neither can be tuned honestly against evidence containing no attack.
  On a clean host every hit is a false positive by definition, so 'this rule
  is too broad' and 'there is nothing here to find' are the same
  observation. That is what the attack simulation is for.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())