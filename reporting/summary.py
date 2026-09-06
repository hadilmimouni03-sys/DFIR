"""Attack chain, risk level, and recommended actions.

WHAT THIS ADDS THAT THE FINDINGS TABLE DOES NOT
------------------------------------------------
A findings table answers "what fired". A reader still has to work out:

    how serious is this host, overall?
    in what ORDER did things happen?
    what should I DO about it?

Those are the three things a recipient acts on, and none of them is answerable
by sorting 21,000 rows by severity.

THE HONESTY PROBLEM, AND HOW IT IS HANDLED
--------------------------------------------
Every one of those three invites fabrication, so each is constrained:

  RISK is computed from BREADTH, not VOLUME. A rule firing 800 times is one
  observation repeated -- usually about the environment, not an intrusion.
  Counting hits would let a single untuned rule declare any machine critical.
  Distinct TACTICS covered is the signal: one tactic is an anomaly, five in
  sequence is an intrusion.

  The CHAIN is an OBSERVED ORDER, never a causal one. Techniques are placed on
  the ATT&CK tactic sequence and ordered by their timestamps. That two
  techniques appear adjacent does NOT mean one caused the other, and the
  output says so. Asserting causation from proximity is the same error as
  clustering artifacts by filename.

  RECOMMENDATIONS are derived from rules that ACTUALLY FIRED. There is no
  generic advice list: if MDF-0025 did not fire, nothing is said about shadow
  copies. A recommendation for a finding you do not have is noise that trains
  the reader to skip the section.

WHY NOT A RISK SCORE OUT OF 100
---------------------------------
Because it would be false precision. A number implies a calibrated scale, and
this one would be calibrated against a single FLARE-VM with an untuned
ruleset. A four-level band with its reasoning stated is a claim that can be
checked; "risk: 73/100" is not.
"""
import json
import logging
from collections import Counter, defaultdict

from database.database import connection

log = logging.getLogger(__name__)

# ATT&CK tactic order. Not a strict sequence -- real intrusions loop and skip
# -- but it is the conventional reading order, and it is what makes a list of
# techniques legible as a narrative.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]

# Tactics whose presence means the intrusion progressed beyond a foothold.
# Used for the risk band: five tactics ending in `impact` is a different
# situation from five tactics of discovery.
LATE_STAGE = {"credential-access", "lateral-movement", "collection",
              "exfiltration", "impact", "command-and-control"}


def _artifacts_view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"


# --------------------------------------------------------------------------
# RECOMMENDED ACTIONS
#
# Keyed on the RULE that fired, not on a technique or a severity band. A rule
# is the most specific thing that is actually true about this host, so the
# advice can be specific too: "the Security log was cleared at <time>" leads
# somewhere; "review your logging posture" does not.
#
# Each entry: (what to do, why it follows from THIS finding).
# --------------------------------------------------------------------------
ACTIONS = {
    "MDF-0008": ("Recover the cleared log from backup or a SIEM forward, and "
                 "identify the account that cleared it (Security 1102 records "
                 "the SubjectUserName).",
                 "A cleared log is both a finding and a gap: everything it "
                 "held is unavailable for the rest of this investigation."),
    "MDF-0025": ("Treat as a ransomware precursor. Isolate the host, verify "
                 "backups are intact and offline, and check for encrypted "
                 "files before restoring anything.",
                 "Deleting shadow copies has essentially no benign use on an "
                 "endpoint and normally precedes encryption by minutes."),
    "MDF-0026": ("Force a password reset for every account that had a session "
                 "on this host, and rotate any service account credentials it "
                 "held. Assume the hashes are compromised.",
                 "LSASS holds credentials in memory; a successful read means "
                 "they are already extracted."),
    "MDF-0029": ("Confirm which security or backup services were stopped and "
                 "whether they restarted. Check the same accounts on other "
                 "hosts.",
                 "Stopping defences is preparation, not an end state -- "
                 "whatever it enabled happened next."),
    "MDF-0031": ("Review what the elevated child process did. Check for "
                 "persistence created immediately afterwards.",
                 "A UAC bypass is a means, not a goal: the interesting "
                 "activity is what ran with the elevation."),
    "MDF-0033": ("Verify the account against your change records. If "
                 "unauthorised, disable rather than delete -- deleting "
                 "destroys the SID linkage for later analysis.",
                 "A new privileged account is durable access that survives "
                 "password resets and reboots."),
    "MDF-0012": ("Examine the source and target processes. Correlate with the "
                 "memory image if one was taken.",
                 "A remote thread is live injection; disk artifacts alone "
                 "will not show what was injected."),
    "MDF-0017": ("Remove the autorun value and identify the writing process "
                 "from the same Sysmon event.",
                 "The registry hive records the value but not who wrote it; "
                 "Sysmon EventID 13 does."),
    "MDF-C001": ("Retrieve the downloaded file, hash it, and check it against "
                 "threat intelligence. Identify the source URL from the "
                 "browser history.",
                 "Download-then-execute within an hour is the most common "
                 "initial-access sequence and is rarely coincidental."),
    "MDF-C002": ("Compare the psscan-only processes against the process list "
                 "and Sysmon. A process that exited between plugin runs is "
                 "benign; one that never appeared in pslist is not.",
                 "Unlinked process structures are a rootkit indicator, but "
                 "exited processes produce the same signal."),
    "MDF-C008": ("Compare each running service binary against its registry "
                 "configuration. Normalise \\\\SystemRoot\\\\ and case before "
                 "concluding a mismatch is real.",
                 "A genuine mismatch means the running binary is not the one "
                 "configured -- service hijacking."),
    "MDM-W005": ("Dump the injected region from the memory image and scan it. "
                 "Identify the process that created it.",
                 "An executable-and-writable region is how injected code "
                 "runs; the content is only recoverable from memory."),
    "IOC-SHA256": ("Retrieve the matched file if it still exists, and check "
                   "every other host for the same hash.",
                   "A hash match means this exact file was reported "
                   "malicious; the same sample is usually deployed widely."),
    "IOC-IP": ("Check firewall and proxy logs for other hosts contacting the "
               "same address, and block it.",
               "A C2 address is rarely used against one host only."),
}

# Advice that follows from a COLLECTION GAP rather than a finding. Keyed on
# the artifact type that was missing, and only emitted when rules were
# actually blocked for want of it -- see engine.coverage().
GAP_ACTIONS = {
    "mft_file": "Re-ingest with --include-mft. Timestomping (T1070.006) "
                "cannot be confirmed from Sysmon alone.",
    "scheduled_task": "Add TaskCache to the KAPE target. Scheduled-task "
                      "persistence is invisible without it.",
    "auditd": "Enable auditd on Linux hosts. Three rules examine it and none "
              "could run.",
    "memory_process": "No memory image was analysed. Process injection, "
                      "hidden processes and in-memory-only malware cannot be "
                      "detected from disk artifacts.",
}


# --------------------------------------------------------------------------
def assess(case_id, host=None):
    """Risk band, attack chain and recommended actions for one case."""
    with connection() as conn:
        A = _artifacts_view(conn)
        sql = f"""
            SELECT d.rule_id, d.rule_title, d.severity, d.score, d.attack,
                   d.engine, a.timestamp_utc, a.host, a.description
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ?"""
        params = [case_id]
        if host:
            sql += " AND a.host = ?"
            params.append(host)
        rows = conn.execute(sql, params).fetchall()

        types_present = {t for (t,) in conn.execute(
            f"SELECT DISTINCT artifact_type FROM {A} WHERE case_id=?",
            (case_id,))}

    if not rows:
        return {"level": "none", "reason": "No detections.", "chain": [],
                "actions": [], "gaps": [], "techniques": {}, "tactics": [],
                "rules_fired": 0, "detections": 0}

    # ---- collect, per TECHNIQUE not per hit ---------------------------
    # Deliberately not per detection: hit volume is dominated by whichever
    # rule is least tuned, and would let one noisy rule set the risk level.
    techniques = {}
    rules_fired = set()
    for (rule_id, title, severity, score, attack, engine, ts, h, desc) in rows:
        rules_fired.add(rule_id)
        try:
            techs = json.loads(attack) if attack else []
        except (json.JSONDecodeError, TypeError):
            techs = [t.strip() for t in str(attack).split(",") if t.strip()]
        for tid in techs:
            tid = tid.upper()
            entry = techniques.setdefault(tid, {
                "hits": 0, "rules": set(), "first": ts, "last": ts,
                "severity": severity, "examples": []})
            entry["hits"] += 1
            entry["rules"].add(rule_id)
            if ts:
                entry["first"] = min(filter(None, [entry["first"], ts]))
                entry["last"] = max(filter(None, [entry["last"], ts]))
            if len(entry["examples"]) < 3 and desc:
                entry["examples"].append(str(desc)[:110])

    # ---- place techniques on the tactic sequence ----------------------
    try:
        from mitre.attack_mapper import name as tech_name
        from mitre.attack_mapper import tactic as tech_tactic
    except ImportError:
        def tech_name(t):
            return ""

        def tech_tactic(t):
            return ["unknown"]

    by_tactic = defaultdict(list)
    for tid, info in techniques.items():
        tactics = tech_tactic(tid)
        if isinstance(tactics, str):
            tactics = [tactics]
        for tac in tactics or ["unknown"]:
            by_tactic[tac].append((tid, info))

    chain = []
    for tac in TACTIC_ORDER:
        if tac not in by_tactic:
            continue
        entries = sorted(by_tactic[tac], key=lambda kv: kv[1]["first"] or "")
        chain.append({
            "tactic": tac,
            "techniques": [{
                "id": tid, "name": tech_name(tid), "hits": i["hits"],
                "rules": sorted(i["rules"]), "first": i["first"],
                "last": i["last"], "examples": i["examples"],
            } for tid, i in entries],
        })

    tactics_seen = [c["tactic"] for c in chain]
    late = [t for t in tactics_seen if t in LATE_STAGE]

    # ---- risk band ----------------------------------------------------
    # BREADTH, not volume. Reasoning is returned with the level so a reader
    # can disagree with the judgement rather than the number.
    n_tac, n_late = len(tactics_seen), len(late)
    crit = [r for r in rows if r[2] == "critical"]

    if n_tac >= 5 and n_late >= 2:
        level = "critical"
        reason = (f"{n_tac} ATT&CK tactics observed including {n_late} "
                  f"late-stage ({', '.join(late)}). Breadth across the kill "
                  f"chain is consistent with an intrusion that progressed "
                  f"beyond initial access.")
    elif n_tac >= 4 or n_late >= 1:
        level = "high"
        reason = (f"{n_tac} tactics observed"
                  + (f", including {', '.join(late)}" if late else "")
                  + ". Findings span several stages rather than clustering in "
                    "one, which is harder to explain as ordinary activity.")
    elif crit or n_tac >= 2:
        level = "medium"
        reason = (f"{len(crit)} critical-severity detection(s) across "
                  f"{n_tac} tactic(s). Individually explainable; worth "
                  f"reading each before dismissing.")
    else:
        level = "low"
        reason = (f"Findings limited to {n_tac} tactic(s) with no "
                  f"late-stage activity. Consistent with an unusual but "
                  f"not compromised host.")

    # ---- recommended actions ------------------------------------------
    # Only for rules that FIRED. No generic advice: a recommendation about a
    # finding you do not have trains the reader to skip the section.
    actions = []
    for rule_id in sorted(rules_fired):
        if rule_id in ACTIONS:
            do, why = ACTIONS[rule_id]
            actions.append({"rule": rule_id, "action": do, "because": why})

    # ---- gaps ---------------------------------------------------------
    gaps = []
    try:
        from detection.engine import coverage
        blocked = coverage(case_id)["blocked"]
        needed = Counter(t for _r, _t2, types in blocked for t in types)
        for atype, n in needed.most_common():
            if atype in GAP_ACTIONS and atype not in types_present:
                gaps.append({"artifact_type": atype, "rules_blocked": n,
                             "action": GAP_ACTIONS[atype]})
    except Exception:
        pass

    return {
        "level": level, "reason": reason, "chain": chain,
        "tactics": tactics_seen, "late_stage": late,
        "techniques": {k: {**v, "rules": sorted(v["rules"])}
                       for k, v in techniques.items()},
        "actions": actions, "gaps": gaps,
        "rules_fired": len(rules_fired), "detections": len(rows),
        "critical": len(crit),
    }


# --------------------------------------------------------------------------
def show(case_id, host=None):
    """Print the summary."""
    r = assess(case_id, host)

    print(f"\n{'='*74}\nSUMMARY -- {case_id}\n{'='*74}")
    print(f"\n  RISK: {r['level'].upper()}\n")
    for line in _wrap(r["reason"], 68):
        print(f"    {line}")

    print(f"\n  {r['detections']:,} detections from {r['rules_fired']} rules, "
          f"{len(r['techniques'])} techniques, {len(r['tactics'])} tactics")

    if r["chain"]:
        print(f"\n{'-'*74}\nOBSERVED SEQUENCE\n{'-'*74}")
        print("  Techniques placed on the ATT&CK tactic order and sorted by "
              "time.\n  ADJACENCY IS NOT CAUSATION: this is the order things "
              "were observed,\n  not evidence that one led to the next.\n")
        for stage in r["chain"]:
            print(f"  {stage['tactic'].replace('-', ' ').upper()}")
            for t in stage["techniques"]:
                when = (t["first"] or "")[:19]
                print(f"    {when}  {t['id']:<12} {t['name'][:40]:<42} "
                      f"{t['hits']:>5} hits")
                print(f"                         via {', '.join(t['rules'][:4])}")
            print()

    if r["actions"]:
        print(f"{'-'*74}\nRECOMMENDED ACTIONS ({len(r['actions'])})\n{'-'*74}")
        print("  Derived from the rules that FIRED. Nothing generic.\n")
        for a in r["actions"]:
            print(f"  [{a['rule']}]")
            for line in _wrap(a["action"], 66):
                print(f"    {line}")
            for line in _wrap("Why: " + a["because"], 66):
                print(f"      {line}")
            print()

    if r["gaps"]:
        print(f"{'-'*74}\nCOLLECTION GAPS ({len(r['gaps'])})\n{'-'*74}")
        print("  Not findings -- capabilities this evidence could not "
              "exercise.\n")
        for g in r["gaps"]:
            print(f"  {g['artifact_type']} ({g['rules_blocked']} rules blocked)")
            for line in _wrap(g["action"], 66):
                print(f"    {line}")
            print()
    return r


def _wrap(text, width):
    words, line, out = str(text).split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


# --------------------------------------------------------------------------
def chain_svg(case_id, host=None, width=1000):
    """The observed sequence as an inline SVG, for the report.

    A horizontal band per tactic in ATT&CK order, with the techniques placed
    inside. Deliberately NOT a graph with arrows between techniques: an arrow
    asserts that one led to the next, which the evidence does not establish.
    """
    r = assess(case_id, host)
    if not r["chain"]:
        return ""

    COLOUR = {"initial-access": "#7c3aed", "execution": "#2563eb",
              "persistence": "#0891b2", "privilege-escalation": "#059669",
              "defense-evasion": "#ca8a04", "credential-access": "#dc2626",
              "discovery": "#64748b", "lateral-movement": "#ea580c",
              "collection": "#9333ea", "command-and-control": "#be123c",
              "exfiltration": "#b91c1c", "impact": "#7f1d1d"}

    band, gap = 54, 10
    height = len(r["chain"]) * (band + gap) + 50
    out = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
           f'style="max-width:100%;font-family:-apple-system,Segoe UI,sans-serif">',
           f'<text x="0" y="16" font-size="12" fill="#4a5568">Observed order '
           f'&#8212; position shows ATT&amp;CK tactic, not causation</text>']

    y = 32
    for stage in r["chain"]:
        tac = stage["tactic"]
        colour = COLOUR.get(tac, "#4a5568")
        out.append(f'<rect x="0" y="{y}" width="{width}" height="{band}" '
                   f'rx="4" fill="{colour}" fill-opacity="0.07"/>')
        out.append(f'<rect x="0" y="{y}" width="5" height="{band}" '
                   f'rx="2" fill="{colour}"/>')
        out.append(f'<text x="16" y="{y+20}" font-size="12" font-weight="600" '
                   f'fill="{colour}">{tac.replace("-", " ").upper()}</text>')

        x = 16
        for t in stage["techniques"][:6]:
            label = f'{t["id"]} ({t["hits"]})'
            w = 12 + len(label) * 6.5
            out.append(f'<rect x="{x}" y="{y+26}" width="{w:.0f}" height="20" '
                       f'rx="3" fill="{colour}" fill-opacity="0.18" '
                       f'stroke="{colour}" stroke-opacity="0.4"/>')
            out.append(f'<text x="{x+6}" y="{y+40}" font-size="11" '
                       f'fill="#1a202c">{label}</text>')
            out.append(f'<title>{t["name"]} -- {", ".join(t["rules"][:4])}</title>')
            x += w + 8
            if x > width - 120:
                break
        if len(stage["techniques"]) > 6:
            out.append(f'<text x="{x+4}" y="{y+40}" font-size="11" '
                       f'fill="#718096">+{len(stage["techniques"])-6} more</text>')
        y += band + gap

    out.append("</svg>")
    return "".join(out)