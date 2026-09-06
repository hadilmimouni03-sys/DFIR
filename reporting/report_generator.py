import html
import logging
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from database.database import connection

log = logging.getLogger(__name__)

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOUR = {"critical": "#a32020", "high": "#c05621", "medium": "#b7791f",
              "low": "#4a7c59", "info": "#4a5568"}

CSS = """
/* ====================================================================== *
 * MiniDFIR report stylesheet
 *
 * DESIGNED PRINT-FIRST. The PDF is the deliverable; the HTML is the same
 * document on screen. Two rules govern everything below:
 *
 *   1. COLOUR MEANS SEVERITY, AND NOTHING ELSE. A reader scanning a 20-page
 *      printout must be able to trust that anything coloured is a finding.
 *      Structure is carried by rules, weight and space instead.
 *   2. NOTHING IS ADDED OR REWORDED FOR PRINT. The print block changes
 *      layout only, so the PDF cannot say something the HTML does not.
 * ====================================================================== */
:root {
  --ink:#12161c;          /* headings, table data                     */
  --body:#2b3440;         /* running text                             */
  --muted:#69737f;        /* labels, captions, section numbers        */
  --rule:#dde2e8;         /* hairline separators                      */
  --rule-strong:#98a3b0;  /* table head and foot                      */
  --bg:#fff;
  --panel:#f5f7f9;
  --zebra:#fafbfc;
  --warn-bg:#fdf8ef;
  --warn-rule:#c98a2e;
  --accent:#1f3350;       /* one structural accent, used sparingly    */
}
* { box-sizing: border-box; }

/* backgrounds and rules must survive the print pipeline, or every table
   loses its header underline and the severity badges lose their borders */
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }

body {
  font: 14px/1.55 "Segoe UI", -apple-system, Roboto, "Helvetica Neue", sans-serif;
  /* columns of counts are unreadable in proportional figures */
  font-variant-numeric: tabular-nums;
  color: var(--body); background: var(--bg);
  margin: 0 auto; padding: 2.5rem 3rem; max-width: 1180px;
  counter-reset: section;
}

/* ---------------------------------------------------------------- type -- */
h1 { font-size: 26px; line-height: 1.2; font-weight: 600;
     color: var(--ink); margin: 0 0 .35rem; letter-spacing: -.01em; }

/* Sections are numbered BY A COUNTER, not by hand. The report grew from 9
   sections to 12 and the hand-written numbers had already drifted to
   "1b", "1c", "5b" -- which reads as an unfinished document. */
h2 {
  counter-increment: section;
  font-size: 17px; font-weight: 600; color: var(--ink);
  margin: 2.6rem 0 .9rem; padding-bottom: .35rem;
  border-bottom: 1.5px solid var(--rule-strong);
  letter-spacing: -.005em;
}
h2::before {
  content: counter(section) ".";
  color: var(--muted); font-weight: 600; margin-right: .55em;
}
h3 { font-size: 14px; font-weight: 600; color: var(--ink);
     margin: 1.5rem 0 .45rem; }
p  { margin: .55rem 0; max-width: 78ch; orphans: 3; widows: 3; }

code, .mono, pre {
  font-family: "Cascadia Mono", Consolas, "SF Mono", monospace;
  font-size: 12px;
}
pre { background: var(--panel); border: 1px solid var(--rule);
      padding: .8rem 1rem; overflow-x: auto; line-height: 1.45; }

/* -------------------------------------------------------------- tables -- */
table { border-collapse: collapse; width: 100%;
        margin: .8rem 0 1.5rem; font-size: 12.5px; }
thead th {
  text-align: left; font-weight: 600; color: var(--ink);
  padding: .45rem .6rem; white-space: nowrap;
  border-bottom: 1.5px solid var(--rule-strong);
}
tbody td { padding: .38rem .6rem; border-bottom: 1px solid var(--rule);
           vertical-align: top; color: var(--ink); word-break: break-word; }
/* a 250-row table is materially easier to track across with banding */
tbody tr:nth-child(even) td { background: var(--zebra); }
tbody tr:last-child td { border-bottom: 1.5px solid var(--rule-strong); }
tbody tr:hover td { background: #eef3f8; }

/* ------------------------------------------------------------ severity -- */
/* The inline colour comes from SEV_COLOUR; border and text both read it
   through currentColor, so the palette lives in ONE place, in Python. */
.sev {
  display: inline-block; min-width: 5.4em; text-align: center;
  font-size: 10px; font-weight: 700; letter-spacing: .06em;
  text-transform: uppercase;
  padding: .1em .45em; border-radius: 2px;
  border: 1px solid currentColor;
}

/* --------------------------------------------------------- components -- */
.note, .warn { padding: .75rem 1rem; margin: 1rem 0; font-size: 13px;
               border-left: 3px solid; }
.note { background: var(--panel); border-left-color: var(--rule-strong); }
.warn { background: var(--warn-bg); border-left-color: var(--warn-rule); }
.note p:first-child, .warn p:first-child { margin-top: 0; }
.note p:last-child,  .warn p:last-child  { margin-bottom: 0; }

.cluster { border: 1px solid var(--rule); border-left: 3px solid var(--accent);
           padding: .9rem 1.1rem; margin: 1.1rem 0; background: var(--panel); }
.cluster h3 { margin-top: 0; }
.cluster table { margin-bottom: .2rem; }

.kv { display: grid; grid-template-columns: 190px 1fr;
      gap: .35rem 1.2rem; font-size: 13.5px; margin: 1rem 0 1.4rem; }
.kv div:nth-child(odd)  { color: var(--muted); }
.kv div:nth-child(even) { color: var(--ink); font-weight: 500; }

.meta { color: var(--muted); font-size: 12.5px; }
footer { margin-top: 3rem; padding-top: .9rem;
         border-top: 1px solid var(--rule);
         color: var(--muted); font-size: 11.5px; max-width: 78ch; }

/* ---------------------------------------------------------- cover page -- */
/* Hidden on screen: on a monitor the reader already has the document title
   in front of them. On paper a report with no title page reads as a
   fragment, so print gets one and screen does not. */
.cover { display: none; }

/* ====================================================================== *
 * PRINT / PDF -- layout only
 * ====================================================================== */
@page { size: A4; margin: 18mm 15mm; }

@media print {
  body { padding: 0; max-width: none; font-size: 10pt; line-height: 1.45; }

  .cover {
    display: flex; flex-direction: column; justify-content: center;
    min-height: 250mm; break-after: page;
    border-top: 5px solid var(--accent);
    padding-top: 2rem;
  }
  .cover .cover-kicker { font-size: 10pt; letter-spacing: .16em;
                         text-transform: uppercase; color: var(--muted);
                         margin-bottom: 1.2rem; }
  .cover h1 { font-size: 30pt; line-height: 1.12; margin: 0 0 .5rem;
              max-width: 20ch; }
  .cover .cover-case { font-size: 15pt; color: var(--accent);
                       font-weight: 600; margin: 0 0 3rem; }
  .cover .kv { grid-template-columns: 150px 1fr; font-size: 10.5pt;
               max-width: 130mm; }
  .cover .cover-foot { margin-top: auto; padding-top: 2rem;
                       border-top: 1px solid var(--rule);
                       font-size: 9pt; color: var(--muted); }
  /* the on-screen title block is redundant once the cover page exists */
  .dochead { display: none; }

  h1 { font-size: 17pt; }
  /* a heading stranded at the foot of a page reads as an empty section,
     which in a findings report is actively misleading */
  h2 { font-size: 12.5pt; margin: 16pt 0 7pt; break-after: avoid; }
  h3 { font-size: 10.5pt; break-after: avoid; }
  p  { max-width: none; }

  table { font-size: 8.5pt; }
  /* a findings table split across three pages is unreadable if only the
     first page says what the columns are */
  thead { display: table-header-group; }
  tr { break-inside: avoid; }
  tbody tr:hover td { background: inherit; }   /* hover is meaningless on paper */

  .cluster, .note, .warn, .kv { break-inside: avoid; }
  pre { break-inside: avoid; white-space: pre-wrap; }
  footer { break-before: avoid; }
}
"""


# --------------------------------------------------------------------------
def _e(v):
    """Escape. Artifact descriptions contain attacker-controlled text."""
    return html.escape("" if v is None else str(v), quote=True)


def _table(rows, headers, sev_col=None):
    if not rows:
        return "<p class='meta'>None.</p>"
    out = ["<table><thead><tr>"]
    out += [f"<th>{_e(h)}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>")
        for i, cell in enumerate(r):
            if sev_col is not None and i == sev_col:
                s = str(cell).lower()
                out.append(f"<td><span class='sev' style='color:"
                           f"{SEV_COLOUR.get(s, '#4a5568')}'>{_e(cell)}</span></td>")
            else:
                out.append(f"<td>{_e(cell)}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return ("v_artifacts" if "v_artifacts" in objs else "artifacts",
            "v_timeline" if "v_timeline" in objs else None)


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------
def _header(case_id, analyst, stats):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hosts = ", ".join(stats["hosts"]) or "none"
    span = stats["range"]
    return f"""
<div class="cover">
  <div class="cover-kicker">Digital forensics &amp; incident response</div>
  <h1>Endpoint forensic analysis</h1>
  <p class="cover-case">Case {_e(case_id)}</p>
  <div class="kv">
    <div>Host(s)</div><div>{_e(hosts)}</div>
    <div>Analyst</div><div>{_e(analyst)}</div>
    <div>Evidence spans</div><div>{_e(span[0])} &ndash; {_e(span[1])}</div>
    <div>Report generated</div><div>{now}</div>
  </div>
  <div class="cover-foot">
    Produced by MiniDFIR. Every finding in this report carries the rule
    identifier that produced it and the field value that matched, so a
    reader can evaluate the reasoning rather than trust the tool.
  </div>
</div>

<div class="dochead">
<h1>Digital forensic analysis &mdash; {_e(case_id)}</h1>
<p class="meta">Generated {now} &nbsp;|&nbsp; Analyst: {_e(analyst)}
&nbsp;|&nbsp; MiniDFIR</p>
</div>

<h2>Summary</h2>
<div class="kv">
  <div>Case</div><div>{_e(case_id)}</div>
  <div>Hosts examined</div><div>{_e(hosts)}</div>
  <div>Evidence sources</div><div>{stats['sources']}</div>
  <div>Artifacts</div><div>{stats['artifacts']:,}</div>
  <div>Timeline events</div><div>{stats['events']:,}</div>
  <div>Evidence spans</div><div>{_e(span[0])} &nbsp;to&nbsp; {_e(span[1])}</div>
  <div>Detections</div><div>{stats['detections']:,}
      from {stats['rules_fired']} rules</div>
</div>
"""


def _evidence(conn, case_id):
    """Chain of custody. A finding is only as good as the provenance of the
    artifact behind it."""
    rows = conn.execute("""
        SELECT host, tool, tool_version, source_path, sha256, size_bytes,
               acquired_utc, status, error
        FROM evidence WHERE case_id = ? ORDER BY host, tool""",
                        (case_id,)).fetchall()

    table = []
    failures = []
    for host, tool, ver, path, sha, size, acq, status, err in rows:
        table.append([
            host, tool, ver or "not recorded",
            Path(str(path)).name or str(path),
            (sha[:16] + "\u2026") if sha else "not hashed",
            f"{size/1e9:.2f} GB" if size else "",
            acq or "", status or "",
        ])
        if status and status != "ok":
            failures.append((host, tool, status, err or ""))

    out = ["<h2>Evidence</h2>", _table(table,
           ["Host", "Tool", "Version", "Source", "SHA-256", "Size",
            "Acquired (UTC)", "Status"])]

    unhashed = [r for r in rows if not r[4]]
    if unhashed:
        out.append(
            "<div class='warn'><b>Unhashed sources.</b> "
            f"{len(unhashed)} evidence source(s) have no SHA-256. Parsed "
            "output directories are not hashed individually; acquired images "
            "should be. Anything listed above without a hash cannot be shown "
            "to be unchanged since collection.</div>")

    if failures:
        out.append("<h3>Acquisition failures</h3>")
        out.append("<p>These are recorded rather than omitted: a stage that "
                   "failed is a gap in coverage, and a reader needs to know "
                   "which analysis could not be performed.</p>")
        out.append(_table([[h, t, s, e[:160]] for h, t, s, e in failures],
                          ["Host", "Tool", "Status", "Reason"]))
    return "\n".join(out)


def _rulesets():
    """Which rules produced these findings, and at what version.

    Without this a finding cannot be reproduced: public rulesets change
    weekly, so "a YARA rule matched" is not a verifiable claim.
    """
    try:
        from detection.rules_manager import read_manifest
        manifest = read_manifest()
    except ImportError:
        manifest = {}

    out = ["<h2>Detection rulesets</h2>"]
    if not manifest:
        out.append("<p class='meta'>No ruleset manifest. Only the framework's "
                   "own rules were used.</p>")
    else:
        rows = [[n, d.get("version", "?"), d.get("file_rules", 0),
                 d.get("memory_rules", 0), d.get("updated_utc", "?"),
                 (d.get("licence") or "")[:44]]
                for n, d in manifest.items() if not n.startswith("_")]
        out.append(_table(rows, ["Ruleset", "Version", "File rules",
                                 "Memory rules", "Fetched", "Licence"]))
        bad = [f for f, r in (manifest.get("_validation") or {}).items()
               if r != "ok"]
        if bad:
            out.append(f"<div class='warn'><b>{len(bad)} ruleset(s) did not "
                       f"compile</b> and matched nothing: {_e(', '.join(bad))}. "
                       "A ruleset that fails to compile produces zero hits, "
                       "which is indistinguishable from a clean result.</div>")

    try:
        from config import IOC_FEEDS_DIR
        from detection.ioc import load_all
        _data, feeds = load_all(IOC_FEEDS_DIR)
        if feeds:
            out.append("<h3>Threat intelligence feeds</h3>")
            out.append(_table(
                [[f["name"], f.get("dated", "?"),
                  ", ".join(f"{k}={v:,}" for k, v in f.get("counts", {}).items())
                  or "0", f.get("skipped", 0)] for f in feeds],
                ["Feed", "Dated", "Indicators", "Unparsed lines"]))
    except Exception:
        pass

    try:
        from detection.engine import load_rules
        rules = load_rules()
        by_file = Counter(r["_file"] for r in rules)
        out.append("<h3>Internal rules</h3>")
        out.append(_table([[f, n] for f, n in sorted(by_file.items())],
                          ["File", "Rules"]))
    except Exception:
        pass
    return "\n".join(out)


def _scope(case_id, artifact_types):
    """Limitations, GENERATED rather than written from memory.

    This is the section most reports get wrong. "No persistence was found" is
    meaningless unless the reader knows whether persistence artifacts were
    collected at all.
    """
    out = ["<h2>Scope and limitations</h2>"]
    out.append("<p>The rules below could not run: the artifact types they "
               "examine are absent from this case. Each line is a capability "
               "the framework has that was <b>not exercised on this evidence</b>, "
               "and a finding of &ldquo;none&rdquo; from an unrun rule would be "
               "misleading.</p>")

    try:
        from detection.engine import coverage
        cov = coverage(case_id)
    except Exception as e:
        out.append(f"<p class='meta'>Coverage could not be computed: {_e(e)}</p>")
        return "\n".join(out)

    out.append(f"<p class='meta'>{len(cov['runnable'])} rules were applicable; "
               f"{len(cov['blocked'])} were not.</p>")
    if cov.get("not_applicable"):                     # <-- NEW CODE GOES HERE
        out.append(f"<p class='meta'>{len(cov['not_applicable'])} further "
                   f"rule(s) target a different operating system than this "
                   f"case (Linux-only rules on a Windows host, or vice versa) "
                   f"and are excluded from the count above as not applicable, "
                   f"rather than listed as a gap.</p>")
    grouped = defaultdict(list)
    for rid, _title, types in cov["blocked"]:
        grouped[", ".join(types)].append(rid)

    out.append(_table(
        [[types, len(ids), ", ".join(ids[:10]) + (" \u2026" if len(ids) > 10 else "")]
         for types, ids in sorted(grouped.items(), key=lambda kv: -len(kv[1]))],
        ["Artifact type not collected", "Rules blocked", "Rule IDs"]))

    out.append("<h3>Artifact types collected</h3>")
    out.append(f"<p class='mono' style='font-size:12px'>"
               f"{_e(', '.join(artifact_types))}</p>")
    return "\n".join(out)


def _clusters(case_id):
    """Findings grouped by process. The section a reader acts on."""
    try:
        from detection.cluster import clusters, coverage
    except ImportError:
        return ""

    cov = coverage(case_id)
    result = clusters(case_id, min_rules=2)
    total = cov["total_detections"]

    out = ["<h2>Findings by process</h2>"]
    if not total:
        return "\n".join(out + ["<p class='meta'>No detections.</p>"])

    out.append(
        f"<p>Of {total:,} detections, {cov['clustered']:,} carry a process "
        f"identity and are grouped below. The remaining {cov['unclustered']:,} "
        f"come from artifacts with no process association &mdash; registry "
        f"keys, Prefetch, Shimcache, USN records, LNK files, browser history "
        f"&mdash; and appear only in the full telemetry table. No relationship is inferred "
        f"for those: linking them by filename or timestamp proximity would "
        f"assert a connection the evidence does not contain.</p>")

    if cov["processes"] and not cov["guid_backed"]:
        out.append("<div class='warn'><b>Grouped by PID, not ProcessGuid.</b> "
                   "No Sysmon ProcessGuid was available. Operating systems "
                   "recycle PIDs, so on a host with long uptime a single group "
                   "may represent more than one process.</div>")

    if not result["clusters"]:
        out.append("<div class='note'>No process was flagged by more than one "
                   "rule. Findings are scattered rather than converging, which "
                   "argues against a single compromised process.</div>")
        return "\n".join(out)

    out.append("<p class='meta'>Scores sum across <b>distinct rules</b>, not "
               "hits: one rule firing repeatedly on a process is a single "
               "observation repeated, not many findings.</p>")

    for c in result["clusters"][:10]:
        out.append("<div class='cluster'>")
        out.append(f"<h3>PID {_e(c['pid'])} &mdash; {_e(', '.join(c['names']))}"
                   f" <span class='sev' style='color:"
                   f"{SEV_COLOUR.get(c['severity'], '#4a5568')}'>"
                   f"{_e(c['severity'])}</span></h3>")
        out.append(f"<p class='meta'>Aggregate score <b>{c['score']}</b> from "
                   f"{c['rule_count']} distinct rules ({c['hit_count']} hits)"
                   + (f" &nbsp;|&nbsp; {_e(c['first_seen'])} to "
                      f"{_e(c['last_seen'])}" if c["first_seen"] else "")
                   + ("" if c["has_guid"] else
                      " &nbsp;|&nbsp; <i>PID only, may be reused</i>") + "</p>")
        if c["attack"]:
            out.append(f"<p class='meta'>ATT&amp;CK: "
                       f"{_e(' \u2192 '.join(c['attack']))}</p>")
        out.append(_table(
            [[h["timestamp"] or "", h["rule_id"], h["severity"], h["title"],
              (h["matched_on"] or "")[:110]] for h in c["hits"][:15]],
            ["Time (UTC)", "Rule", "Severity", "Finding", "Matched on"],
            sev_col=2))
        out.append("</div>")
    return "\n".join(out)



def _iocs(case_id):
    """Known indicators, kept in its own section.

    An IOC hit is a DIFFERENT KIND of evidence from a behavioural rule. A rule
    says "this resembles technique X". An IOC says "this exact file has been
    seen before, and here is who reported it and when." Presenting them in one
    undifferentiated list would flatten that distinction.
    """
    try:
        from detection.ioc import summary
    except ImportError:
        return ""

    out = ["<h2>Known indicators of compromise</h2>"]

    # WHAT WAS LOADED decides what this section may claim. Reporting "the
    # feeds were applied and nothing matched" when ZERO feeds were configured
    # asserts a negative finding that was never tested -- the exact failure
    # `coverage()` exists to prevent for detection rules, and it must not be
    # repeated here.
    feeds, total_iocs = [], 0
    try:
        from config import IOC_FEEDS_DIR
        from detection.ioc import load_all
        data, feeds = load_all(IOC_FEEDS_DIR)
        total_iocs = sum(len(v) for v in (data.get("iocs") or {}).values())
    except Exception:
        pass

    if not feeds or not total_iocs:
        out.append(
            "<div class='warn'><b>No IOC correlation was performed.</b> "
            "No threat-intelligence feeds were configured, so no artifact was "
            "checked against any known indicator. This is <b>not</b> a finding "
            "of &ldquo;clean&rdquo;: the check did not run. To perform it, "
            "place hash, address or domain lists in the configured feeds "
            "directory and re-run detection.</div>")
        return "\n".join(out)

    rows = summary(case_id)
    loaded = ", ".join(f"{f['name']} ({f.get('dated','?')})" for f in feeds)
    if not rows:
        out.append(
            f"<p>{total_iocs:,} indicator(s) from {len(feeds)} feed(s) "
            f"&mdash; {_e(loaded)} &mdash; were applied across every artifact "
            f"carrying a hash, address or domain. <b>No matches.</b> This is a "
            f"result rather than an absence: the check ran and returned "
            f"nothing.</p>")
        return "\n".join(out)

    out.append("<p>Each hit names the <b>feed and its date</b>. Feeds age "
               "&mdash; an address that was command-and-control in 2024 may be "
               "an ordinary hosting provider now &mdash; so the date is part "
               "of the evidence, not metadata. IMPHASH values are deliberately "
               "excluded from matching: they hash a binary's import table "
               "rather than the binary, and thousands of unrelated files share "
               "one legitimately.</p>")
    out.append(_table([[r[4] or "", r[6], r[0], r[1], r[3], r[2][:110],
                        str(r[5])[:80]] for r in rows],
                      ["Time (UTC)", "Host", "Type", "Severity", "Artifact",
                       "Indicator and source", "Description"], sev_col=3))
    return "\n".join(out)


def _findings(conn, case_id, A, limit_per_rule=25):
    """Every detection, by rule. The complete record behind section 5."""
    rows = conn.execute(f"""
        SELECT d.rule_id, d.rule_title, d.severity, d.engine, COUNT(*)
        FROM detections d JOIN {A} a ON a.id = d.artifact_id
        WHERE a.case_id = ? GROUP BY 1,2,3,4""", (case_id,)).fetchall()

    out = ["<h2>Telemetry &mdash; every rule match</h2>",
           "<p class='meta'>Retained and searchable, not escalated. Only "
           "the Alerts section was surfaced as an alert.</p>"]
    if not rows:
        return "\n".join(out + ["<p class='meta'>No detections.</p>"])

    rows.sort(key=lambda r: (SEV_ORDER.index(r[2]) if r[2] in SEV_ORDER else 9,
                             -r[4]))
    out.append(_table([[r[0], r[2], r[3], r[1], r[4]] for r in rows],
                      ["Rule", "Severity", "Engine", "Title", "Hits"],
                      sev_col=1))

    noisy = [r for r in rows if r[4] > 200]
    if noisy:
        out.append(
            f"<div class='note'><b>{len(noisy)} rule(s) produced more than 200 "
            f"hits.</b> On a workstation that runs development or analysis "
            f"tooling this is usually correct rule behaviour on an unusual "
            f"environment rather than a fault in the rule, but such volume "
            f"should be triaged and excluded before the ruleset is applied to "
            f"other hosts.</div>")

    for rule_id, title, _severity, _engine, n in rows[:12]:
        detail = conn.execute(f"""
            SELECT a.timestamp_utc, a.host, a.artifact_type, a.description,
                   d.matched_on
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ? AND d.rule_id = ?
            ORDER BY a.timestamp_utc LIMIT ?""",
                              (case_id, rule_id, limit_per_rule)).fetchall()
        out.append(f"<h3>{_e(rule_id)} &mdash; {_e(title)} "
                   f"<span class='meta'>({n} hits)</span></h3>")
        out.append(_table([[d[0] or "", d[1], d[2], str(d[3])[:130],
                            str(d[4] or "")[:110]] for d in detail],
                          ["Time (UTC)", "Host", "Artifact", "Description",
                           "Matched on"]))
        if n > limit_per_rule:
            out.append(f"<p class='meta'>Showing {limit_per_rule} of {n}. "
                       f"Full set: <code>python tools/triage.py --case "
                       f"{_e(case_id)} --rule {_e(rule_id)}</code></p>")
    return "\n".join(out)


def _attack(case_id):
    try:
        from mitre import attack_mapper
    except ImportError:
        return ""

    summary = attack_mapper.summary(case_id)
    report = attack_mapper.coverage_report(case_id)

    out = ["<h2>MITRE ATT&amp;CK</h2>"]
    out.append(f"<p>{report['detected']} technique(s) detected across "
               f"{len(report['tactics'])} tactic(s). "
               f"{report['examined_clean']} further technique(s) were "
               f"examinable from the collected artifacts and produced no "
               f"detection.</p>")

    if report.get("unmapped_detections"):
        out.append(
            f"<div class='warn'><b>{report['unmapped_detections']} detection(s) "
            f"carry no ATT&amp;CK identifier</b> and are not represented below. "
            f"They come from {report['unmapped_rules']} rule(s) &mdash; usually "
            f"imported YARA rules, whose metadata carries a reference rather "
            f"than a technique id. They are real findings; the coverage figure "
            f"above would otherwise under-count them.</div>")

    for tactic in sorted(summary):
        out.append(f"<h3>{_e(tactic.replace('-', ' ').title())}</h3>")
        out.append(_table(
            [[tid, tname, info["hits"], info["severity"],
              ", ".join(info["rules"])[:90]]
             for tid, tname, info in summary[tactic]],
            ["Technique", "Name", "Hits", "Severity", "Rules"], sev_col=3))

    out.append("<p class='meta'>Mapping is driven by the ATT&amp;CK "
               "identifiers on the rules that fired. Nothing is inferred from "
               "artifact types: the presence of a scheduled task is not "
               "evidence of persistence, since Windows ships with hundreds.</p>")
    return "\n".join(out)


def _timeline(conn, case_id, A, T, limit=60):
    """Flagged events in order. The narrative, if there is one."""
    if T:
        sql = f"""SELECT t.ts_utc, a.host, a.artifact_type, a.description,
                         d.rule_id, d.severity
                  FROM detections d
                  JOIN {A} a ON a.id = d.artifact_id
                  JOIN {T} t ON t.id = a.id
                  WHERE a.case_id = ? AND t.ts_utc IS NOT NULL
                  ORDER BY t.ts_utc LIMIT ?"""
    else:
        sql = f"""SELECT a.timestamp_utc, a.host, a.artifact_type,
                         a.description, d.rule_id, d.severity
                  FROM detections d JOIN {A} a ON a.id = d.artifact_id
                  WHERE a.case_id = ? AND a.timestamp_utc IS NOT NULL
                  ORDER BY a.timestamp_utc LIMIT ?"""
    try:
        rows = conn.execute(sql, (case_id, limit)).fetchall()
    except Exception:
        rows = []

    out = ["<h2>Timeline of flagged events</h2>"]
    if not rows:
        return "\n".join(out + ["<p class='meta'>No flagged events carry a "
                                "timestamp.</p>"])
    out.append(_table([[r[0], r[1], r[4], r[5], r[2], str(r[3])[:120]]
                       for r in rows],
                      ["Time (UTC)", "Host", "Rule", "Severity", "Artifact",
                       "Description"], sev_col=3))
    out.append("<p class='meta'>All timestamps are UTC. Windows event logs "
               "carry an explicit offset; traditional Linux syslog does not, "
               "and is converted from the host timezone recorded in the "
               "collection.</p>")
    return "\n".join(out)


def _methodology(case_id, host):
    h = f" --host {host}" if host else ""
    return f"""
<h2>Method</h2>
<p>Every stage below is reproducible from the preserved evidence. Detection
runs against the stored artifacts, so the ruleset can be revised and re-applied
without re-acquisition &mdash; the artifact table is written once and never
modified.</p>
<pre class="mono" style="background:#f7fafc;padding:1rem;border-radius:4px;
overflow-x:auto">python main.py acquire  --case {_e(case_id)}{_e(h)} --source C:
python main.py ingest   --case {_e(case_id)}{_e(h)}
python main.py rules    --update
python main.py detect   --case {_e(case_id)}{_e(h)}
python main.py clusters --case {_e(case_id)}
python main.py report   --case {_e(case_id)}</pre>
<p class="meta">Acquisition follows RFC 3227 order of volatility: memory is
captured before disk artifacts, because collecting disk artifacts spawns
processes and writes to the filesystem journal, altering memory.</p>
"""


# --------------------------------------------------------------------------
def _stats(conn, case_id, A):
    def one(sql, params=(case_id,)):
        try:
            return conn.execute(sql, params).fetchone()
        except Exception:
            return None

    artifacts = (one(f"SELECT COUNT(*) FROM {A} WHERE case_id=?") or [0])[0]
    sources = (one("SELECT COUNT(*) FROM evidence WHERE case_id=?") or [0])[0]
    detections = (one(f"""SELECT COUNT(*) FROM detections d
                          JOIN {A} a ON a.id=d.artifact_id
                          WHERE a.case_id=?""") or [0])[0]
    rules_fired = (one(f"""SELECT COUNT(DISTINCT d.rule_id) FROM detections d
                           JOIN {A} a ON a.id=d.artifact_id
                           WHERE a.case_id=?""") or [0])[0]
    try:
        events = conn.execute(f"""SELECT COUNT(*) FROM events e
                                  JOIN {A} a ON a.id=e.artifact_id
                                  WHERE a.case_id=?""", (case_id,)).fetchone()[0]
    except Exception:
        events = artifacts
    rng = one(f"""SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM {A}
                  WHERE case_id=? AND timestamp_utc IS NOT NULL""") or (None, None)
    hosts = [h for (h,) in conn.execute(
        f"SELECT DISTINCT host FROM {A} WHERE case_id=? ORDER BY 1", (case_id,))]
    types = [t for (t,) in conn.execute(
        f"""SELECT artifact_type FROM {A} WHERE case_id=?
            GROUP BY 1 ORDER BY COUNT(*) DESC""", (case_id,))]

    return {"artifacts": artifacts, "events": events, "sources": sources,
            "detections": detections, "rules_fired": rules_fired,
            "range": (rng[0] or "n/a", rng[1] or "n/a"),
            "hosts": hosts, "types": types}
def _alerts(case_id, top=10):
    """Two tiers, answering two different questions.

    ALERTS -- critical findings, grouped by rule. Legitimately EMPTY on a host
    with no adversary activity, and empty is a meaningful answer.

    TRIAGE QUEUE -- highest-scoring processes. ALWAYS returns N rows, so it is
    a RANKING and not a verdict: "start here", not "these are bad". With 800+
    rules loaded, 2,692 processes on this host carry two or more, so any
    threshold we invented would be fitted to evidence containing no attack.
    """
    with connection() as conn:
        A, _T = _view(conn)
        crit = conn.execute(f"""
            SELECT d.rule_id, d.rule_title, COUNT(*),
                   MIN(a.timestamp_utc), MAX(a.timestamp_utc)
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ? AND d.severity = 'critical'
            GROUP BY 1, 2 ORDER BY 3 DESC""", (case_id,)).fetchall()
        total = conn.execute(f"""
            SELECT COUNT(*) FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ?""", (case_id,)).fetchone()[0]
    try:
        from detection.cluster import clusters
        conv = clusters(case_id, min_rules=2)["clusters"][:top]
    except Exception:
        conv = []

    out = ["<h2>Alerts</h2>"]
    if not crit:
        out.append("<div class='note'><b>No critical findings.</b> "
                   f"All {total:,} detections were medium or high confidence "
                   "observations, retained and searchable below. This is a "
                   "<b>result</b>, not a gap in coverage.</div>")
    else:
        out.append(f"<p class='meta'>{sum(r[2] for r in crit):,} critical "
                   f"detections from {len(crit)} rule(s), grouped by rule &mdash; "
                   f"a rule firing 92 times is one observation repeated, not 92 "
                   f"findings.</p>")
        out.append(_table([[r[0], r[1], r[2], r[3] or "", r[4] or ""]
                           for r in crit],
                          ["Rule", "Finding", "Hits", "First (UTC)",
                           "Last (UTC)"]))

    out.append("<h2>Triage queue</h2>")
    out.append(f"<p>The {len(conv)} highest-scoring processes, out of "
               f"{total:,} detections. Score sums across <b>distinct rules</b>: "
               f"one rule firing repeatedly is a single observation repeated, "
               f"while several independent rules on one process is a finding. "
               f"This is a <b>ranking, not a verdict</b> &mdash; it returns the "
               f"top {top} whether or not anything is wrong.</p>")
    if conv:
        out.append(_table(
            [[c["score"], c["rule_count"], c["pid"],
              ", ".join(c["names"])[:60], c["severity"]] for c in conv],
            ["Score", "Rules", "PID", "Process", "Severity"], sev_col=4))
    return "\n".join(out)

def _find_browser():
    """Locate headless Chromium (Edge or Chrome) for PDF rendering."""
    pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    for c in (Path(pf86) / "Microsoft/Edge/Application/msedge.exe",
              Path(pf) / "Microsoft/Edge/Application/msedge.exe",
              Path(pf) / "Google/Chrome/Application/chrome.exe",
              Path(pf86) / "Google/Chrome/Application/chrome.exe"):
        if c.exists():
            return c
    for name in ("msedge", "chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def to_pdf(html_path, pdf_path=None):
    """Render an already-written HTML report to PDF. Returns the path or None.

    WHY A HEADLESS BROWSER AND NOT A PDF LIBRARY
    --------------------------------------------
    The report is already a styled HTML document. The alternatives both cost
    more than they are worth here:

      weasyprint  needs GTK and Pango installed as native Windows libraries,
                  which is a well-known install failure on this platform.
      reportlab   would mean rewriting every section to draw boxes and text
                  by hand -- a SECOND report generator to keep in sync with
                  the first, and the two would drift.

    Edge ships with Windows and renders the exact stylesheet the HTML report
    uses, so the PDF cannot say something different from the HTML. If no
    browser is found this returns None and the HTML report is still written:
    losing the PDF must never lose the report.
    """
    html_path = Path(html_path)
    pdf_path = Path(pdf_path or html_path.with_suffix(".pdf"))

    browser = _find_browser()
    if browser is None:
        log.warning("no Edge/Chrome found, PDF skipped -- the HTML report at "
                    "%s can still be printed to PDF from any browser (Ctrl+P)",
                    html_path)
        return None

    # --print-to-pdf-no-header suppresses the browser's own banner, which
    # otherwise stamps a local file path and today's date across every page
    # of what is meant to be an evidentiary document.
    cmd = [str(browser), "--headless", "--disable-gpu", "--no-sandbox",
           "--print-to-pdf-no-header",
           f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("PDF render failed (%s); the HTML report is unaffected", e)
        return None

    if r.returncode != 0 or not pdf_path.exists():
        log.warning("PDF render failed (exit %s): %s", r.returncode,
                    r.stderr.decode(errors="replace")[:300])
        return None

    log.info("PDF written: %s (%.0f KB)", pdf_path,
             pdf_path.stat().st_size / 1024)
    return pdf_path


def generate(case_id, out_path, analyst="unspecified", host=None, pdf=False):
    """Write the report. Returns the path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with connection() as conn:
        A, T = _view(conn)
        stats = _stats(conn, case_id, A)
        if not stats["artifacts"]:
            log.warning("no artifacts for case %s -- report will be empty",
                        case_id)

        body = "\n".join([
            _header(case_id, analyst, stats),
            _alerts(case_id),
            _evidence(conn, case_id),
            _rulesets(),
            _scope(case_id, stats["types"]),
            _clusters(case_id),
            _iocs(case_id),
            _findings(conn, case_id, A),
            _attack(case_id),
            _timeline(conn, case_id, A, T),
            _methodology(case_id, host or (stats["hosts"][0]
                                           if stats["hosts"] else None)),
        ])

    doc = (f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
           f"<title>{_e(case_id)} \u2014 DFIR report</title>"
           f"<style>{CSS}</style></head><body>{body}"
           f"<footer>Generated by MiniDFIR. Findings are produced by rules; "
           f"each carries the rule identifier and the field value that matched, "
           f"so a reader can evaluate the reasoning rather than trust the tool."
           f"</footer></body></html>")

    out_path.write_text(doc, encoding="utf-8")
    log.info("report written: %s (%d artifacts, %d detections, %d hosts)",
             out_path, stats["artifacts"], stats["detections"],
             len(stats["hosts"]))

    # The HTML is written FIRST and unconditionally. The PDF is a rendering of
    # it, so a browser that is missing or fails costs you the PDF, never the
    # report itself.
    if pdf:
        to_pdf(out_path)

    return out_path