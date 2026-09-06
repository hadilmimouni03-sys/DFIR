import argparse
import logging
import sys
from pathlib import Path
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import evidence_dir, output_dir  # noqa: E402


# --------------------------------------------------------------------------
# logging: console for you, file for the report appendix
# --------------------------------------------------------------------------
def setup_logging(case_id=None, verbose=False):
    """Two handlers on purpose.

    Console is for the human watching. The per-case file is the audit trail:
    what ran, when, with what result. "Memory acquisition failed: insufficient
    disk" is a FINDING that belongs in the report, not a message that scrolls
    past and is lost.
    """
    handlers = [logging.StreamHandler(sys.stdout)]
    if case_id:
        out = Path(output_dir(case_id))
        out.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(out / "minidfir.log", encoding="utf-8"))

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-26s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,        # replace any config a library already installed
    )


# --------------------------------------------------------------------------
# stages
# --------------------------------------------------------------------------
def cmd_init(args):
    from database.database import init_db
    init_db()
    print("database initialised")


def cmd_acquire(args):
    """Windows acquisition. MEMORY FIRST -- RFC 3227 order of volatility.

    Collecting disk artifacts runs processes, opens files and writes to the
    journal, all of which perturbs memory. Memory is the most volatile thing
    you can collect, so it goes first. This ordering is a forensic requirement,
    not a preference, and putting it in code is how you guarantee it.

    If memory fails we do NOT abort. We record WHY in the evidence table and
    carry on with disk -- a partial acquisition with a documented gap is worth
    far more than no acquisition.
    """
    from acquisition.windows.kape_runner import reparse_usn, run_kape
    from acquisition.windows.volatility_runner import run_volatility
    from acquisition.windows.winpmem_runner import acquire_memory

    log = logging.getLogger("acquire")
    base = evidence_dir(args.case, args.host, "windows")
    results = {}

    if args.skip_memory:
        log.info("--skip-memory given, going straight to disk")
        mem = {"ok": False, "stderr": "skipped by operator"}
    else:
        log.info("=== stage 1/3: memory (most volatile first) ===")
        mem = acquire_memory(args.case, args.host, dry_run=args.dry_run,
                             min_free_gb=args.min_free_gb)
    results["memory"] = mem

    if mem.get("ok") and mem.get("path"):
        log.info("=== stage 2/3: memory analysis ===")
        results["volatility"] = run_volatility(
            mem["path"], base / "volatility", case_id=args.case,
            host=args.host, os_name="windows", plugin_set=args.plugin_set,
            dry_run=args.dry_run)
    else:
        log.warning("skipping memory analysis: %s",
                    mem.get("stderr", "no dump produced"))

    log.info("=== stage 3/3: disk triage ===")
    kape = run_kape(args.case, args.host, args.source, target=args.target,
                    module=args.module, dry_run=args.dry_run)
    results["kape"] = kape

    if kape.get("ok"):
        # KAPE's !EZParser runs MFTECmd against $J WITHOUT the $MFT, so parent
        # directory paths stay unresolved and no path-based rule can fire on
        # filesystem events. Re-parse supplying the MFT.
        results["reparse_usn"] = reparse_usn(args.case, args.host,
                                             dry_run=args.dry_run)

    failed = [k for k, v in results.items() if isinstance(v, dict)
              and v.get("ok") is False]
    if failed:
        log.warning("stages that failed: %s -- the reason is recorded in the "
                    "evidence table and belongs in the report", ", ".join(failed))
    return results


def cmd_acquire_linux(args):
    """Same order of volatility: memory, then disk."""
    log = logging.getLogger("acquire")

    if args.avml:
        log.info("=== stage 1/2: memory ===")
        from acquisition.linux.avml_runner import acquire_memory
        mem = acquire_memory(args.case, args.host, args.avml,
                             dry_run=args.dry_run, min_free_gb=args.min_free_gb,
                             compress=args.compress)
        if not mem.get("ok"):
            log.warning("memory acquisition failed: %s", mem.get("stderr"))
            log.warning("run tools/check_isf.py: without kernel debug symbols "
                        "for this exact build, a dump cannot be analysed anyway")
    else:
        log.info("no --avml given, skipping memory acquisition")

    log.info("=== stage 2/2: disk artifacts ===")
    from acquisition.linux.uac_runner import run_uac
    return run_uac(args.case, args.host, args.uac, profile=args.profile,
                   dry_run=args.dry_run)


def cmd_ingest(args):
    """Parse collected evidence into the database.

    Which platform runs is decided by WHAT IS ON DISK, not by a flag. Fewer
    arguments to get wrong, and a mixed case just works.

    Safe to re-run: each ingestor calls clear_source() first, so fixing a spec
    and re-ingesting replaces the old rows instead of duplicating them.
    """
    log = logging.getLogger("ingest")
    did_something = False

    lnx = evidence_dir(args.case, args.host, "linux")
    if lnx.exists():
        from ingestion.uac_ingestor import ingest_uac
        raw = lnx / "raw"
        archives = sorted(raw.glob("uac-*.tar.gz")) if raw.exists() else []
        target = archives[0] if archives else (raw if raw.exists() else None)
        if target:
            ingest_uac(target, args.case, args.host)
            did_something = True
        if (lnx / "volatility").exists():
            from ingestion.volatility_ingestor import ingest_volatility
            ingest_volatility(lnx / "volatility", args.case, args.host)

    win = evidence_dir(args.case, args.host, "windows")
    parsed = _latest(win / "parsed")
    if parsed:
        from ingestion.kape_ingestor import ingest_folder
        ingest_folder(parsed, args.case, args.host, include_mft=args.include_mft)
        did_something = True

    raw = _latest(win / "raw")
    if raw:
        from ingestion.browser_ingestor import ingest_browsers
        ingest_browsers(raw, args.case, args.host)

    if (win / "volatility").exists():
        from ingestion.volatility_ingestor import ingest_volatility
        ingest_volatility(win / "volatility", args.case, args.host)
        did_something = True

    if not did_something:
        log.error("nothing to ingest under %s or %s", win, lnx)
        return

    cmd_stats(args)


def _latest(parent):
    """Acquisition writes to <parent>/<UTC stamp>/ so re-running never mixes
    two collections. Pick the newest. Falls back to the directory itself for
    evidence that was placed there by hand."""
    parent = Path(parent)
    if not parent.is_dir():
        return None
    runs = sorted((p for p in parent.iterdir() if p.is_dir()),
                  key=lambda p: p.name)
    return runs[-1] if runs else (parent if any(parent.iterdir()) else None)


def cmd_detect(args):
    """Run rules over stored artifacts. Seconds, and never touches evidence.

    This is the stage you will run fifty times. Each run clears the previous
    pass and starts fresh, so results always reflect the CURRENT ruleset.
    """
    log = logging.getLogger("detect")

    # a ruleset that fails to compile matches NOTHING, which looks exactly
    # like a clean machine -- so this warning has to be loud
    try:
        from detection.rules_manager import read_manifest
        bad = [f for f, r in (read_manifest().get("_validation") or {}).items()
               if r != "ok"]
        if bad:
            log.error("these rulesets do NOT compile and will silently match "
                      "nothing: %s", ", ".join(bad))
    except ImportError:
        pass

    from detection import engine
    engine.run(args.case, rules_dir=args.rules, host=args.host)

    try:
        from detection import correlate
        correlate.run_all(args.case, minutes=args.window)
    except ImportError:
        log.info("detection/correlate.py not present, skipping correlations")

    # IOC correlation is a detection pass like any other, so it lives behind
    # the same command rather than one more thing to remember.
    if not args.no_ioc:
        try:
            from detection import ioc
            result = ioc.run(args.case, host=args.host)
            if result["sources"]:
                log.info("IOC feeds applied: %s",
                         ", ".join(f"{x['name']} ({x.get('dated','?')})"
                                   for x in result["sources"]))
        except ImportError:
            log.info("detection/ioc.py not present, skipping IOC correlation")

    if args.yara and args.host:
        try:
            from detection.yara_scanner import scan_directory
            for os_name in ("windows", "linux"):
                raw = _latest(evidence_dir(args.case, args.host, os_name) / "raw")
                if raw:
                    scan_directory(args.case, args.host, raw)
        except ImportError as e:
            log.info("file YARA scan skipped: %s", e)

    print("\n  review:     python tools/triage.py --case " + args.case)
    print("  by process: python main.py clusters --case " + args.case)


def cmd_rules(args):

    from detection import rules_manager

    if args.status:
        rules_manager.status()
        return
    if args.validate:
        results = rules_manager.validate()
        if not results:
            print("yara-python not installed; cannot verify rulesets compile.")
            return
        for f, r in results.items():
            print(f"  [{'ok  ' if r == 'ok' else 'FAIL'}] {f}")
            if r != "ok":
                print(f"         {r}")
        return

    rules_manager.update(names=args.ruleset, fetch_remote=not args.no_fetch,
                         max_memory_rules=args.max_memory_rules,
                         translate=args.translate, verify_case=args.verify, refresh=args.refresh)
    print()
    rules_manager.status()
    if args.translate:
        print("\n  read the refusals before trusting the import:")
        print("    rules/sigma_refused.txt")
        print("  then re-validate:")
        print("    python -c \"from detection.engine import validate_rules; "
              "print(len(validate_rules()), 'valid')\"")


def cmd_register_memory(args):
    """Record an evidence row for a dump acquired outside the framework.

    The realistic Linux workflow: run avml over SSH, scp the image across, and
    the database knows nothing about it. This hashes the file and registers
    it, so chain of custody survives the manual path. If a .sha256 sidecar was
    written on the target it is compared -- a 4 GB scp can truncate silently.
    """
    from acquisition.linux.avml_runner import register_dump
    return register_dump(args.case, args.host, args.dump,
                         acquired_utc=args.acquired)


def cmd_clusters(args):
    """Group detections by process.

    A VIEW, not a detection pass: it reads `detections` and groups them, so it
    can be re-run after any tuning change and never needs clearing.
    """
    from detection.cluster import show
    show(args.case, host=args.host, top=args.top,
         min_rules=args.min_rules, verbose=args.verbose)


def cmd_coverage(args):
    """Which rules CAN fire against this evidence, without running them.

    A rule that ran and found nothing is a RESULT. A rule with nothing to scan
    is a COLLECTION GAP. Mistaking the second for the first is how you report
    a clean machine you never examined.
    """
    from collections import defaultdict

    from detection.engine import coverage
    cov = coverage(args.case)
    print(f"\n  artifact types present:     {len(cov['artifact_types_present'])}")
    print(f"  rules that CAN fire:        {len(cov['runnable'])}")
    print(f"  rules with NOTHING to scan: {len(cov['blocked'])}\n")

    grouped = defaultdict(list)
    for rid, _title, types in cov["blocked"]:
        grouped[", ".join(types)].append(rid)
    for types, ids in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(ids):>3} rules need: {types[:56]}")
        print(f"       {', '.join(ids[:10])}{' ...' if len(ids) > 10 else ''}")

    print("\n  This IS the report's limitations section: each line is a")
    print("  capability the framework has that this evidence did not exercise.")



def cmd_stats(args):
    from database.database import stats
    s = stats(args.case)
    print(f"\n  evidence sources  {s.get('evidence', 0):>10,}")
    print(f"  artifacts         {s['artifacts']:>10,}")
    print(f"  timeline events   {s['events']:>10,}")
    print(f"  no timestamp      {s['no_timestamp']:>10,}   <- invisible in the timeline")
    print(f"  noise (hidden)    {s['noise']:>10,}")
    print(f"  detections        {s['detections']:>10,}")
    print(f"  span              {s['range'][0]}  ..  {s['range'][1]}")
    print("\n  artifact_type                        count")
    for t, n in s["by_type"][:30]:
        print(f"  {t:<36} {n:>8,}")


def cmd_timeline(args):
    from timeline.timeline_builder import get_timeline, show
    rows = get_timeline(args.case, layer=args.layer, host=args.host,
                        keyword=args.keyword, artifact_type=args.type,
                        flagged_only=args.flagged, limit=args.limit)
    show(rows)
    print(f"\n{len(rows):,} rows")


def cmd_report(args):
    out = Path(output_dir(args.case))
    from timeline.timeline_builder import export_csv, export_html

    export_html(args.case, out / "timeline.html",
                title=f"DFIR Timeline - {args.case}")
    export_csv(args.case, out / "timeline.csv",
               hide_noise=not args.include_noise)

    try:
        from mitre.attack_mapper import navigator_layer
        navigator_layer(args.case, out / "attack_navigator_layer.json")
    except ImportError:
        pass

    from reporting.report_generator import generate
    path = generate(args.case, out / "report.html", analyst=args.analyst,
                    host=args.host, pdf=args.pdf)
    print(f"\nreport: {path}")
    if args.pdf and path.with_suffix(".pdf").exists():
        print(f"pdf:    {path.with_suffix('.pdf')}")

    print(f"folder: {out}")


def cmd_pipeline(args):
    """Run the full chain in one process: acquire -> ingest -> detect -> report.

    WHY IN-PROCESS AND NOT SUBPROCESS CALLS
    ---------------------------------------
    Each stage below is the same function `main.py <stage>` would call. Doing
    it in-process means one database connection, one log file, and a real
    Python traceback when something breaks -- instead of an exit code and a
    guess. The only thing this adds over running the four commands by hand is
    STOP ON FAILURE: ingesting after a half-finished acquisition would build a
    case from partial evidence, and every later stage would look successful
    while analysing garbage.
    """
    log = logging.getLogger("pipeline")
    ns = argparse.Namespace

    stages = [
        ("acquire", cmd_acquire, ns(
            case=args.case, host=args.host, source=args.source,
            target="!SANS_Triage,Browsers", module="!EZParser",
            plugin_set=args.plugin_set, min_free_gb=args.min_free_gb,
            skip_memory=args.skip_memory, dry_run=False)),
        ("ingest", cmd_ingest, ns(
            case=args.case, host=args.host, include_mft=args.include_mft)),
        ("detect", cmd_detect, ns(
            case=args.case, host=args.host, rules=None, window=args.window,
            yara=args.yara, no_ioc=args.no_ioc)),
        ("report", cmd_report, ns(
            case=args.case, host=args.host, analyst=args.analyst,
            include_noise=False, pdf=args.pdf)),
    ]

    skip = set(args.skip or [])
    for name, fn, stage_args in stages:
        if name in skip:
            log.info("-- skipping %s (--skip %s)", name, name)
            continue
        log.info("%s\n== %s\n%s", "=" * 70, name.upper(), "=" * 70)
        started = time.time()
        try:
            fn(stage_args)
        except Exception:
            log.exception("stage %r failed -- stopping here. Fix the problem, "
                          "then re-run with --skip for the stages that "
                          "already completed.", name)
            return 1
        log.info("-- %s ok, %.0fs", name, time.time() - started)

    print(f"\nreport: {output_dir(args.case)}/report.html")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="minidfir", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    def case_args(sp, host_required=False):
        sp.add_argument("--case", required=True, help="case id, e.g. IR-2026-014")
        sp.add_argument("--host", required=host_required)

    sub.add_parser("init", help="create the database").set_defaults(
        func=cmd_init, case=None)

    rl = sub.add_parser("rules", help="fetch and manage detection rulesets")
    rl.add_argument("--ruleset", nargs="*", default=None)
    rl.add_argument("--status", action="store_true")
    rl.add_argument("--validate", action="store_true")
    rl.add_argument("--no-fetch", action="store_true",
                    help="re-triage what is downloaded, do not pull")
    rl.add_argument("--max-memory-rules", type=int, default=None,
                    help="cap the memory ruleset. Default: NO CAP. YARA makes "
                         "one pass regardless of rule count, so a cap saves "
                         "little and risks dropping the rule that mattered.")
    rl.add_argument("--refresh", action="store_true",
                    help="pull upstream updates. Without this an already-"
                         "cloned ruleset is reused: the version is pinned in "
                         "the manifest, so re-cloning is minutes of network "
                         "for no benefit -- and a version that changes "
                         "silently means a finding from last week cannot be "
                         "reproduced")
 
    rl.add_argument("--translate", action="store_true",
                    help="also translate Sigma rules into "
                         "rules/yaml/sigma_derived.yaml")
    rl.add_argument("--verify", metavar="CASE",
                    help="verify translated rules against a real case; a rule "
                         "whose fields appear in no artifact is NOT written, "
                         "because it would scan normally and report zero")
    rl.set_defaults(func=cmd_rules, case=None)
    a = sub.add_parser("acquire", help="collect evidence (Windows)")
    case_args(a, host_required=True)
    a.add_argument("--source", required=True, help="volume or image, e.g. C:")
    a.add_argument("--target", default="!SANS_Triage,Browsers")
    a.add_argument("--module", default="!EZParser")
    a.add_argument("--plugin-set", default="core",
                   help="core | context | all | comma-separated")
    a.add_argument("--min-free-gb", type=float, default=None,
                   help="refuse to dump memory below this much free space")
    a.add_argument("--skip-memory", action="store_true")
    a.add_argument("--dry-run", action="store_true",
                   help="print the exact commands without running them")
    a.set_defaults(func=cmd_acquire)

    al = sub.add_parser("acquire-linux", help="collect evidence (Linux)")
    case_args(al, host_required=True)
    al.add_argument("--uac", required=True, help="path to the uac script")
    al.add_argument("--avml", help="path to avml (omit to skip memory)")
    al.add_argument("--profile", default="ir_triage")
    al.add_argument("--compress", action="store_true",
                    help="snappy-compress the image; Volatility reads it directly")
    al.add_argument("--min-free-gb", type=float, default=None)
    al.add_argument("--dry-run", action="store_true")
    al.set_defaults(func=cmd_acquire_linux)

    rm = sub.add_parser("register-memory",
                        help="record a dump acquired outside the framework")
    case_args(rm, host_required=True)
    rm.add_argument("--dump", required=True, help="path to the .lime or .raw")
    rm.add_argument("--acquired", help="acquisition time, ISO 8601 UTC")
    rm.set_defaults(func=cmd_register_memory)

    i = sub.add_parser("ingest", help="parse evidence into the database")
    case_args(i, host_required=True)
    i.add_argument("--include-mft", action="store_true",
                   help="ingest $MFT: large, but required for T1070.006")
    i.set_defaults(func=cmd_ingest)

    d = sub.add_parser("detect", help="run detection rules")
    case_args(d)
    d.add_argument("--rules", default=None, help="override the rules directory")
    d.add_argument("--window", type=int, default=60,
                   help="download->execute correlation window, minutes")
    d.add_argument("--yara", action="store_true", help="also scan files with YARA")
    d.add_argument("--no-ioc", action="store_true",
                   help="skip IOC correlation (useful while tuning rules)")
    d.set_defaults(func=cmd_detect)

    cl = sub.add_parser("clusters", help="group detections by process")
    case_args(cl)
    cl.add_argument("--top", type=int, default=15)
    cl.add_argument("--min-rules", type=int, default=2,
                    help="hide processes flagged by fewer distinct rules")
    cl.add_argument("--verbose", action="store_true")
    cl.set_defaults(func=cmd_clusters)

    cv = sub.add_parser("coverage", help="which rules can fire on this evidence")
    case_args(cv)
    cv.set_defaults(func=cmd_coverage)

    s = sub.add_parser("stats", help="database health after ingest")
    case_args(s)
    s.set_defaults(func=cmd_stats)

    t = sub.add_parser("timeline", help="query the timeline")
    case_args(t)
    t.add_argument("--layer", help="execution | persistence | files | logs | ...")
    t.add_argument("--type", help="filter by artifact_type")
    t.add_argument("--keyword", help="substring search in the description")
    t.add_argument("--flagged", action="store_true", help="only rows with detections")
    t.add_argument("--limit", type=int, default=100)
    t.set_defaults(func=cmd_timeline)

    r = sub.add_parser("report", help="generate the report and exports")
    case_args(r)
    r.add_argument("--analyst", default="unspecified")
    r.add_argument("--include-noise", action="store_true")
    # PDF IS THE DEFAULT. The PDF is what gets attached to a ticket, mailed
    # to a supervisor or handed in; the HTML is the working copy. --no-pdf
    # exists for fast iteration while tuning rules, when rendering 20 pages
    # on every run is pure waste.
    r.add_argument("--no-pdf", dest="pdf", action="store_false",
                   help="skip the PDF and write only report.html. The HTML is "
                        "always written first, so a missing browser costs you "
                        "the PDF, never the report.")
    r.set_defaults(func=cmd_report)
    pl = sub.add_parser("pipeline",
                        help="acquire -> ingest -> detect -> report, one command")
    case_args(pl, host_required=True)
    pl.add_argument("--source", required=True)
    pl.add_argument("--analyst", default="unspecified")
    pl.add_argument("--plugin-set", default="core")
    pl.add_argument("--min-free-gb", type=float, default=None)
    pl.add_argument("--skip-memory", action="store_true")
    pl.add_argument("--include-mft", action="store_true")
    pl.add_argument("--window", type=int, default=60)
    pl.add_argument("--yara", action="store_true")
    pl.add_argument("--no-ioc", action="store_true")
    pl.add_argument("--no-pdf", dest="pdf", action="store_false",
                    help="skip the PDF at the report stage")
    pl.add_argument("--skip", nargs="*",
                    choices=["acquire", "ingest", "detect", "report"],
                    help="stages already done, e.g. --skip acquire ingest")
    pl.set_defaults(func=cmd_pipeline)

    cp = sub.add_parser("compare", help="diff detections between two cases")
    case_args(cp)
    cp.add_argument("--baseline", required=True, help="the clean case, e.g. CASE01")
    cp.set_defaults(func=cmd_compare)
    return p

def cmd_compare(args):
    """Diff two cases rule-by-rule: same host, different point in time.

    A rule firing about equally on both is describing the ENVIRONMENT.
    A rule firing only on one is describing what changed between them.
    """
    from database.database import connection
    with connection() as conn:
        rows = conn.execute("""
            SELECT d.rule_id, d.rule_title,
                   SUM(a.case_id = ?) AS a_count,
                   SUM(a.case_id = ?) AS b_count
            FROM detections d JOIN v_artifacts a ON a.id = d.artifact_id
            WHERE a.case_id IN (?, ?)
            GROUP BY 1, 2 ORDER BY (b_count - a_count) DESC""",
            (args.baseline, args.case, args.baseline, args.case)).fetchall()

    if not rows:
        print(f"no detections for {args.baseline!r} or {args.case!r}")
        return 1

    more    = [r for r in rows if r[3] > r[2]]
    same    = [r for r in rows if r[2] and r[3] == r[2]]
    fewer   = [r for r in rows if r[2] and r[3] < r[2]]

    print(f"\n{'='*74}\n{args.baseline} vs {args.case}\n{'='*74}")
    print(f"\n  FIRED MORE on {args.case} ({len(more)} rule(s)):")
    for rid, title, a, b in more[:20]:
        print(f"    +{b-a:<5} {rid:<24} {str(title)[:42]}")
    print(f"\n  IDENTICAL on both -- environmental ({len(same)} rule(s)):")
    for rid, title, a, b in same[:10]:
        print(f"     {a:<5} {rid:<24} {str(title)[:42]}")
    if fewer:
        print(f"\n  FIRED FEWER ({len(fewer)} rule(s)) -- a rule cannot fire")
        print(f"  LESS because you ADDED an attack. A non-trivial list here")
        print(f"  means the two acquisitions are not a matched pair, only two")
        print(f"  snapshots of the same host at different times. Use the")
        print(f"  simulation's marker validation as ground truth instead.")
        for rid, title, a, b in fewer[:10]:
            print(f"    -{a-b:<5} {rid:<24} {str(title)[:42]}")
    return 0


def main():
    args = build_parser().parse_args()
    setup_logging(getattr(args, "case", None), args.verbose)
    try:
        args.func(args)
    except KeyboardInterrupt:
        logging.getLogger("main").warning("interrupted by operator")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())