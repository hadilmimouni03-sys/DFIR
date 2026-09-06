#!/usr/bin/env python3
"""Verify every wiring point in the framework.

    python tools/selfcheck.py

Reads nothing from the database and writes nothing. It answers one question:
IS EVERY PIECE CONNECTED TO EVERY OTHER PIECE?

WHY THIS EXISTS
---------------
Most failures in this framework are not crashes. They are SILENCE:

    a plugin runs and its output has no VOL_SPECS key   -> zero artifacts
    an artifact type is in no timeline LAYER            -> invisible on the timeline
    a rule scopes to a type nothing produces            -> can never fire
    a technique has no name in the mapper               -> a bare id in the report
    a ruleset fails to compile                          -> zero YARA hits

Every one of those looks exactly like a clean machine. This checks the joins
rather than the parts, because the parts individually work.
"""
import ast
import importlib
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

problems, warnings = [], []


def section(title):
    print(f"\n{'='*72}\n{title}\n{'='*72}")


def ok(label, detail=""):
    print(f"  [ ok ] {label}" + (f"\n         {detail}" if detail else ""))


def fail(label, detail=""):
    problems.append(label)
    print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


def warn(label, detail=""):
    warnings.append(label)
    print(f"  [warn] {label}" + (f"\n         {detail}" if detail else ""))


# =====================================================================
section("1. MODULES IMPORT")
# =====================================================================
MODULES = [
    "config", "database.database", "database.schema",
    "normalization.normalizer", "normalization.specs",
    "normalization.linux_specs", "normalization.linux_vol_specs",
    "ingestion.kape_ingestor", "ingestion.uac_ingestor",
    "ingestion.volatility_ingestor", "ingestion.browser_ingestor",
    "detection.engine", "detection.correlate", "detection.cluster",
    "detection.ioc", "detection.rules_manager", "detection.yara_scanner",
    "mitre.attack_mapper", "timeline.timeline_builder",
    "reporting.report_generator",
    "acquisition.run_tool", "acquisition.windows.volatility_runner",
]
loaded = {}
for name in MODULES:
    try:
        loaded[name] = importlib.import_module(name)
        ok(name)
    except Exception as e:
        fail(name, f"{type(e).__name__}: {e}")

if "config" not in loaded:
    print("\nCannot continue without config.")
    sys.exit(1)

cfg = loaded["config"]


# =====================================================================
section("2. CONFIG CONSTANTS")
# =====================================================================
REQUIRED_CFG = [
    ("DATABASE_PATH", "where the database lives"),
    ("EVIDENCE_ROOT", "evidence tree root"),
    ("DETECTION_RULES_DIR", "YAML rules -- engine.load_rules reads this"),
    ("YARA_RULES_DIR", "yara_scanner and rules_manager read this"),
    ("IOC_FEEDS_DIR", "ioc.run reads this"),
    ("VOLATILITY_CMD", "volatility_runner"),
    ("VOLATILITY_SYMBOLS_DIR", "-s flag; without it vol3 downloads symbols"),
    ("BATCH_SIZE", "insert batching"),
    ("MAX_YARA_FILE_MB", "yara_scanner file size cap"),
]
for name, why in REQUIRED_CFG:
    if hasattr(cfg, name):
        value = getattr(cfg, name)
        exists = ""
        if isinstance(value, Path):
            exists = f"  (exists: {value.exists()})"
        ok(f"{name}{exists}")
    else:
        fail(f"config.{name} missing", why)

for name in ("PLUGIN_TIMEOUT", "YARA_TIMEOUT", "MEMORY_TIMEOUT"):
    if not hasattr(cfg, name):
        warn(f"config.{name} missing",
             "the module defines a fallback, but tuning it means editing code")

for name in ("WINPMEM_VERSION", "VOLATILITY_VERSION"):
    if not hasattr(cfg, name):
        warn(f"config.{name} missing",
             "tool_version would be derived by guessing a --version flag, "
             "which once produced an invented value in a chain-of-custody field")


# =====================================================================
section("3. DATABASE API")
# =====================================================================
db = loaded.get("database.database")
if db:
    REQUIRED_FN = {
        "connection": [],
        "init_db": [],
        "register_evidence": ["case_id", "host"],
        "insert_artifacts": [],
        "insert_detections": [],
        "clear_detections": ["case_id"],
        "clear_source": [],
        "stats": ["case_id"],
    }
    for fn_name, expected_args in REQUIRED_FN.items():
        fn = getattr(db, fn_name, None)
        if fn is None:
            fail(f"database.{fn_name}() missing")
            continue
        try:
            params = list(inspect.signature(fn).parameters)
        except (TypeError, ValueError):
            params = []
        missing = [a for a in expected_args if a not in params]
        if missing:
            fail(f"database.{fn_name}() missing parameter(s) {missing}")
        else:
            ok(f"database.{fn_name}({', '.join(params[:4])}{'...' if len(params) > 4 else ''})")

    # clear_detections must accept engine=, or ioc/correlation passes would
    # wipe each other's results
    cd = getattr(db, "clear_detections", None)
    if cd and "engine" not in inspect.signature(cd).parameters:
        fail("clear_detections() has no engine= parameter",
             "each engine (internal, correlation, ioc, yara) clears only its "
             "own rows; without this, one pass wipes another's results")


# =====================================================================
section("4. SPECS -- are the Linux tables merged?")
# =====================================================================
specs = loaded.get("normalization.specs")
if specs:
    vol = getattr(specs, "VOL_SPECS", {})
    primary = getattr(specs, "PRIMARY_TS", {})
    linux_vol = [k for k in vol if k.startswith("linux_")]

    ok(f"VOL_SPECS: {len(vol)} entries ({len(linux_vol)} Linux)")
    if not linux_vol:
        fail("no linux_* keys in VOL_SPECS",
             "add to specs.py:\n"
             "         from normalization.linux_vol_specs import (\n"
             "             LINUX_VOL_PRIMARY_TS, LINUX_VOL_SPECS)\n"
             "         VOL_SPECS.update(LINUX_VOL_SPECS)\n"
             "         PRIMARY_TS.update(LINUX_VOL_PRIMARY_TS)\n"
             "         Without it those plugins run, write JSON, and produce "
             "ZERO artifacts with no error.")

    lspecs = loaded.get("normalization.linux_specs")
    if lspecs:
        n = len(getattr(lspecs, "LINUX_SPECS", []))
        ok(f"LINUX_SPECS: {n} dispatch globs")
        if n < 40:
            warn(f"only {n} globs -- the merged file has ~57",
                 "an unmerged linux_extra.py leaves auditd, package logs, "
                 "journald, persistence files and Trash unreachable")

    # every plugin must have a spec, or its output is silently discarded
    lvs = loaded.get("normalization.linux_vol_specs")
    if lvs:
        plugins = {**getattr(lvs, "LINUX_PLUGINS", {}),
                   **getattr(lvs, "LINUX_MALWARE_PLUGINS", {})}
        orphans = [k for k in plugins if k not in vol]
        if orphans:
            fail(f"{len(orphans)} plugin(s) have no VOL_SPECS entry",
                 f"{orphans[:6]} -- they run, write <key>.json, and yield "
                 f"nothing")
        else:
            ok(f"all {len(plugins)} Linux plugins have a spec")

    # duplicate PRIMARY_TS keys: the last silently wins
    try:
        src = Path(specs.__file__).read_text(encoding="utf-8")
        import re
        block = re.search(r"PRIMARY_TS = \{(.*?)\n\}", src, re.S)
        if block:
            from collections import Counter
            keys = re.findall(r'^\s*"(\w+)":', block.group(1), re.M)
            dupes = [k for k, c in Counter(keys).items() if c > 1]
            if dupes:
                fail(f"duplicate PRIMARY_TS keys: {dupes}",
                     "the LAST wins, so the timestamp you chose is silently "
                     "overridden and min(timestamps) is used instead")
            else:
                ok("no duplicate PRIMARY_TS keys")
    except Exception:
        pass

    # the _mz newline bug: MDF-0009 cannot fire without this
    mz = getattr(specs, "_mz", None)
    if mz:
        if mz({"Hexdump": "\n4d 5a 90 00"}) and not mz({"Hexdump": "\n90 90"}):
            ok("_mz() strips Volatility's leading newline")
        else:
            fail("_mz() returns False on a real MZ header",
                 "MDF-0009 CANNOT FIRE, and that looks identical to a clean "
                 "machine. Strip \\n \\r \\t as well as spaces.")


# =====================================================================
section("5. RULES")
# =====================================================================
engine = loaded.get("detection.engine")
rules = []
if engine:
    try:
        rules = engine.validate_rules()
        ok(f"{len(rules)} rules compile")
        from collections import Counter
        for f, n in sorted(Counter(r["_file"] for r in rules).items()):
            print(f"           {f:<26} {n:>3}")
    except Exception as e:
        fail("rule validation failed", str(e)[:200])

    if rules:
        no_attack = [r["id"] for r in rules if not r.get("attack")]
        if no_attack:
            warn(f"{len(no_attack)} rule(s) carry no ATT&CK id",
                 f"{no_attack[:8]} -- their findings cannot be placed on the "
                 f"matrix")
        else:
            ok("every rule carries an ATT&CK id")


# =====================================================================
section("6. ATT&CK MAPPER")
# =====================================================================
mapper = loaded.get("mitre.attack_mapper")
if mapper and rules:
    named = set(getattr(mapper, "TECHNIQUES", {}))
    used = {t.upper() for r in rules for t in r.get("attack", [])}

    # correlations and YARA meta reference techniques too
    corr = loaded.get("detection.correlate")
    if corr:
        import re
        used |= set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"',
                               Path(corr.__file__).read_text(encoding="utf-8")))
    yar = Path(cfg.YARA_RULES_DIR)
    if yar.is_dir():
        import re
        for f in yar.glob("*.yar"):
            for m in re.findall(r'attack\s*=\s*"([^"]*)"',
                                f.read_text(encoding="utf-8", errors="replace")):
                used |= {t.strip().upper() for t in m.split(",") if t.strip()}

    missing = sorted(used - named)
    if missing:
        fail(f"{len(missing)} technique(s) referenced but unnamed",
             f"{missing} -- these render as bare ids in the report")
    else:
        ok(f"all {len(used)} referenced techniques have names "
           f"({len(named)} defined)")

    cov = getattr(mapper, "COVERAGE", {})
    ok(f"COVERAGE maps {len(cov)} artifact types")


# =====================================================================
section("7. TIMELINE LAYERS -- can every artifact type be seen?")
# =====================================================================
tl = loaded.get("timeline.timeline_builder")
if tl and specs:
    layers = getattr(tl, "LAYERS", {})
    covered = {t for types in layers.values() for t in types}

    produced = set()
    for spec in getattr(specs, "VOL_SPECS", {}).values():
        t = spec.get("type")
        if isinstance(t, str):
            produced.add(t)
    lspecs = loaded.get("normalization.linux_specs")
    if lspecs:
        produced |= set(getattr(lspecs, "LINUX_PRIMARY_TS", {}))
    produced |= set(getattr(specs, "PRIMARY_TS", {}))

    orphans = sorted(t for t in produced
                     if not any(t.startswith(c) or c.startswith(t)
                                for c in covered))
    ok(f"{len(layers)} layers covering {len(covered)} type patterns")
    if orphans:
        warn(f"{len(orphans)} artifact type(s) are in NO layer",
             f"{orphans[:10]}\n"
             f"         They are stored and searchable but will not appear in "
             f"any `main.py timeline --layer` view.")


# =====================================================================
section("8. YARA AND IOC")
# =====================================================================
try:
    import yara  # noqa: F401
    ok("yara-python installed")
    yar = Path(cfg.YARA_RULES_DIR)
    if yar.is_dir():
        files = sorted(yar.glob("*.yar"))
        ok(f"{len(files)} ruleset file(s) in {yar}")
        for f in files:
            try:
                yara.compile(str(f))
                ok(f"  {f.name} compiles")
            except Exception as e:
                fail(f"  {f.name} does NOT compile",
                     f"{str(e)[:140]}\n         a ruleset that fails to "
                     f"compile matches NOTHING, which looks like a clean host")
    else:
        warn(f"no {yar}", "the memory YARA scan will be skipped")
except ImportError:
    warn("yara-python not installed",
         "pip install yara-python -- the file scanner is skipped without it")

ioc_dir = Path(getattr(cfg, "IOC_FEEDS_DIR", ROOT / "intel" / "feeds"))
if ioc_dir.is_dir():
    feeds = [f for f in ioc_dir.rglob("*") if f.is_file()
             and f.suffix.lower() in (".txt", ".csv", ".tsv", ".ioc", ".list", "")]
    if feeds:
        ok(f"{len(feeds)} IOC feed file(s)")
        ioc = loaded.get("detection.ioc")
        if ioc:
            data, sources = ioc.load_all(ioc_dir)
            counts = {k: len(v) for k, v in (data.get("iocs") or {}).items()}
            if counts:
                ok(f"loaded {sum(counts.values()):,} IOCs: {counts}")
            else:
                fail("feeds present but ZERO IOCs parsed",
                     "check the format: one value per line, or CSV")
    else:
        warn(f"{ioc_dir} is empty",
             "IOC correlation will run and match nothing")
else:
    warn(f"no {ioc_dir}", "mkdir it and drop hash/IP/domain lists in")


# =====================================================================
section("SUMMARY")
# =====================================================================
print(f"  {len(problems)} problem(s), {len(warnings)} warning(s)")
if problems:
    print("\n  MUST FIX -- each of these fails SILENTLY at run time:")
    for p in problems:
        print(f"    - {p}")
if warnings:
    print("\n  worth knowing:")
    for w in warnings:
        print(f"    - {w}")
if not problems and not warnings:
    print("\n  Every wiring point checks out.")

sys.exit(1 if problems else 0)