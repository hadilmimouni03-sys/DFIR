#!/usr/bin/env python3
"""
MiniDFIR — memory forensics test commands.

Each SECTION is independent. Read the guard at the top of each: some sections
need Administrator, a real dump, or an ingested database.

    python tools/test_memory.py --case CASE01 --host FLARE-VM
    python tools/test_memory.py --case CASE01 --host FLARE-VM --acquire
    python tools/test_memory.py --case CASE01 --host FLARE-VM --run-vol

Without --acquire / --run-vol it only does dry runs and reads the database,
so it is safe to run any time.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import logging  # noqa: E402
logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

ap = argparse.ArgumentParser()
ap.add_argument("--case", required=True)
ap.add_argument("--host", required=True)
ap.add_argument("--acquire", action="store_true", help="REALLY dump memory (needs admin)")
ap.add_argument("--run-vol", action="store_true", help="REALLY run Volatility")
ap.add_argument("--dump", help="path to an existing dump, skips acquisition")
args = ap.parse_args()

CASE, HOST = args.case, args.host
from config import evidence_dir, VOLATILITY_CMD, VOLATILITY_SYMBOLS_DIR, WINPMEM_EXE_PATH  # noqa: E402

BASE = evidence_dir(CASE, HOST, "windows")
VOL_OUT = BASE / "volatility"


def section(n, title):
    print(f"\n{'='*72}\n{n}. {title}\n{'='*72}")


# =========================================================================
section(1, "CONFIG — are the paths right?")
# =========================================================================
print(f"  winpmem:      {WINPMEM_EXE_PATH}")
print(f"                exists: {Path(WINPMEM_EXE_PATH).is_file()}")
print(f"  vol command:  {VOLATILITY_CMD}")
print(f"  symbols dir:  {VOLATILITY_SYMBOLS_DIR}")
print(f"                exists: {Path(VOLATILITY_SYMBOLS_DIR).is_dir()}")
if Path(VOLATILITY_SYMBOLS_DIR).is_dir():
    packs = list(Path(VOLATILITY_SYMBOLS_DIR).rglob("*.json*")) + \
            list(Path(VOLATILITY_SYMBOLS_DIR).rglob("*.zip"))
    print(f"                symbol files: {len(packs)}")
    if not packs:
        print("                EMPTY -- vol3 will try to DOWNLOAD symbols.")
        print("                Get windows.zip from")
        print("                downloads.volatilityfoundation.org/volatility3/symbols/")
print(f"  evidence dir: {BASE}")


# =========================================================================
section(2, "ENVIRONMENT — admin, RAM, disk")
# =========================================================================
from acquisition.run_tool import free_space_gb, is_admin  # noqa: E402

print(f"  running as admin: {is_admin()}")
try:
    import ctypes

    class MS(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    st = MS(); st.dwLength = ctypes.sizeof(MS)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
    ram = st.ullTotalPhys / 1e9
    print(f"  physical RAM:     {ram:.1f} GB  <- the dump will be about this size")
except Exception:
    ram = None
    print("  physical RAM:     unknown")
free = free_space_gb(BASE)
print(f"  free disk:        {free:.1f} GB")
if ram and free < ram * 1.2:
    print("  NOT ENOUGH SPACE -- the dump fills the disk and fails at ~99%")


# =========================================================================
section(3, "ACQUISITION — dry run (always safe)")
# =========================================================================
from acquisition.windows.winpmem_runner import acquire_memory  # noqa: E402

res = acquire_memory(CASE, HOST, dry_run=True)
print(f"  ok={res['ok']}  would write: {res.get('path')}")
print(f"  cmdline: {res['cmdline']}")


# =========================================================================
section(4, "ACQUISITION — for real")
# =========================================================================
dump = Path(args.dump) if args.dump else None
if args.acquire:
    res = acquire_memory(CASE, HOST, min_free_gb=(ram * 1.2 if ram else None))
    print(f"  ok={res['ok']}")
    if res.get("ok"):
        dump = Path(res["path"])
        print(f"  path:     {dump}")
        print(f"  size:     {res['size_bytes']/1e9:.1f} GB")
        print(f"  sha256:   {res['sha256']}")
        print(f"  acquired: {res['acquired_utc']}   <- START time, not finish")
    else:
        print(f"  failed: {res['stderr']}")
        print("  ^ the reason is recorded in the evidence table and belongs")
        print("    in the report's limitations section")
else:
    print("  skipped (pass --acquire). Looking for an existing dump...")
    found = sorted((BASE / "memory").glob("*.raw")) if (BASE / "memory").is_dir() else []
    if found:
        dump = found[-1]
        print(f"  found: {dump}  ({dump.stat().st_size/1e9:.1f} GB)")
    else:
        print("  none found")


# =========================================================================
section(5, "CHAIN OF CUSTODY — what the evidence table recorded")
# =========================================================================
from database.database import connection  # noqa: E402

with connection() as c:
    rows = c.execute("""SELECT tool, tool_version, source_path, sha256,
                               size_bytes, acquired_utc, status, error
                        FROM evidence WHERE case_id=? AND host=?
                          AND tool IN ('winpmem','volatility')""",
                     (CASE, HOST)).fetchall()
if rows:
    for tool, ver, path, sha, size, acq, status, err in rows:
        print(f"  {tool:<12} {status:<9} {ver or '-'}")
        print(f"               {path}")
        print(f"               sha256={sha or 'NOT HASHED'}")
        print(f"               {size/1e9 if size else 0:.1f} GB  acquired={acq}")
        if err:
            print(f"               error: {err}")
else:
    print("  no memory evidence registered yet")


# =========================================================================
section(6, "VOLATILITY — dry run")
# =========================================================================
from acquisition.windows.volatility_runner import (WINDOWS_PLUGINS, _base_cmd,  # noqa: E402
                                                   run_volatility)

print(f"  base command: {' '.join(str(x) for x in _base_cmd())}")
print(f"  plugins ({len(WINDOWS_PLUGINS)}):")
for name, plugin in WINDOWS_PLUGINS.items():
    print(f"    {name:<10} {plugin}")

if dump:
    r = run_volatility(dump, VOL_OUT, os_name="windows", dry_run=True)
    print(f"\n  dry run ok, would write {len(r['results'])} json files to {VOL_OUT}")
else:
    print("\n  no dump available, skipping")


# =========================================================================
section(7, "VOLATILITY — for real")
# =========================================================================
if args.run_vol and dump:
    print("  running pslist FIRST as a smoke test (fast). If this fails,")
    print("  everything will -- usually a symbols problem.\n")
    r = run_volatility(dump, VOL_OUT, case_id=CASE, host=HOST,
                       plugins={"pslist": WINDOWS_PLUGINS["pslist"]})
    if r["failed"]:
        print("\n  pslist FAILED. Read the error above. Most likely causes:")
        print("    - symbol tables missing and no internet")
        print("    - the dump is truncated (check the size against RAM)")
        print("    - wrong profile: is this actually a Windows dump?")
    else:
        print("\n  pslist ok -- running the rest")
        r = run_volatility(dump, VOL_OUT, case_id=CASE, host=HOST)
        print(f"\n  failed plugins: {r['failed'] or 'none'}")
else:
    print("  skipped (pass --run-vol with a dump present)")


# =========================================================================
section(8, "RAW OUTPUT — what Volatility actually produced")
# =========================================================================
if VOL_OUT.is_dir():
    for f in sorted(VOL_OUT.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            n = len(data) if isinstance(data, list) else "not a list"
            keys = sorted(data[0].keys())[:8] if isinstance(data, list) and data else []
            print(f"  {f.name:<18} {str(n):>8} rows   keys: {keys}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  {f.name:<18} UNREADABLE: {e}")
    print("\n  ^ compare those keys against VOL_SPECS in normalization/specs.py.")
    print("    A key mismatch means the description comes out empty.")
else:
    print(f"  {VOL_OUT} does not exist yet")


section(9, "NORMALIZATION — VOL_SPECS against the real rows")

from normalization.specs import VOL_SPECS  # noqa: E402

print(f"  {len(VOL_SPECS)} specs defined: {sorted(VOL_SPECS)}\n")
if VOL_OUT.is_dir():
    for name, spec in VOL_SPECS.items():
        f = VOL_OUT / f"{name}.json"
        if not f.exists():
            continue
        try:
            rows = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not rows:
            print(f"  {name:<10} 0 rows")
            continue
        row = rows[0]
        desc = spec["desc"](row)
        ts = [(label, row.get(col)) for label, col in spec["ts"]]
        print(f"  {name:<10} -> {spec['type']}")
        print(f"             desc: {desc[:78]}")
        print(f"             ts:   {ts}")
        missing = [c for _l, c in spec["ts"] if c not in row]
        if missing:
            print(f"             MISSING COLUMNS: {missing}  <- ts will be empty")


section(10, "INGESTION")

from ingestion.volatility_ingestor import ingest_volatility  # noqa: E402

if VOL_OUT.is_dir() and any(VOL_OUT.glob("*.json")):
    r = ingest_volatility(VOL_OUT, CASE, HOST)
    print(f"  {r['artifacts']} artifacts, {r['events']} events")
else:
    print("  no volatility output to ingest")


section(11, "VERIFY — what landed in the database")

with connection() as c:
    objs = {r[0] for r in c.execute("SELECT name FROM sqlite_master")}
    A = "v_artifacts" if "v_artifacts" in objs else "artifacts"

    rows = c.execute(f"""SELECT artifact_type, COUNT(*) FROM {A}
                         WHERE case_id=? AND artifact_type LIKE 'memory_%'
                         GROUP BY 1 ORDER BY 2 DESC""", (CASE,)).fetchall()
    if rows:
        for t, n in rows:
            print(f"  {t:<28} {n:>6}")
    else:
        print("  NO memory artifacts. MDF-0009 and MDF-C002 cannot fire.")

    nots = c.execute(f"""SELECT COUNT(*) FROM {A} WHERE case_id=?
                         AND artifact_type LIKE 'memory_%'
                         AND timestamp_utc IS NULL""", (CASE,)).fetchone()[0]
    print(f"\n  memory artifacts with no timestamp: {nots}")
    print("  (cmdline/malfind have no time of their own -- they anchor to")
    print("   the acquisition time, so this should be 0)")


section(12, "PSLIST vs PSSCAN — process hiding")

with connection() as c:
    hidden = c.execute(f"""
        SELECT json_extract(s.raw_data,'$.PID'),
               json_extract(s.raw_data,'$.ImageFileName')
        FROM {A} s
        WHERE s.case_id=? AND s.artifact_type='memory_process_scan'
          AND NOT EXISTS (SELECT 1 FROM {A} l
                          WHERE l.case_id=s.case_id AND l.host=s.host
                            AND l.artifact_type='memory_process'
                            AND json_extract(l.raw_data,'$.PID')
                              = json_extract(s.raw_data,'$.PID'))
    """, (CASE,)).fetchall()
print(f"  {len(hidden)} PIDs in psscan but not pslist:")
for pid, name in hidden[:15]:
    print(f"    pid {pid}  {name}")
print("\n  Not all are malicious: a process that exited between the two plugin")
print("  runs appears here too. It is a lead, not a verdict.")

# NOTE: the former section 13 ("YARA TARGETING") exercised in-memory YARA via
# Volatility's vadyarascan. That path was never wired into the acquire flow and
# has been removed. Memory detection now runs entirely through the normal engine
# over ingested memory artifacts (the MDM-* rules in rules/YAML/memory.yaml).

