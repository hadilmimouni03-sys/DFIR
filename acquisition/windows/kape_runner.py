import logging
from datetime import datetime, timezone
from pathlib import Path

from acquisition.run_tool import ( hash_collection, latest_run, run_tool,
                                     tool_version)
from config import KAPE_EXE_PATH, MFTECMD_PATH, evidence_dir
from database.database import register_evidence

log = logging.getLogger(__name__)

KAPE_TIMEOUT = 4 * 3600


def run_kape(case_id, host, target_source, target="!SANS_Triage,Browsers",
             module="!EZParser", dry_run=False):
    
    base = evidence_dir(case_id, host, "windows")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    raw_dest = base / "raw" / stamp
    parsed_dest = base / "parsed" / stamp
    raw_dest.mkdir(parents=True, exist_ok=True)
    parsed_dest.mkdir(parents=True, exist_ok=True)

    command = [KAPE_EXE_PATH,
               "--tsource", target_source, "--tdest", str(raw_dest),
               "--target", target,
               "--module", module, "--mdest", str(parsed_dest),
               "--mflush"]

    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    version = None if dry_run else tool_version([KAPE_EXE_PATH])
    res = run_tool(command, timeout=KAPE_TIMEOUT, dry_run=dry_run)

    integrity = {"files": 0, "sha256": None}
    if res["ok"] and not dry_run and any(raw_dest.rglob("*")):
        integrity = hash_collection(raw_dest, base / "raw" / f"manifest_{stamp}.json")

    source_id = register_evidence(
        case_id, host, "kape", parsed_dest,
        sha256=integrity["sha256"], size_bytes=integrity.get("bytes"),
        acquired_utc=started, tool_version=version,
        tool_cmdline=res["cmdline"], os_name="windows",
        status="ok" if res["ok"] else "failed",
        error=None if res["ok"] else res["stderr"][:2000])

    return {**res, "run": stamp, "raw_dest": raw_dest,
            "parsed_dest": parsed_dest, "manifest": integrity.get("manifest"),
            "sha256": integrity["sha256"], "files": integrity["files"],
            "source_id": source_id}


def reparse_usn(case_id, host, run=None, dry_run=False):
    base = evidence_dir(case_id, host, "windows")
    raw = (base / "raw" / run) if run else latest_run(base / "raw")
    parsed = (base / "parsed" / run) if run else latest_run(base / "parsed")

    if not raw or not raw.is_dir():
        return {"ok": True, "skipped": "no raw collection"}

    usn = next(iter(sorted(raw.rglob("$J"))), None)
    mft = next(iter(sorted(raw.rglob("$MFT"))), None)
    if not usn:
        return {"ok": True, "skipped": "no $J found"}
    if not mft:
        log.warning("no $MFT found; USN parent paths will stay unresolved")
        return {"ok": True, "skipped": "no $MFT found"}

    out_dir = parsed / "FileSystem"
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*_MFTECmd_$J_Output.csv"):
        log.info("removing path-less USN output %s", old.name)
        if not dry_run:
            old.unlink()

    return run_tool([MFTECMD_PATH, "-f", str(usn), "-m", str(mft),
                     "--csv", str(out_dir)], timeout=3600, dry_run=dry_run)