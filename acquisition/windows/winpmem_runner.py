"""Physical memory acquisition."""
import logging
from datetime import datetime, timezone
from pathlib import Path

from acquisition.run_tool import (free_space_gb, is_admin, run_tool,
                                     sha256_file, tool_version)
from config import WINPMEM_EXE_PATH, evidence_dir
from database.database import register_evidence

log = logging.getLogger(__name__)

MEMORY_TIMEOUT = 2 * 3600


def acquire_memory(case_id, host, dry_run=False, min_free_gb=None):
    """Dump physical memory, hash it, register the acquisition.

    Returns a dict on failure rather than raising, so the orchestrator can
    record WHY memory is missing in the evidence table -- that reason belongs
    in the report's limitations section.
    """
    out_dir = evidence_dir(case_id, host, "windows") / "memory"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not dry_run and not is_admin():
        return _fail(case_id, host, out_dir, "memory acquisition requires administrator")

    # RAM dumps fail silently at 99% when the disk fills. Check first.
    if min_free_gb and not dry_run:
        free = free_space_gb(out_dir)
        if free < min_free_gb:
            return _fail(case_id, host, out_dir,
                         f"only {free:.1f} GB free, need ~{min_free_gb} GB")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dump = out_dir / f"memory_{stamp}.raw"

    # Acquisition START time, not finish time: a 64 GB dump takes many minutes
    # and the interesting question is when the snapshot began.
    started_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    version = None if dry_run else tool_version([WINPMEM_EXE_PATH])

    # Older winpmem builds want "acquire", the mini builds take the output path
    # directly. Try the documented form, fall back once.
    res = run_tool([WINPMEM_EXE_PATH, "acquire", str(dump)],
                   timeout=MEMORY_TIMEOUT, dry_run=dry_run)
    if not dry_run and (not res["ok"] or not dump.exists()):
        log.warning("winpmem 'acquire' form failed, retrying without subcommand")
        res = run_tool([WINPMEM_EXE_PATH, str(dump)], timeout=MEMORY_TIMEOUT)

    if dry_run:
        return {**res, "path": dump, "source_id": None}
    if not res["ok"] or not dump.exists():
        return _fail(case_id, host, dump, res["stderr"][:2000] or "winpmem produced no file",
                     cmdline=res["cmdline"])

    sha = sha256_file(dump)
    size = dump.stat().st_size
    source_id = register_evidence(case_id, host, "winpmem", dump, sha256=sha,
                                  size_bytes=size, acquired_utc=started_utc,
                                  tool_version=version, tool_cmdline=res["cmdline"],
                                  os_name="windows")
    log.info("%.1f GB, sha256=%s", size / 1e9, sha)
    return {**res, "path": dump, "sha256": sha, "size_bytes": size,
            "acquired_utc": started_utc, "source_id": source_id}


def _fail(case_id, host, path, reason, cmdline=None):
    log.error("memory acquisition failed: %s", reason)
    source_id = register_evidence(case_id, host, "winpmem", path, os_name="windows",
                                  tool_cmdline=cmdline, status="failed", error=reason)
    return {"ok": False, "path": None, "source_id": source_id, "stderr": reason,
            "returncode": -1, "cmdline": cmdline or "", "stdout": "", "seconds": 0.0}
