import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from acquisition.run_tool import free_space_gb, is_admin, run_tool, sha256_file
from config import AVML_PATH, evidence_dir
from database.database import register_evidence

log = logging.getLogger(__name__)

MEMORY_TIMEOUT = 2 * 3600

try:
    from config import AVML_VERSION
except ImportError:

    AVML_VERSION = "avml (version not recorded in config.py)"


def physical_ram_gb():
    try:
        return (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) / 1e9
    except (ValueError, OSError, AttributeError):
        return None


def memory_source():
   
    for path in ("/proc/kcore", "/dev/crash", "/dev/mem"):
        if Path(path).exists():
            return path
    return None


def acquire_memory(case_id, host, avml_path=None, min_free_gb=None,
                   compress=False, dry_run=False):
   
    avml = Path(avml_path or AVML_PATH)
    out_dir = evidence_dir(case_id, host, "linux") / "memory"
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = out_dir / f"memory_{stamp}.lime"

    if not avml.is_file():
        msg = (f"avml not found at {avml}. Download a release from "
               f"github.com/microsoft/avml and chmod +x it.")
        log.error(msg)
        return {"ok": False, "stderr": msg, "path": None}

    if not os.access(avml, os.X_OK):
        msg = f"{avml} is not executable: chmod +x {avml}"
        log.error(msg)
        return {"ok": False, "stderr": msg, "path": None}

    if not is_admin():
        msg = "memory acquisition needs root (reading /proc/kcore)"
        log.error(msg)
        return {"ok": False, "stderr": msg, "path": None}

    source = memory_source()
    if source is None:
        msg = ("no readable memory interface: /proc/kcore, /dev/crash and "
               "/dev/mem are all absent or restricted. Some hardened kernels "
               "block all three -- record this in the report's limitations.")
        log.error(msg)
        return {"ok": False, "stderr": msg, "path": None}
    log.info("memory source: %s", source)

    ram = physical_ram_gb()
    free = free_space_gb(out_dir)
    need = min_free_gb if min_free_gb is not None else ((ram or 0) * 1.2)
    if need and free < need:
        msg = (f"only {free:.1f} GB free at {out_dir}, need about {need:.1f} GB "
               f"(RAM is {ram:.1f} GB). The dump would fill the disk and fail "
               f"at ~99%.")
        log.error(msg)
        return {"ok": False, "stderr": msg, "path": None}

    if ram:
        log.info("physical RAM %.1f GB, free disk %.1f GB -- expect roughly "
                 "%.0f-%.0f minutes", ram, free, ram * 0.5, ram * 2)

    cmd = [str(avml)]
    if compress:
        cmd.append("--compress")
    cmd.append(str(target))

    acquired_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    res = run_tool(cmd, timeout=MEMORY_TIMEOUT, dry_run=dry_run)
    res["path"] = str(target)
    res["acquired_utc"] = acquired_utc      

    if dry_run:
        return res

    if not res["ok"] or not target.exists():
        log.error("avml failed: %s", (res.get("stderr") or "")[:300])
        if case_id and host:
            register_evidence(case_id, host, "avml", target,
                              tool_version=AVML_VERSION,
                              tool_cmdline=" ".join(cmd), os_name="linux",
                              status="failed", error=(res.get("stderr") or "")[:500])
        target.unlink(missing_ok=True)
        return res

    size = target.stat().st_size
    log.info("hashing %.1f GB, this takes a few minutes", size / 1e9)
    digest = sha256_file(target)
    res.update({"size_bytes": size, "sha256": digest})
    log.info("%.1f GB, sha256=%s", size / 1e9, digest)

    if case_id and host:
        register_evidence(case_id, host, "avml", target, sha256=digest,
                          size_bytes=size, acquired_utc=acquired_utc,
                          tool_version=AVML_VERSION,
                          tool_cmdline=" ".join(cmd), os_name="linux",
                          status="ok")

    (target.with_suffix(target.suffix + ".sha256")).write_text(
        f"{digest}  {target.name}\n", encoding="utf-8")

    return res


def register_dump(case_id, host, dump_path, acquired_utc=None,
                  tool_version=None):
  
    dump_path = Path(dump_path)
    if not dump_path.is_file():
        raise SystemExit(f"no such file: {dump_path}")

    log.info("hashing %s (%.1f GB)", dump_path.name,
             dump_path.stat().st_size / 1e9)
    digest = sha256_file(dump_path)


    sidecar = dump_path.with_suffix(dump_path.suffix + ".sha256")
    if sidecar.exists():
        original = sidecar.read_text(encoding="utf-8").split()[0]
        if original.lower() != digest.lower():
            log.error("HASH MISMATCH. The sidecar says %s but the file hashes "
                      "to %s -- the image changed in transit and must not be "
                      "relied on.", original, digest)
        else:
            log.info("hash matches the sidecar written at acquisition time")

    source_id = register_evidence(
        case_id, host, "avml", dump_path, sha256=digest,
        size_bytes=dump_path.stat().st_size,
        acquired_utc=acquired_utc or "unknown (acquired outside the framework)",
        tool_version=tool_version or AVML_VERSION,
        tool_cmdline="acquired manually, registered after transfer",
        os_name="linux", status="ok")
    log.info("registered source_id=%s sha256=%s", source_id, digest)
    return {"source_id": source_id, "sha256": digest, "path": str(dump_path)}