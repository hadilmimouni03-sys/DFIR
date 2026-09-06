import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger(__name__)

def run_tool(command, timeout, stdout_path=None, dry_run=False, cwd=None):
    command = [str(c) for c in command]
    cmdline = subprocess.list2cmdline(command)

    if dry_run:
        log.info("DRY RUN: %s", cmdline)
        return {"ok": True, "dry_run": True, "cmdline": cmdline,
                "returncode": 0, "stdout": "", "stderr": "", "seconds": 0.0}

    log.info("running: %s", cmdline)
    started = time.monotonic()
    try:
        if stdout_path:
            Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
            with open(stdout_path, "w", encoding="utf-8") as out:
                res = subprocess.run(command, stdout=out, stderr=subprocess.PIPE,
                                     text=True, timeout=timeout, cwd=cwd)
            stdout = ""
        else:
            res = subprocess.run(command, capture_output=True, text=True,
                                 timeout=timeout, cwd=cwd)
            stdout = res.stdout

        elapsed = time.monotonic() - started
        ok = res.returncode == 0
        if not ok:
            log.error("exit %s after %.1fs: %s", res.returncode, elapsed,
                      (res.stderr or "")[:500])
        return {"ok": ok, "cmdline": cmdline, "returncode": res.returncode,
                "stdout": stdout, "stderr": res.stderr or "", "seconds": elapsed}

    except FileNotFoundError:
        msg = f"executable not found: {command[0]}"
        log.error(msg)
        return {"ok": False, "cmdline": cmdline, "returncode": -1,
                "stdout": "", "stderr": msg, "seconds": 0.0}

    except PermissionError as e:
        msg = f"permission denied running {command[0]}: {e}"
        log.error(msg)
        return {"ok": False, "cmdline": cmdline, "returncode": -13,
                "stdout": "", "stderr": msg, "seconds": 0.0}

    except subprocess.TimeoutExpired:
        log.error("timed out after %ss: %s", timeout, cmdline)
        return {"ok": False, "cmdline": cmdline, "returncode": -9, "stdout": "",
                "stderr": f"timed out after {timeout}s", "seconds": float(timeout)}


def tool_version(command, timeout=60):
    for flag in ("--version", "-version", "/version"):
        r = run_tool(list(command) + [flag], timeout=timeout)
        m = re.search(r"v?\d+\.\d+[\.\d]*", f"{r['stdout']} {r['stderr']}")
        if m:
            return m.group(0)
    return None


# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def hash_collection(raw_dir, manifest_path):
    raw_dir = Path(raw_dir)
    manifest_path = Path(manifest_path)
    entries, total = [], 0

    for p in sorted(raw_dir.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            size = p.stat().st_size
            digest = sha256_file(p)
        except (OSError, PermissionError) as e:
            # a locked or unreadable file is itself a finding -- record it
            log.warning("could not hash %s: %s", p, e)
            entries.append({"path": str(p.relative_to(raw_dir)).replace("\\", "/"),
                            "size": None, "sha256": None, "error": str(e)[:200]})
            continue
        entries.append({"path": str(p.relative_to(raw_dir)).replace("\\", "/"),
                        "size": size, "sha256": digest})
        total += size

    text = json.dumps(entries, indent=1, sort_keys=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(text, encoding="utf-8")
    manifest_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    log.info("hashed %d files (%.1f MB), manifest sha256=%s",
             len(entries), total / 1e6, manifest_hash)
    return {"files": len(entries), "bytes": total,
            "sha256": manifest_hash, "manifest": str(manifest_path)}


def verify_collection(raw_dir, manifest_path):
    raw_dir = Path(raw_dir)
    entries = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    recorded = {e["path"]: e["sha256"] for e in entries}
    changed, missing = [], []

    for rel, expected in recorded.items():
        p = raw_dir / rel
        if not p.is_file():
            missing.append(rel)
        elif expected and sha256_file(p) != expected:
            changed.append(rel)

    on_disk = {str(p.relative_to(raw_dir)).replace("\\", "/")
               for p in raw_dir.rglob("*") if p.is_file()}
    added = sorted(on_disk - set(recorded))

    return {"ok": not (changed or missing or added),
            "changed": changed, "missing": missing, "added": added}


def latest_run(parent):
    parent = Path(parent)
    if not parent.is_dir():
        return None
    runs = [p for p in parent.iterdir() if p.is_dir()]
    if not runs:
        return None
    stamped = [p for p in runs if re.fullmatch(r"\d{8}T\d{6}Z", p.name)]
    return max(stamped or runs, key=lambda p: p.name)


def list_runs(parent):
    parent = Path(parent)
    if not parent.is_dir():
        return []
    return sorted((p for p in parent.iterdir() if p.is_dir()),
                  key=lambda p: p.name)


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (ImportError, AttributeError, OSError):
        import os
        return hasattr(os, "geteuid") and os.geteuid() == 0

def free_space_gb(path):
    """RAM dumps fail silently at 99% when the disk fills. Check first."""
    Path(path).mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(path).free / 1e9