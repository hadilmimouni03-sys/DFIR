import os
import hashlib
import zipfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone

from config import CYLR_PATH, CYLR_CONFIG, LINUX_EVIDENCE_DIR
from database.database import register_evidence


def _finalize(archive, host):
    """Hash, register and extract. Shared by all three collection paths."""
    archive = Path(archive)

    h = hashlib.sha256()
    with open(archive, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)

    acquired = datetime.fromtimestamp(archive.stat().st_mtime, tz=timezone.utc
                                      ).strftime("%Y-%m-%d %H:%M:%S.%f")
    source_id = register_evidence(host, "cylr", archive,
                                  sha256=h.hexdigest(), acquired_utc=acquired)

    extracted = archive.parent / archive.stem
    extracted.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        z.extractall(extracted)

    print(f"{archive.name}: {archive.stat().st_size/1e6:.1f} MB, "
          f"sha256={h.hexdigest()[:16]}...")
    return {"archive": archive, "extracted": extracted, "sha256": h.hexdigest(),
            "acquired_utc": acquired, "source_id": source_id}


def run_cylr(host="unknown", out_dir=None, config=None, timeout=3600):
    if os.name == "nt":
        raise RuntimeError("run_cylr must execute on the Linux target")
    if os.geteuid() != 0:
        raise PermissionError("CyLR needs root to read /etc/shadow and /var/log")
    if not CYLR_PATH or not Path(CYLR_PATH).exists():
        raise FileNotFoundError(f"CyLR not found at {CYLR_PATH}")

    out = Path(out_dir or LINUX_EVIDENCE_DIR)
    out.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_name = f"{host}_{stamp}.zip"

    cmd = [str(CYLR_PATH), "-od", str(out), "-of", archive_name,
           "-l", str(out / f"cylr_{stamp}.log")]

    cfg = config or CYLR_CONFIG
    if cfg and Path(cfg).exists():
        cmd += ["-d", str(cfg)]          # -d keeps CyLR defaults AND adds ours

    print(f"collecting with CyLR -> {archive_name}")
    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as p:
        for line in p.stdout:
            print(f"  cylr: {line.rstrip()}")
        p.wait(timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"CyLR exited {p.returncode}")

    archive = out / archive_name
    if not archive.exists():
        raise RuntimeError("CyLR produced no archive")
    return _finalize(archive, host)


def run_cylr_remote(ssh_host, ssh_user, host="unknown",
                    key_file=None, out_dir=None, config=None):
    """Push CyLR to a remote Linux target over SSH, run it, pull the archive back."""
    out = Path(out_dir or LINUX_EVIDENCE_DIR)
    out.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_name = f"{host}_{stamp}.zip"
    remote_tmp = f"/tmp/minidfir_{stamp}"
    target = f"{ssh_user}@{ssh_host}"

    opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if key_file:
        opts += ["-i", str(key_file)]

    def ssh(command):
        r = subprocess.run(["ssh", *opts, target, command],
                           capture_output=True, text=True, timeout=3600)
        if r.returncode != 0:
            raise RuntimeError(f"ssh failed: {r.stderr[-400:]}")
        return r.stdout

    def scp(src, dst):
        r = subprocess.run(["scp", *opts, str(src), str(dst)],
                           capture_output=True, text=True, timeout=3600)
        if r.returncode != 0:
            raise RuntimeError(f"scp failed: {r.stderr[-400:]}")

    print(f"staging CyLR on {ssh_host}")
    ssh(f"mkdir -p {remote_tmp}")
    scp(CYLR_PATH, f"{target}:{remote_tmp}/CyLR")

    cfg = config or CYLR_CONFIG
    cfg_arg = ""
    if cfg and Path(cfg).exists():
        scp(cfg, f"{target}:{remote_tmp}/custom.txt")
        cfg_arg = f" -d {remote_tmp}/custom.txt"

    print("collecting (several minutes)")
    ssh(f"chmod +x {remote_tmp}/CyLR && "
        f"sudo {remote_tmp}/CyLR -od {remote_tmp} -of {archive_name}{cfg_arg}")

    print("retrieving archive")
    scp(f"{target}:{remote_tmp}/{archive_name}", out / archive_name)

    ssh(f"rm -rf {remote_tmp}")          # limit our own footprint on the target
    return _finalize(out / archive_name, host)


def import_cylr_archive(archive_path, host="unknown"):
    """Use an archive collected earlier or handed to you."""
    return _finalize(archive_path, host)


def collect_linux(host="unknown", ssh_host=None, ssh_user=None,
                  key_file=None, archive=None):
    """Single entry point. Picks the right collection method."""
    if archive:
        return import_cylr_archive(archive, host)
    if ssh_host:
        return run_cylr_remote(ssh_host, ssh_user, host, key_file=key_file)
    if os.name == "posix":
        return run_cylr(host)
    raise RuntimeError("No Linux target. Pass ssh_host for a remote machine "
                       "or archive for a collection you already have.")

