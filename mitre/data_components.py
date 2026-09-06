"""ATT&CK data components: what a technique NEEDS, what an artifact PROVIDES.

WHY THIS EXISTS ALONGSIDE COVERAGE
-----------------------------------
attack_mapper.COVERAGE runs one direction:

    artifact type  ->  techniques it could surface
    registry_run   ->  T1547.001

This runs the other:

    technique   ->  telemetry required to detect it     (REQUIRES)
    artifact    ->  telemetry it provides               (PROVIDES)

The pair answers a question COVERAGE structurally cannot:

    "I collect process-creation and command-execution telemetry via Sysmon.
     ATT&CK says T1218.011 needs exactly those. So why is there no rule?"

That is a DETECTION GAP -- a technique you could catch and don't. It is
different from `engine.coverage()`, which reports rules that could not run
because their artifact type is missing. One is "I have a rule and no data";
this is "I have data and no rule".

WHY THIS IS A HAND-WRITTEN TABLE AND NOT A STIX IMPORT
-------------------------------------------------------
ATT&CK's enterprise bundle is ~35 MB of STIX and thousands of objects, and
importing it would deliver two things: technique names (already here) and
data components (below). The rest -- mitigations, groups, software -- is not
detection.

More importantly, the mapping that matters is the SECOND table: what THIS
framework's artifact types provide. No bundle can tell you that; it depends
on which tools you run and how you parse them. So the import would still
leave the hard half hand-written.

The table is deliberately small: only techniques the framework's artifacts
can plausibly reach. A complete ATT&CK mirror would be mostly rows about
telemetry nobody here collects.

SOURCE
------
Data components are taken from ATT&CK v17 technique pages. They are recorded
in this framework's own vocabulary rather than ATT&CK's exact strings
("process_creation", not "Process: Process Creation"), because the names have
to join against PROVIDES, and ATT&CK's naming has changed across versions.
The mapping to ATT&CK's terms is in the comment on each constant.
"""
import logging

from database.database import connection

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Telemetry vocabulary. Left column is this framework's term; the comment is
# the ATT&CK data component it corresponds to.
# --------------------------------------------------------------------------
COMPONENTS = {
    "process_creation":       "Process: Process Creation",
    "process_access":         "Process: OS API Execution / Process Access",
    "process_modification":   "Process: Process Modification",
    "command_execution":      "Command: Command Execution",
    "file_creation":          "File: File Creation",
    "file_modification":      "File: File Modification",
    "file_metadata":          "File: File Metadata",
    "file_deletion":          "File: File Deletion",
    "registry_creation":      "Windows Registry: Registry Key Creation",
    "registry_modification":  "Windows Registry: Registry Key Modification",
    "scheduled_job_creation": "Scheduled Job: Scheduled Job Creation",
    "service_creation":       "Service: Service Creation",
    "service_metadata":       "Service: Service Metadata",
    "module_load":            "Module: Module Load",
    "driver_load":            "Driver: Driver Load",
    "network_connection":     "Network Traffic: Network Connection Creation",
    "network_traffic_dns":    "Network Traffic: Network Traffic Content (DNS)",
    "user_account_creation":  "User Account: User Account Creation",
    "user_account_metadata":  "User Account: User Account Metadata",
    "logon_session":          "Logon Session: Logon Session Creation",
    "application_log":        "Application Log: Application Log Content",
    "kernel_module_load":     "Kernel: Kernel Module Load",
    "script_execution":       "Script: Script Execution",
}


# --------------------------------------------------------------------------
# What each technique REQUIRES. Only techniques this framework's artifacts
# can plausibly reach -- a full ATT&CK mirror would be mostly rows about
# telemetry nobody here collects.
#
# The list is what ATT&CK names as detection data sources. A technique is
# considered DETECTABLE here when ALL its listed components are available,
# which is conservative: some techniques are detectable from a subset.
# --------------------------------------------------------------------------
REQUIRES = {
    # --- persistence ---
    "T1547.001": ["registry_modification"],                      # Run keys
    "T1547.006": ["kernel_module_load", "driver_load"],          # kernel modules
    "T1053.005": ["scheduled_job_creation"],                     # scheduled task
    "T1053.003": ["file_modification", "command_execution"],     # cron
    "T1543.002": ["service_creation", "file_modification"],      # systemd
    "T1543.003": ["service_creation", "service_metadata"],        # Windows service
    "T1546.003": ["process_creation", "command_execution"],      # WMI subscription
    "T1546.004": ["file_modification"],                          # shell profile
    "T1098.004": ["file_modification"],                          # SSH keys
    "T1136.001": ["user_account_creation"],                      # local account

    # --- execution ---
    "T1204.002": ["process_creation", "file_creation"],          # user runs a file
    "T1059.001": ["process_creation", "command_execution", "script_execution"],
    "T1059.004": ["process_creation", "command_execution"],      # unix shell
    "T1569.002": ["service_creation", "command_execution"],      # service exec
    "T1218.010": ["process_creation", "command_execution"],      # regsvr32
    "T1218.011": ["process_creation", "command_execution"],      # rundll32

    # --- defense evasion ---
    "T1055":     ["process_access", "process_modification"],
    "T1055.001": ["process_access", "module_load"],
    "T1055.002": ["process_access", "process_modification"],
    "T1070.001": ["application_log"],                            # clear event log
    "T1070.004": ["file_deletion"],
    "T1070.006": ["file_metadata"],                              # timestomp
    "T1027":     ["command_execution", "process_creation"],
    "T1562.001": ["registry_modification", "command_execution"], # disable tools
    "T1036.005": ["process_creation", "file_metadata"],          # masquerading
    "T1574.001": ["module_load", "file_creation"],               # DLL hijack
    "T1574.006": ["module_load", "process_creation"],            # LD_PRELOAD
    "T1014":     ["kernel_module_load", "driver_load"],          # rootkit

    # --- credential access ---
    "T1003.001": ["process_access", "command_execution"],        # LSASS
    "T1003.002": ["file_creation", "command_execution"],         # SAM
    "T1003.008": ["file_modification", "command_execution"],     # /etc/shadow

    # --- discovery / lateral / c2 ---
    "T1018":     ["process_creation", "command_execution"],
    "T1087.002": ["process_creation", "command_execution"],
    "T1021.002": ["logon_session", "network_connection"],        # SMB
    "T1021.006": ["logon_session", "process_creation"],          # WinRM
    "T1071.001": ["network_connection"],                         # web c2
    "T1071.004": ["network_traffic_dns"],                        # dns c2
    "T1105":     ["network_connection", "file_creation"],        # tool transfer
    "T1572":     ["network_connection"],                         # tunnelling

    # --- added after the Tier 1 review: these could not appear in the gap
    #     analysis at all, because a technique absent from REQUIRES is
    #     invisible to it. The table's completeness is its own blind spot.
    "T1047":     ["process_creation", "command_execution"],       # WMI
    "T1021.001": ["logon_session", "network_connection"],         # RDP
    "T1489":     ["process_creation", "command_execution",
                  "service_metadata"],                            # service stop
    "T1518.001": ["process_creation", "command_execution"],       # AV discovery
    "T1548.002": ["process_creation", "registry_modification"],   # UAC bypass
    "T1574.002": ["module_load", "file_creation"],                # DLL side-load
    "T1553.005": ["file_creation", "file_metadata"],              # MOTW bypass
    "T1546.008": ["file_modification", "registry_modification"],  # accessibility
    "T1546.012": ["registry_modification"],                       # IFEO
    "T1197":     ["process_creation", "command_execution"],       # BITS
    "T1564.004": ["file_creation"],                               # ADS
    "T1112":     ["registry_modification"],                       # modify registry
    "T1059.003": ["process_creation", "command_execution"],       # cmd
    "T1550.002": ["logon_session"],                               # pass the hash
    "T1558.003": ["logon_session"],                               # kerberoasting
    "T1486":     ["file_modification", "file_creation"],          # encryption
    "T1091":     ["file_creation", "registry_modification"],      # removable media

    # --- privilege escalation / impact ---
    "T1548.001": ["file_metadata"],                              # setuid
    "T1548.003": ["file_modification", "command_execution"],     # sudo
    "T1078.003": ["logon_session", "user_account_metadata"],
    "T1490":     ["command_execution", "process_creation"],      # inhibit recovery
}


# --------------------------------------------------------------------------
# What each artifact type PROVIDES.
#
# THIS IS THE HALF NO BUNDLE CAN SUPPLY. It depends entirely on which tools
# this framework runs and how their output is parsed, so it is the part that
# would remain hand-written even with a full STIX import.
#
# Prefix match, matching the convention in COVERAGE and the rule scopes.
# --------------------------------------------------------------------------
PROVIDES = {
    # --- Windows disk ---
    "prefetch_execution":    ["process_creation"],
    "shimcache":             ["process_creation", "file_metadata"],
    "amcache_file":          ["process_creation", "file_metadata"],
    "bam_execution":         ["process_creation"],
    "user_assist_execution": ["process_creation"],
    "registry_run":          ["registry_modification", "registry_creation"],
    "registry_autoruns":     ["registry_modification"],
    "registry_services":     ["service_metadata", "registry_modification"],
    "registry_user_accounts": ["user_account_metadata"],
    "scheduled_task":        ["scheduled_job_creation"],
    "service":               ["service_creation", "service_metadata"],
    "mft_file":              ["file_metadata", "file_creation"],
    "usn_journal":           ["file_creation", "file_modification", "file_deletion"],
    "lnk_file":              ["file_metadata", "command_execution"],
    "recycle_bin":           ["file_deletion"],
    "srum_network":          ["network_connection"],
    "browser_download":      ["file_creation"],
    # USB registry artifacts were collected and no rule ever read them
    "registry_devices":      ["registry_modification"],
    "registry_usb":          ["registry_modification", "file_creation"],
    "unparsed_usb":          ["registry_modification", "file_creation"],

    # --- Windows logs. WITH SYSMON this is the richest source in the
    #     framework; without it, event_log provides far less. That asymmetry
    #     is why sysmon_present() below adjusts the answer.
    "event_log":             ["application_log", "logon_session",
                              "user_account_creation"],

    # --- memory ---
    "memory_process":        ["process_creation"],
    "memory_process_scan":   ["process_creation"],
    "memory_cmdline":        ["command_execution"],
    "memory_injection":      ["process_modification", "process_access"],
    "memory_service":        ["service_metadata", "service_creation"],
    "memory_network":        ["network_connection"],
    "memory_kernel_module":  ["kernel_module_load"],
    "memory_hidden_module":  ["kernel_module_load"],
    "memory_loaded_library": ["module_load"],
    "memory_shell_history":  ["command_execution"],
    "memory_environment":    ["process_creation"],
    "memory_open_file":      ["file_metadata"],

    # --- Linux disk ---
    "file_entry":            ["file_metadata", "file_creation"],
    "auth_log":              ["logon_session", "user_account_creation",
                              "command_execution"],
    "auditd":                ["process_creation", "command_execution",
                              "file_modification"],
    "shell_history":         ["command_execution"],
    "cron_job":              ["scheduled_job_creation", "file_modification"],
    "systemd_unit":          ["service_creation", "file_modification"],
    "ssh_authorized_key":    ["file_modification"],
    "user_account":          ["user_account_creation", "user_account_metadata"],
    "persistence_file":      ["file_modification"],
    "package_event":         ["file_creation", "command_execution"],
    "journal":               ["application_log", "service_creation"],
    "trash_item":            ["file_deletion"],
    "process":               ["process_creation"],
    "network_connection":    ["network_connection"],
}

# Sysmon turns event_log from an application log into the framework's richest
# telemetry source. Detected rather than assumed, because a collection taken
# before Sysmon was installed contains none of it -- Sysmon does not backfill.
SYSMON_PROVIDES = ["process_creation", "command_execution", "file_creation",
                   "file_modification", "registry_creation",
                   "registry_modification", "network_connection",
                   "network_traffic_dns", "module_load", "driver_load",
                   "process_access", "script_execution", "file_metadata"]


def _artifacts_view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"


def sysmon_present(case_id, conn=None):
    """Is there Sysmon data in this case?

    Checked rather than assumed: Sysmon only logs from the moment it is
    installed, so a collection taken beforehand contains none of it and every
    component it would provide is absent.
    """
    close = conn is None
    conn = conn or connection().__enter__()
    try:
        A = _artifacts_view(conn)
        n = conn.execute(
            f"""SELECT COUNT(*) FROM {A} WHERE case_id=?
                AND artifact_type='event_log'
                AND json_extract(raw_data,'$.Channel') LIKE '%Sysmon%'""",
            (case_id,)).fetchone()[0]
        return n > 0, n
    finally:
        if close:
            conn.close()


def available_components(case_id):
    """Telemetry actually present in this case, and which artifact supplies it."""
    with connection() as conn:
        A = _artifacts_view(conn)
        types = [t for (t,) in conn.execute(
            f"SELECT DISTINCT artifact_type FROM {A} WHERE case_id=?", (case_id,))]
        has_sysmon, sysmon_n = sysmon_present(case_id, conn)

    available = {}
    for atype in types:
        for prefix, components in PROVIDES.items():
            if atype.startswith(prefix):
                for c in components:
                    available.setdefault(c, set()).add(atype)

    if has_sysmon:
        for c in SYSMON_PROVIDES:
            available.setdefault(c, set()).add(f"event_log (Sysmon, {sysmon_n:,})")

    return available, has_sysmon


def detection_gaps(case_id, rules=None):
    """Techniques detectable from the collected telemetry with NO rule against them.

    The question `engine.coverage()` cannot ask. That reports rules that could
    not RUN because their artifact type is absent -- "I have a rule and no
    data". This reports the opposite: "I have the data and no rule".

    Conservative on purpose: a technique counts as detectable only when EVERY
    component ATT&CK lists is available. Some techniques are detectable from a
    subset, so this under-reports rather than over-claims.
    """
    from detection.engine import load_rules
    rules = rules if rules is not None else load_rules()
    covered = {t.upper() for r in rules for t in r.get("attack", [])}

    available, has_sysmon = available_components(case_id)
    have = set(available)

    gaps, partial = [], []
    for tid, needs in sorted(REQUIRES.items()):
        if tid in covered:
            continue
        missing = [n for n in needs if n not in have]
        if not missing:
            sources = sorted({s for n in needs for s in available[n]})
            gaps.append({"technique": tid, "needs": needs, "sources": sources})
        elif len(missing) < len(needs):
            partial.append({"technique": tid, "needs": needs, "missing": missing})

    return {"gaps": gaps, "partial": partial, "covered": sorted(covered),
            "available": {k: sorted(v) for k, v in available.items()},
            "sysmon": has_sysmon}


def missing_telemetry(case_id, rules=None):
    """Rules that exist but whose required telemetry is absent.

    The complement of detection_gaps, and a stronger statement than
    engine.coverage() makes: not merely "this artifact type is missing" but
    "the DATA CLASS this technique needs was never collected."
    """
    from detection.engine import load_rules
    rules = rules if rules is not None else load_rules()
    available, _ = available_components(case_id)
    have = set(available)

    out = []
    for rule in rules:
        for tid in rule.get("attack", []):
            needs = REQUIRES.get(tid.upper())
            if not needs:
                continue
            missing = [n for n in needs if n not in have]
            if missing:
                out.append({"rule": rule["id"], "technique": tid.upper(),
                            "missing": [COMPONENTS.get(m, m) for m in missing]})
    return out


def show(case_id):
    """Print the gap analysis."""
    result = detection_gaps(case_id)

    print(f"\n{'='*74}\nDETECTION GAP ANALYSIS -- {case_id}\n{'='*74}")
    print(f"  Sysmon present: {result['sysmon']}")
    print(f"  telemetry classes available: {len(result['available'])}")
    print(f"  techniques covered by a rule: {len(result['covered'])}\n")

    print("  AVAILABLE TELEMETRY")
    for comp, sources in sorted(result["available"].items()):
        print(f"    {COMPONENTS.get(comp, comp):<48} {', '.join(sources)[:44]}")

    print(f"\n  DETECTION GAPS -- {len(result['gaps'])} technique(s) you have the")
    print("  telemetry for and no rule against:")
    if not result["gaps"]:
        print("    none")
    for g in result["gaps"]:
        try:
            from mitre.attack_mapper import name
            label = name(g["technique"])
        except ImportError:
            label = ""
        print(f"    {g['technique']:<12} {label[:44]}")
        print(f"                 needs: {', '.join(g['needs'])}")
        print(f"                 have it from: {', '.join(g['sources'])[:60]}")

    if result["partial"]:
        print(f"\n  PARTIAL -- {len(result['partial'])} technique(s) with SOME of the")
        print("  required telemetry. Detectable with lower confidence, or after")
        print("  collecting what is missing:")
        for p in result["partial"][:10]:
            print(f"    {p['technique']:<12} missing: {', '.join(p['missing'])}")

    print(f"\n{'-'*74}")
    print("  This is the opposite question to `main.py coverage`. That reports")
    print("  rules that could not RUN because their artifact type is absent.")
    print("  This reports telemetry collected that NO rule examines.")
    return result