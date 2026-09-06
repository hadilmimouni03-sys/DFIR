import json
import logging
from collections import defaultdict
from pathlib import Path
from database.database import connection

log = logging.getLogger(__name__)


def _artifacts_view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"

VALID_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}

TECHNIQUES = {
    # --- credential access ---
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1552.001": "Unsecured Credentials: Credentials In Files",

    # --- execution ---
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1204.002": "User Execution: Malicious File",
    "T1569.002": "System Services: Service Execution",
    "T1620":     "Reflective Code Loading",

    # --- persistence ---
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1098":     "Account Manipulation",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1136.001": "Create Account: Local Account",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1546.003": "Event Triggered Execution: WMI Event Subscription",
    "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",

    # --- privilege escalation ---
    "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",

    # --- defense evasion ---
    "T1014":     "Rootkit",
    "T1027":     "Obfuscated Files or Information",
    "T1055":     "Process Injection",
    "T1055.001": "Process Injection: Dynamic-link Library Injection",
    "T1055.002": "Process Injection: Portable Executable Injection",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1070.006": "Indicator Removal: Timestomp",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1222.002": "File and Directory Permissions Modification: Linux and Mac",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
    "T1574.006": "Hijack Execution Flow: Dynamic Linker Hijacking",

    # --- discovery ---
    "T1018":     "Remote System Discovery",
    "T1087.002": "Account Discovery: Domain Account",
    "T1482":     "Domain Trust Discovery",

    # --- lateral movement ---
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",

    # --- collection ---
    "T1560.001": "Archive Collected Data: Archive via Utility",

    # --- command and control ---
    "T1071":     "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1090":     "Proxy",
    "T1105":     "Ingress Tool Transfer",
    "T1572":     "Protocol Tunneling",

    # --- initial access ---
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1566.001": "Phishing: Spearphishing Attachment",

    # --- resource development ---
    "T1588.002": "Obtain Capabilities: Tool",

    # --- masquerading and evasion (memory rules) ---
    "T1036":     "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1055.012": "Process Injection: Process Hollowing",
    "T1134":     "Access Token Manipulation",
    "T1571":     "Non-Standard Port",
    "T1030":     "Data Transfer Size Limits",
    "T1048":     "Exfiltration Over Alternative Protocol",
    "T1204.001": "User Execution: Malicious Link",
    "T1547.009": "Boot or Logon Autostart Execution: Shortcut Modification",

    # --- collection / discovery (Linux memory rules) ---
    "T1040":     "Network Sniffing",
    "T1056.001": "Input Capture: Keylogging",

    # --- privilege escalation / evasion (Linux memory rules) ---
    "T1036.004": "Masquerading: Masquerade Task or Service",
    "T1068":     "Exploitation for Privilege Escalation",
    "T1564":     "Hide Artifacts",

    # --- impact ---
    "T1490":     "Inhibit System Recovery",
}

TACTICS = {
    "T1003.001": ["credential-access"],
    "T1003.002": ["credential-access"],
    "T1003.003": ["credential-access"],
    "T1003.008": ["credential-access"],
    "T1552.001": ["credential-access"],
    "T1110":     ["credential-access"],          
    "T1040":     ["credential-access", "discovery"],

    "T1059.001": ["execution"],
    "T1059.004": ["execution"],
    "T1204.001": ["execution"],
    "T1204.002": ["execution"],
    "T1569.002": ["execution"],

    "T1053.003": ["execution", "persistence", "privilege-escalation"],
    "T1053.005": ["execution", "persistence", "privilege-escalation"],
    "T1098":     ["persistence", "privilege-escalation"],
    "T1098.004": ["persistence", "privilege-escalation"],
    "T1136.001": ["persistence"],
    "T1543.002": ["persistence", "privilege-escalation"],
    "T1543.003": ["persistence", "privilege-escalation"],
    "T1546.003": ["persistence", "privilege-escalation"],
    "T1546.004": ["persistence", "privilege-escalation"],
    "T1547.001": ["persistence", "privilege-escalation"],
    "T1547.006": ["persistence", "privilege-escalation"],
    "T1547.009": ["persistence", "privilege-escalation"],

    "T1068":     ["privilege-escalation"],
    "T1548.001": ["privilege-escalation", "defense-evasion"],
    "T1548.003": ["privilege-escalation", "defense-evasion"],
    "T1134":     ["privilege-escalation", "defense-evasion"],

    "T1014":     ["defense-evasion"],
    "T1027":     ["defense-evasion"],
    "T1036":     ["defense-evasion"],
    "T1036.004": ["defense-evasion"],
    "T1036.005": ["defense-evasion"],
    "T1055":     ["defense-evasion", "privilege-escalation"],
    "T1055.001": ["defense-evasion", "privilege-escalation"],
    "T1055.002": ["defense-evasion", "privilege-escalation"],
    "T1055.012": ["defense-evasion", "privilege-escalation"],
    "T1070.001": ["defense-evasion"],
    "T1070.002": ["defense-evasion"],            # was referenced, never defined
    "T1070.003": ["defense-evasion"],
    "T1070.004": ["defense-evasion"],
    "T1070.006": ["defense-evasion"],
    "T1218.010": ["defense-evasion"],
    "T1218.011": ["defense-evasion"],
    "T1222.002": ["defense-evasion"],
    "T1562.001": ["defense-evasion"],
    "T1564":     ["defense-evasion"],
    "T1574.001": ["persistence", "privilege-escalation", "defense-evasion"],
    "T1574.006": ["persistence", "privilege-escalation", "defense-evasion"],

    "T1620":     ["defense-evasion"],

    "T1018":     ["discovery"],
    "T1087.002": ["discovery"],
    "T1482":     ["discovery"],

    "T1021.002": ["lateral-movement"],
    "T1021.006": ["lateral-movement"],

    "T1056.001": ["collection", "credential-access"],
    "T1560.001": ["collection"],

    "T1071":     ["command-and-control"],
    "T1071.001": ["command-and-control"],
    "T1071.004": ["command-and-control"],
    "T1090":     ["command-and-control"],
    "T1105":     ["command-and-control"],
    "T1571":     ["command-and-control"],
    "T1572":     ["command-and-control"],

    "T1078.003": ["initial-access", "persistence", "privilege-escalation",
                  "defense-evasion"],
    "T1566.001": ["initial-access"],

    "T1588.002": ["resource-development"],
    "T1030":     ["exfiltration"],
    "T1048":     ["exfiltration"],
    "T1490":     ["impact"],
}


COVERAGE = {
    # Windows disk
    "prefetch_execution":    ["T1204.002", "T1059.001"],
    "shimcache":             ["T1204.002"],
    "amcache_file":          ["T1204.002"],
    "bam_execution":         ["T1204.002"],
    "user_assist_execution": ["T1204.002"],
    "registry_run":          ["T1547.001"],
    "registry_autoruns":     ["T1547.001"],
    "scheduled_task":        ["T1053.005"],
    "service":               ["T1543.003", "T1574.001"],
    "mft_file":              ["T1070.006"],
    "browser_download":      ["T1566.001", "T1105"],
    "srum_network":          ["T1071.001"],
    "recycle_bin":           ["T1070.004"],
    "usn_journal":           ["T1105", "T1070.004"],
    "lnk_file":              ["T1204.001", "T1547.009"],
    # Windows logs -- Sysmon widens this a lot
    "event_log":             ["T1070.001", "T1059.001", "T1566.001", "T1055",
                              "T1071.004", "T1547.001", "T1562.001"],
    # memory
    "memory_injection":      ["T1055", "T1055.002"],
    "memory_process_scan":   ["T1014", "T1055"],
    "memory_process_tree":   ["T1036.005", "T1134"],
    "memory_kernel_module":  ["T1014", "T1547.006"],
    "memory_cmdline":        ["T1059.001", "T1218.011"],
    "memory_service":        ["T1543.003"],
    "memory_network":        ["T1071.001"],
    "memory_shell_history":  ["T1059.004", "T1070.003"],
    "memory_hidden_module":  ["T1014", "T1547.006"],
    "memory_module_discrepancy": ["T1014", "T1547.006"],
    "memory_syscall_hook":   ["T1014", "T1547.006"],
    "memory_idt_hook":       ["T1014"],
    "memory_tty_hook":       ["T1056.001", "T1014"],
    "memory_netfilter_hook": ["T1040", "T1014"],
    "memory_protocol_hook":  ["T1040", "T1014"],
    "memory_ftrace_hook":    ["T1014"],
    "memory_process_spoof":  ["T1036.004"],
    "memory_ebpf_program":   ["T1547.006"],
    "memory_shared_creds":   ["T1068"],
    "memory_environment":    ["T1574.006"],
    "memory_loaded_library": ["T1574.006", "T1055.001"],
    "memory_network_scan":   ["T1014"],
    "memory_mount":          ["T1564"],
    "memory_net_interface":  ["T1040"],
    "memory_capability":     ["T1068"],
    "yara_file_hit":         [],
    # IOC correlation reads these; the techniques come from the IOC type
    "browser_visit":         ["T1071.004"],
    # Linux
    "cron_job":              ["T1053.003"],
    "systemd_unit":          ["T1543.002"],
    "ssh_authorized_key":    ["T1098.004"],
    "user_account":          ["T1136.001", "T1078.003"],
    "shell_history":         ["T1059.004", "T1070.003"],
    "auth_log":              ["T1078.003", "T1110"],
    "auditd":                ["T1059.004", "T1548.003", "T1003.008"],
    "package_event":         ["T1588.002", "T1105"],
    "journal":               ["T1543.002", "T1070.002"],
    "persistence_file":      ["T1546.004", "T1547.006", "T1548.003",
                              "T1574.006", "T1098"],
    "trash_item":            ["T1070.004"],
    "file_entry":            ["T1574.006", "T1548.001"],
    "process":               ["T1059.004"],
    "network_connection":    ["T1071"],
}


def name(tid):
    return TECHNIQUES.get(tid, tid)


def tactics(tid):
    return TACTICS.get(tid, ["unknown"])


# --------------------------------------------------------------------------
def detected(case_id):
    """technique_id -> {hits, rules, severity, engines, artifacts}

    Reads the attack column of detections that FIRED. Nothing is inferred.
    """
    order = ["info", "low", "medium", "high", "critical"]
    out = defaultdict(lambda: {"hits": 0, "rules": set(), "engines": set(),
                               "severity": "info", "artifacts": []})

    with connection() as conn:
        A = _artifacts_view(conn)
        rows = conn.execute(
            f"""SELECT d.artifact_id, d.rule_id, d.rule_title, d.severity,
                       d.attack, d.engine
                FROM detections d JOIN {A} a ON a.id = d.artifact_id
                WHERE a.case_id = ?""", (case_id,)).fetchall()

    for artifact_id, rule_id, rule_title, severity, attack, engine in rows:
        try:
            techniques = json.loads(attack) if attack else []
        except (json.JSONDecodeError, TypeError):
            # yara_scanner may store a bare comma-separated string
            techniques = [t.strip() for t in str(attack).split(",") if t.strip()]
        for tid in techniques:
            tid = str(tid).strip().upper()
            if not tid:
                continue
            e = out[tid]
            e["hits"] += 1
            e["rules"].add(f"{rule_id} {rule_title or ''}".strip())
            e["engines"].add(engine)
            if order.index(severity or "info") > order.index(e["severity"]):
                e["severity"] = severity
            if len(e["artifacts"]) < 20:
                e["artifacts"].append(artifact_id)

    return {k: {**v, "rules": sorted(v["rules"]), "engines": sorted(v["engines"])}
            for k, v in out.items()}


def unmapped(case_id):
    
    with connection() as conn:
        A = _artifacts_view(conn)
        return conn.execute(
            f"""SELECT d.engine, d.rule_id, d.severity, COUNT(*)
                FROM detections d JOIN {A} a ON a.id = d.artifact_id
                WHERE a.case_id = ?
                  AND (d.attack IS NULL OR d.attack IN ('', '[]', 'null'))
                GROUP BY 1, 2, 3 ORDER BY 4 DESC""", (case_id,)).fetchall()


def covered(case_id):
    """Techniques the collected artifact types could have surfaced."""
    with connection() as conn:
        A = _artifacts_view(conn)
        types = [r[0] for r in conn.execute(
            f"SELECT DISTINCT artifact_type FROM {A} WHERE case_id=?", (case_id,))]
    out = set()
    for t in types:
        for prefix, techniques in COVERAGE.items():
            if t.startswith(prefix):
                out.update(techniques)
    return sorted(out)


# --------------------------------------------------------------------------
def navigator_layer(case_id, path, attack_version="17"):
    """ATT&CK Navigator layer JSON.

    Two visually distinct bands: scored techniques were DETECTED; score 0 with
    a grey colour means the artifact type was collected and nothing fired.
    Upload at https://mitre-attack.github.io/attack-navigator/
    """
    det, cov = detected(case_id), covered(case_id)
    colour = {"critical": "#a32020", "high": "#d1601a",
              "medium": "#e8b53a", "low": "#8fb04a", "info": "#8fb04a"}

    techniques = [
        {"techniqueID": tid, "score": info["hits"], "enabled": True,
         "color": colour.get(info["severity"], "#8fb04a"),
         "comment": f"{name(tid)} | {'; '.join(info['rules'])[:300]} "
                    f"| engines: {', '.join(info['engines'])}"}
        for tid, info in sorted(det.items())
    ]
    techniques += [
        {"techniqueID": tid, "score": 0, "enabled": True, "color": "#3a3f4a",
         "comment": "artifact type collected; no detection fired"}
        for tid in cov if tid not in det
    ]

    layer = {
        "name": f"MiniDFIR {case_id}",
        "domain": "enterprise-attack",
        "description": ("Scored = a rule fired. Grey = the artifact type was "
                        "collected and nothing matched. Detections from rules "
                        "with no ATT&CK id are NOT represented here -- see the "
                        "unmapped table in the report."),
        "versions": {"attack": attack_version, "navigator": "4.9", "layer": "4.5"},
        "sorting": 3,
        "hideDisabled": False,
        "techniques": techniques,
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(layer, indent=2), encoding="utf-8")

    n_un = sum(n for _e, _r, _s, n in unmapped(case_id))
    log.info("%d techniques detected, %d examined-but-clean, "
             "%d detections with no ATT&CK id -> %s",
             len(det), len(techniques) - len(det), n_un, path)
    return layer


def summary(case_id):

    det = detected(case_id)
    by_tactic = defaultdict(list)
    for tid, info in det.items():
        for t in tactics(tid):                       # <- loop, not a single key
            by_tactic[t].append((tid, name(tid), info))
    for t in by_tactic:
        by_tactic[t].sort(key=lambda x: -x[2]["hits"])
    return dict(by_tactic)


def coverage_report(case_id):
    det, cov = detected(case_id), covered(case_id)
    un = unmapped(case_id)
    return {
        "detected": len(det),
        "examined_clean": len([t for t in cov if t not in det]),
        "unmapped_detections": sum(n for _e, _r, _s, n in un),
        "unmapped_rules": len(un),
        "tactics": sorted({t for tid in det for t in tactics(tid)}),
    }
