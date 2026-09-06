
import json
import logging
import ntpath
from datetime import datetime, timedelta

from database.database import clear_detections, connection, insert_detections
from normalization.normalizer import CANONICAL

log = logging.getLogger(__name__)

EXEC_TYPES = ("prefetch_execution", "amcache_file",
              "bam_execution", "user_assist_execution")


def _artifacts_view(conn):
    objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    return "v_artifacts" if "v_artifacts" in objs else "artifacts"


def _emit(conn, case_id, rows, rule_id, title, severity, score, attack):
    if not rows:
        return 0
    return insert_detections(
        [{"artifact_id": aid, "case_id": case_id, "engine": "correlation",
          "rule_id": rule_id, "rule_title": title, "severity": severity,
          "score": score, "attack": attack, "matched_on": why}
         for aid, why in rows], conn=conn)


def _dt(ts):
    return datetime.strptime(ts, CANONICAL)


def download_then_execute(case_id, minutes=60, conn=None):
    """MDF-C001 -- a browser downloaded a file, and the same host executed it
    within N minutes.

    The initial-access chain in one row: delivery and execution linked by name,
    host and time. Individually MDF-0010 (a download) and MDF-0001 (execution
    from Downloads) are weak signals. Together they are not.

    Done in Python because basename extraction and a time-window join are both
    clearer here than as SQL string surgery, and the download set is small.
    """
    A = _artifacts_view(conn)

    downloads = conn.execute(
        f"""SELECT host, timestamp_utc, raw_data FROM {A}
            WHERE case_id=? AND artifact_type='browser_download'
              AND timestamp_utc IS NOT NULL""", (case_id,)).fetchall()

    targets = []
    for host, ts, raw in downloads:
        try:
            path = (json.loads(raw) or {}).get("path") or ""
        except (json.JSONDecodeError, TypeError):
            continue
        fname = ntpath.basename(str(path).replace("/", "\\")).lower()
        fname = fname.removesuffix(".crdownload").removesuffix(".part")
        if len(fname) > 4:      # "a.js" is too short to join on safely
            targets.append((host, fname, ts))
    if not targets:
        return 0

    lo = min(_dt(t[2]) for t in targets).strftime(CANONICAL)
    hi = (max(_dt(t[2]) for t in targets)
          + timedelta(minutes=minutes)).strftime(CANONICAL)

    ph = ",".join("?" * len(EXEC_TYPES))
    executions = conn.execute(
        f"""SELECT id, host, timestamp_utc, LOWER(description) FROM {A}
            WHERE case_id=? AND artifact_type IN ({ph})
              AND timestamp_utc BETWEEN ? AND ?""",
        (case_id, *EXEC_TYPES, lo, hi)).fetchall()

    window = timedelta(minutes=minutes)
    hits = {}
    for ex_id, ex_host, ex_ts, desc in executions:
        ex_dt = _dt(ex_ts)
        for dl_host, fname, dl_ts in targets:
            if dl_host != ex_host or fname not in desc:
                continue
            dl_dt = _dt(dl_ts)
            if dl_dt <= ex_dt <= dl_dt + window:
                gap = int((ex_dt - dl_dt).total_seconds() // 60)
                hits[ex_id] = (f"downloaded {fname} at {dl_ts}, "
                               f"executed at {ex_ts} (+{gap} min)")
                break

    return _emit(conn, case_id, sorted(hits.items()), "MDF-C001",
                 f"Downloaded file executed within {minutes} minutes",
                 "critical", 70, ["T1204.002"])


# --------------------------------------------------------------------------
_HIDDEN_PROCESS = """
SELECT s.id,
       json_extract(s.raw_data,'$.PID')           AS pid,
       json_extract(s.raw_data,'$.ImageFileName') AS name
FROM {A} s
WHERE s.case_id = ? AND s.artifact_type = 'memory_process_scan'
  AND json_extract(s.raw_data,'$.PID') IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM {A} l
      WHERE l.case_id = s.case_id
        AND l.artifact_type = 'memory_process'
        AND l.host = s.host
        AND json_extract(l.raw_data,'$.PID') = json_extract(s.raw_data,'$.PID'))
"""


def unlinked_process(case_id, conn=None):
    """MDF-C002 -- a PID psscan found but pslist did not.

    pslist walks the kernel's linked list of active processes; psscan scans
    memory for process structures directly. Present in the second but absent
    from the first means the process was unlinked -- classic process hiding.

    Costs nothing extra: you already run both plugins.

    KNOWN FALSE POSITIVE: a process that exited between the two plugin runs
    appears here too. psscan takes far longer than pslist, so short-lived
    processes (git, conhost, SearchProtocolHost) show up routinely. Treat this
    as a lead, not a verdict -- a real hidden process is still RUNNING and
    usually has network connections in netscan.
    """
    A = _artifacts_view(conn)
    rows = [(aid, f"pid {pid} ({name}) present in psscan, absent from pslist")
            for aid, pid, name in conn.execute(
                _HIDDEN_PROCESS.format(A=A), (case_id,))]
    return _emit(conn, case_id, rows, "MDF-C002",
                 "Process visible to psscan but absent from pslist",
                 "critical", 70, ["T1055", "T1014"])


# --------------------------------------------------------------------------
# Timestamp preservation is what installers, archivers, sync clients and
# version control DO. "New creation time is EARLIER than the old one" is the
# NORMAL case for any copy that restores the original date, which is why an
# earlier version of this rule fired on 20,295 of 20,306 EventID 2 events.
#
# Neither DIRECTION nor MAGNITUDE discriminates: copying a genuinely old file
# moves the timestamp back by years, exactly as an attacker would. What
# discriminates is WHO did it and WHERE.
_TIMESTOMP_BENIGN_IMAGE = (
    # installers and servicing
    "\\msiexec.exe", "\\tiworker.exe", "\\trustedinstaller.exe",
    "\\setup.exe", "\\vc_redist", "\\dism.exe", "\\wusa.exe",
    # archivers -- restoring the stored date is their whole job
    "\\7z", "\\winrar.exe", "\\rar.exe", "\\peazip", "\\bandizip",
    # file management and sync
    "\\explorer.exe", "\\robocopy.exe", "\\xcopy.exe",
    "\\onedrive.exe", "\\dropbox.exe", "\\googledrivefs.exe",
    "\\backup", "\\veeam",
    # development tooling: git checkout rewrites timestamps constantly
    "\\git.exe", "\\code.exe", "\\devenv.exe", "\\msbuild.exe",
    "\\node.exe", "\\python", "\\pip", "\\npm",
    # browsers writing to cache and downloads
    "\\chrome.exe", "\\msedge.exe", "\\firefox.exe",
    # system services
    "\\svchost.exe", "\\searchindexer.exe", "\\wmiprvse.exe",
    "\\searchprotocolhost.exe", "\\csrss.exe",
)

# A process with no business rewriting file creation times at all.
_TIMESTOMP_SUSPECT_IMAGE = (
    "\\powershell.exe", "\\pwsh.exe", "\\cmd.exe", "\\wscript.exe",
    "\\cscript.exe", "\\mshta.exe", "\\rundll32.exe",
    "\\regsvr32.exe", "\\certutil.exe", "\\bitsadmin.exe",
)

# Or a target where nothing should be rewriting creation times, whoever does it.
_TIMESTOMP_SUSPECT_PATH = (
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\windows\\tasks\\", "\\appdata\\local\\temp\\",
    "\\windows\\temp\\", "\\programdata\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\perflogs\\",
)


def sysmon_timestomp(case_id, conn=None):
    """MDF-C003 -- Sysmon EventID 2, creation time rewritten BY A PROCESS THAT
    HAS NO REASON TO, or ON A PATH where it should not happen.

    A field-vs-field comparison (CreationUtcTime < PreviousCreationUtcTime),
    which the YAML engine cannot express: its operators compare a field to a
    literal.

    Worth having because it gives you T1070.006 WITHOUT ingesting $MFT.
    MDF-0007 needs --include-mft; this needs only Sysmon.

    THE TUNING HISTORY MATTERS HERE. The first version alerted on any
    backwards move and fired on 20,295 of 20,306 events -- a rule matching
    99.9% of its input is not detecting anything. Backwards IS the normal
    case: restoring a file's original date after a copy moves the timestamp
    from "now" to whenever the original was made.
    """
    A = _artifacts_view(conn)
    rows, examined, benign = [], 0, 0

    for aid, payload in conn.execute(
            f"""SELECT id, json_extract(raw_data,'$._enrich.payload') FROM {A}
                WHERE case_id=? AND artifact_type='event_log'
                  AND json_extract(raw_data,'$.Channel') LIKE '%Sysmon%'
                  AND json_extract(raw_data,'$.EventId') = '2'""", (case_id,)):
        try:
            d = json.loads(payload or "{}")
        except (json.JSONDecodeError, TypeError):
            continue

        new, old = d.get("CreationUtcTime"), d.get("PreviousCreationUtcTime")
        if not (new and old) or str(new) >= str(old):
            continue
        examined += 1

        image = str(d.get("Image", "")).lower()
        target = str(d.get("TargetFilename", "")).lower()

        if any(x in image for x in _TIMESTOMP_BENIGN_IMAGE):
            benign += 1
            continue

        suspect_who = any(x in image for x in _TIMESTOMP_SUSPECT_IMAGE)
        suspect_where = any(x in target for x in _TIMESTOMP_SUSPECT_PATH)
        if not (suspect_who or suspect_where):
            benign += 1
            continue

        why = "script interpreter" if suspect_who else "protected path"
        rows.append((aid, f"{d.get('TargetFilename')}: creation time moved back "
                          f"from {old} to {new} by {d.get('Image')} [{why}]"))

    if examined:
        log.info("MDF-C003: %d backwards timestamps, %d from known "
                 "timestamp-preserving software, %d flagged",
                 examined, benign, len(rows))

    # HIGH, not critical: even tightened, this technique has enough legitimate
    # uses that a critical would overstate it.
    return _emit(conn, case_id, rows, "MDF-C003",
                 "File creation time rewritten by an unexpected process",
                 "high", 60, ["T1070.006"])


# --------------------------------------------------------------------------
def sysmon_process_chain(case_id, depth_minutes=5, conn=None):
  
    A = _artifacts_view(conn)

    flagged = {}
    for guid, aid, rule in conn.execute(
            f"""SELECT json_extract(a.raw_data,'$._enrich.payload.ProcessGuid'),
                       a.id, d.rule_id
                FROM detections d JOIN {A} a ON a.id = d.artifact_id
                WHERE a.case_id=? AND a.artifact_type='event_log'
                  AND d.severity IN ('critical','high')
                  AND d.engine <> 'correlation'
                  AND json_extract(a.raw_data,'$.EventId') = '1'
                  AND json_extract(a.raw_data,'$._enrich.payload.ProcessGuid')
                      IS NOT NULL""", (case_id,)):
        if guid:
            flagged.setdefault(guid, rule)
    if not flagged:
        return 0

    rows = []
    for aid, pguid, image, cmdline in conn.execute(
            f"""SELECT id,
                       json_extract(raw_data,'$._enrich.payload.ParentProcessGuid'),
                       json_extract(raw_data,'$._enrich.payload.Image'),
                       json_extract(raw_data,'$._enrich.payload.CommandLine')
                FROM {A}
                WHERE case_id=? AND artifact_type='event_log'
                  AND json_extract(raw_data,'$.Channel') LIKE '%Sysmon%'
                  AND json_extract(raw_data,'$.EventId') = '1'
                  AND json_extract(raw_data,'$._enrich.payload.ParentProcessGuid')
                      IS NOT NULL""", (case_id,)):
        if pguid in flagged:
            rows.append((aid, f"spawned by a process flagged by "
                              f"{flagged[pguid]}: {image} {str(cmdline)[:120]}"))

    return _emit(conn, case_id, rows, "MDF-C004",
                 "Process spawned by an already-flagged parent",
                 "high", 55, ["T1059.001"])




# ==========================================================================
# MEMORY CORRELATIONS
#
# Everything below compares ROWS -- counting instances, joining a child to
# its parent, comparing two fields on the same row. The YAML engine compares
# a field to a LITERAL, so none of this can be a rule.
#
# These fill the gaps found by auditing which artifact types no rule consumed:
# pstree and lsmod were producing rows nothing queried.
# ==========================================================================

# Windows starts exactly one of each of these. A second instance is one of the
# oldest and most reliable memory-forensics findings.
_SINGLETON = {"lsass.exe": 1, "services.exe": 1, "wininit.exe": 1,
              "smss.exe": 2, "winlogon.exe": 2, "csrss.exe": 2}

# Expected parent for core Windows processes. A mismatch is masquerading or
# process hollowing.
_EXPECTED_PARENT = {
    "lsass.exe":    {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "svchost.exe":  {"services.exe"},
    "wininit.exe":  {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "spoolsv.exe":  {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
}


def _process_rows(conn, case_id, artifact_type="memory_process"):
    """(artifact_id, pid, ppid, name) for every process artifact."""
    A = _artifacts_view(conn)
    out = []
    for aid, raw in conn.execute(
            f"""SELECT id, raw_data FROM {A}
                WHERE case_id=? AND artifact_type=?""", (case_id, artifact_type)):
        try:
            d = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        pid = d.get("PID")
        name = (d.get("ImageFileName") or d.get("COMM") or d.get("Name") or "")
        if pid in (None, ""):
            continue
        out.append((aid, str(pid), str(d.get("PPID", "")), str(name).lower()))
    return out


def duplicate_singleton_process(case_id, conn=None):
    """MDF-C005 -- more than one instance of a process Windows starts once.

    Requires COUNTING, which the YAML engine cannot do: its operators evaluate
    one row at a time.

    Caveat worth knowing before acting: a dump taken during logon or a fast
    user switch can legitimately show a second winlogon or csrss, which is why
    those have a threshold of 2 rather than 1.
    """
    rows = _process_rows(conn, case_id)
    if not rows:
        return 0

    counts, first = {}, {}
    for aid, pid, _ppid, name in rows:
        if name in _SINGLETON:
            counts[name] = counts.get(name, 0) + 1
            first.setdefault(name, []).append((aid, pid))

    hits = []
    for name, n in counts.items():
        if n > _SINGLETON[name]:
            pids = ", ".join(p for _a, p in first[name])
            for aid, pid in first[name]:
                hits.append((aid, f"{n} instances of {name} (expected "
                                  f"{_SINGLETON[name]}); PIDs {pids}"))

    return _emit(conn, case_id, hits, "MDF-C005",
                 "Multiple instances of a singleton system process",
                 "critical", 80, ["T1036.005", "T1055"])


def unexpected_parent_process(case_id, conn=None):
    """MDF-C006 -- a core Windows process with the wrong parent.

    Needs the PARENT'S NAME, and a pstree row carries only a PPID -- so this
    is a join between two process rows. lsass.exe parented by anything other
    than wininit.exe is the classic case.

    PID REUSE is the false positive here: on a long-uptime host the recorded
    PPID may now belong to an unrelated process. Treat a hit as a lead and
    check the parent's start time against the child's.
    """
    rows = _process_rows(conn, case_id)
    by_pid = {pid: name for _a, pid, _pp, name in rows}

    hits = []
    for aid, pid, ppid, name in rows:
        expected = _EXPECTED_PARENT.get(name)
        if not expected or not ppid:
            continue
        parent = by_pid.get(ppid)
        if parent is None:
            continue                      # orphan -- MDF-C007 handles that
        if parent not in expected:
            hits.append((aid, f"{name} (pid {pid}) parented by {parent} "
                              f"(pid {ppid}); expected "
                              f"{' or '.join(sorted(expected))}"))

    return _emit(conn, case_id, hits, "MDF-C006",
                 "System process with an unexpected parent",
                 "critical", 80, ["T1036.005", "T1134"])


def orphaned_process(case_id, conn=None):
    """MDF-C007 -- a process whose parent PID does not exist in pslist.

    Common and usually benign: the parent exited normally. It matters when the
    orphan is itself suspicious, so this is scored as CONTEXT that raises the
    aggregate score of a process another rule already flagged, rather than an
    alert on its own.
    """
    rows = _process_rows(conn, case_id)
    known = {pid for _a, pid, _pp, _n in rows}

    # roots legitimately have no parent in the list
    roots = {"0", "4", "1", ""}
    hits = [(aid, f"{name} (pid {pid}) has parent pid {ppid}, which is not in "
                  f"the process list")
            for aid, pid, ppid, name in rows
            if ppid not in known and ppid not in roots]

    return _emit(conn, case_id, hits, "MDF-C007",
                 "Process whose parent is absent from the process list",
                 "low", 15, [])


def _binary_leaf(path):
    """Executable NAME from a service binary field: no path, no arguments,
    no extension.

    'C:\\Windows\\System32\\drivers\\tcpip.sys' and '\\SystemRoot\\System32\\
    DRIVERS\\tcpip.sys' are the same file; so are 'foo.exe' and '"foo.exe" -k
    netsvcs'. Comparing the raw strings called all three a mismatch.
    """
    name = str(path).replace("/", "\\").strip('"').split("\\")[-1]
    parts = name.split()
    return (parts[0] if parts else name).rsplit(".", 1)[0]


def service_binary_mismatch(case_id, conn=None):
    """MDF-C008 -- the running service binary differs from its registry config.

    svcscan reports BOTH: 'Binary' is what the service is actually running,
    'Binary (Registry)' is what the configuration says. Comparing two fields
    on the same row is field-vs-field, so it cannot be a YAML rule.

    This is the whole reason memory svcscan is worth having alongside the
    registry Services artifacts: from disk there is only ONE value to look at,
    so a mismatch is invisible.
    """
    A = _artifacts_view(conn)
    hits = []
    for aid, raw in conn.execute(
            f"""SELECT id, raw_data FROM {A}
                WHERE case_id=? AND artifact_type='memory_service'""", (case_id,)):
        try:
            d = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        running = str(d.get("Binary") or "").strip().lower()
        configured = str(d.get("Binary (Registry)") or "").strip().lower()
        if not running or not configured:
            continue

        # KERNEL DRIVERS ARE NOT SERVICES WITH A PATH. svcscan reports a
        # driver's Binary as its OBJECT name -- \Driver\Tcpip -- while the
        # registry holds the FILE -- \SystemRoot\System32\drivers\tcpip.sys.
        # Those are SUPPOSED to differ. Comparing them flagged 91 stock VMware
        # and Windows drivers (vmci, vmrawdsk, storahci, Tcpip, SysmonDrv) as
        # hijacked, which was this correlation's entire hit count on a clean
        # machine. A driver's real image path has to come from the registry
        # artifacts, not from svcscan, so there is nothing to compare here.
        if running.startswith(("\\driver\\", "\\filesystem\\")):
            continue

        # svchost-hosted services list the host process as Binary and the real
        # command in the registry value -- not a mismatch, just how they work
        if "svchost.exe" in running and "svchost.exe" in configured:
            continue

        if _binary_leaf(running) != _binary_leaf(configured):
            hits.append((aid, f"{d.get('Name')}: running {d.get('Binary')} but "
                              f"registry says {d.get('Binary (Registry)')}"))

    return _emit(conn, case_id, hits, "MDF-C008",
                 "Service binary differs from its registry configuration",
                 "critical", 80, ["T1543.003", "T1036.005"])


# --------------------------------------------------------------------------
_BURST = """
SELECT a.host, SUBSTR(e.ts_utc, 1, 13) AS hour, COUNT(*) AS n
FROM events e JOIN {A} a ON a.id = e.artifact_id
WHERE a.case_id = ? AND a.is_noise = 0
  AND a.artifact_type IN ('prefetch_execution','shimcache','bam_execution',
                          'user_assist_execution')
GROUP BY 1, 2 HAVING n >= ? ORDER BY n DESC
"""


def execution_bursts(case_id, threshold=25):
    """Hours with an unusual number of executions.

    Returned, NOT written to detections: a burst is a triage hint, not
    evidence of anything.
    """
    with connection() as conn:
        A = _artifacts_view(conn)
        return conn.execute(_BURST.format(A=A), (case_id, threshold)).fetchall()



def run_all(case_id, minutes=60):

    clear_detections(case_id, engine="correlation")
    with connection() as conn:
        results = {
            "MDF-C001": download_then_execute(case_id, minutes, conn=conn),
            "MDF-C002": unlinked_process(case_id, conn=conn),
            "MDF-C003": sysmon_timestomp(case_id, conn=conn),
            "MDF-C004": sysmon_process_chain(case_id, conn=conn),
            "MDF-C005": duplicate_singleton_process(case_id, conn=conn),
            "MDF-C006": unexpected_parent_process(case_id, conn=conn),
            "MDF-C007": orphaned_process(case_id, conn=conn),
            "MDF-C008": service_binary_mismatch(case_id, conn=conn),
        }
    for rid, n in results.items():
        log.info("%-10s %5d hits", rid, n)
    return results