import json
from normalization.linux_specs import (LINUX_NOISE_PATTERNS,
                                       LINUX_PRIMARY_TS)
from normalization.linux_vol_specs import (LINUX_VOL_PRIMARY_TS,
                                           LINUX_VOL_SPECS)

def _p(r, *names, default=""):
    for n in names:
        v = r.get(n)
        if v not in (None, ""):
            return v
    return default


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes", "y")


def _registry_type(r):

    key = str(_p(r, "KeyPath", "BatchKeyPath")).lower()
    if "currentversion\\run" in key:
        return "registry_run"
    cat = str(_p(r, "Category", default="unknown")).lower().replace(" ", "_")
    return "registry_" + cat


SPECS = {
    r"_PECmd_Output\.csv$": {
        "type": lambda r: "prefetch_execution",
        "ts": [("last_run", "LastRun"),
               ("source_created", "SourceCreated"),
               ("source_modified", "SourceModified")]
              + [(f"previous_run_{i}", f"PreviousRun{i}") for i in range(8)],
        "desc": lambda r: f"{_p(r,'ExecutableName')} ran {_p(r,'RunCount')} times "
                          f"({_p(r,'SourceFilename','SourceFile')})",
    },

    r"_EvtxECmd_Output\.csv$": {
        "type": lambda r: "event_log",
        "ts": [("time_created", "TimeCreated")],
        "desc": lambda r: f"EID {_p(r,'EventId')} {_p(r,'Channel')}: "
                          f"{_p(r,'MapDescription','Provider')} user={_p(r,'UserName')}",

        "enrich": lambda r: {"payload": _flatten_payload(r.get("Payload"))},
    },

    r"_MFTECmd_\$J_Output\.csv$": {
        "type": lambda r: "usn_journal",
        "ts": [("update", "UpdateTimestamp")],
        "desc": lambda r: f"{_p(r,'ParentPath')}\\{_p(r,'Name')}: {_p(r,'UpdateReasons')}",
    },

    # $MFT is opt-in (--include-mft) because it is huge, but it is the ONLY
    # source of $SI vs $FN timestomping evidence (T1070.006).
    r"_MFTECmd_\$MFT_Output\.csv$": {
        "type": lambda r: "mft_file",
        "ts": [("si_created",  ["Created0x10"]),
               ("fn_created",  ["Created0x30"]),
               ("si_modified", ["LastModified0x10"]),
               ("si_accessed", ["LastAccess0x10"]),
               ("si_record_changed", ["LastRecordChange0x10"])],
        "desc": lambda r: f"{_p(r,'ParentPath')}\\{_p(r,'FileName')} "
                          f"({_p(r,'FileSize', default='0')} bytes)",
        "enrich": lambda r: {
            # MFTECmd emits these directly in recent versions; we also compute
            # our own comparison so the rule works either way.
            "si_lt_fn": _truthy(_p(r, "SI<FN")) or _si_before_fn(r),
            "usec_zeros": _truthy(_p(r, "uSecZeros")),
            "timestomped": _truthy(_p(r, "Timestomped")),
            "is_directory": _truthy(_p(r, "IsDirectory")),
        },
    },

    r"_RECmd_Batch.*_Output\.csv$": {
        "type": _registry_type,
        "ts": [("last_write", ["LastWriteTimestamp", "KeyLastWriteTimestamp"])],
        "desc": lambda r: f"{_p(r,'KeyPath')}\\{_p(r,'ValueName')} = "
                          f"{_p(r,'ValueData')} ({_p(r,'Description')})",
    },

    r"_Amcache_(Un)?AssociatedFileEntries\.csv$": {
        "type": lambda r: "amcache_file",
        "ts": [("key_last_write", ["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp"])],
        "desc": lambda r: f"{_p(r,'Name')} ({_p(r,'FullPath')}) sha1={_p(r,'SHA1')}",
    },

    r"_UserAssist__.*\.csv$": {
        "type": lambda r: "user_assist_execution",
        "ts": [("last_executed", "LastExecuted")],
        "desc": lambda r: f"{_p(r,'ProgramName')} run {_p(r,'RunCounter')} times",
    },

    r"_TaskCache__.*\.csv$": {
        "type": lambda r: "scheduled_task",
        "ts": [("created", "CreatedOn"),
               ("last_start", "LastStart"),
               ("last_stop", "LastStop")],
        "desc": lambda r: f"Task {_p(r,'KeyName')} -> {_p(r,'Path')} "
                          f"(author={_p(r,'Author')})",
    },
    r"_Services__.*\.csv$": {
        "type": lambda r: "service",
        "ts": [("name_key_last_write", "NameKeyLastWrite"),
               ("parameters_key_last_write", "ParametersKeyLastWrite")],
        "desc": lambda r: f"{_p(r,'Name')} ({_p(r,'DisplayName')}) "
                          f"start={_p(r,'StartMode')} "
                          f"image={_p(r,'ImagePath')} dll={_p(r,'ServiceDLL')}",
    },
    # ---- NEW: the nine types your LAYERS referenced but nothing produced ----

    r"_AppCompatCache.*\.csv$": {          # AppCompatCacheParser (shimcache)
        "type": lambda r: "shimcache",
        "ts": [("last_modified", ["LastModifiedTimeUTC", "LastModifiedTime"])],
        "desc": lambda r: f"{_p(r,'Path')} executed={_p(r,'Executed', default='?')}",
    },

    r"_(BamDam|Bam)__.*\.csv$": {          # RECmd BAM/DAM plugin
        "type": lambda r: "bam_execution",
        "ts": [("last_executed", ["ExecutionTime", "LastExecutionTime", "LastExecuted"])],
        "desc": lambda r: f"{_p(r,'Program','Path','ValueName')} "
                          f"user={_p(r,'UserName','SID','UserSid')}",
    },

    r"_LECmd_Output\.csv$": {              # LNK files
        "type": lambda r: "lnk_file",
        "ts": [("source_created", "SourceCreated"),
               ("source_modified", "SourceModified"),
               ("source_accessed", "SourceAccessed"),
               ("target_created", "TargetCreated"),
               ("target_modified", "TargetModified"),
               ("target_accessed", "TargetAccessed")],
        "desc": lambda r: f"{_p(r,'SourceFile')} -> "
                          f"{_p(r,'LocalPath','NetworkPath','TargetIDAbsolutePath')} "
                          f"{_p(r,'Arguments')} vol={_p(r,'VolumeSerialNumber')}",
    },

    r"_(Automatic|Custom)Destinations\.csv$": {   # JLECmd
        "type": lambda r: "jumplist",
        "ts": [("source_created", "SourceCreated"),
               ("source_modified", "SourceModified"),
               ("target_created", "TargetCreated"),
               ("target_modified", "TargetModified"),
               ("last_modified", "LastModified")],
        "desc": lambda r: f"[{_p(r,'AppIdDescription','AppId')}] "
                          f"{_p(r,'Path','LocalPath','TargetIDAbsolutePath')}",
    },

    r"_(UsrClass|NTUSER)\.csv$": {         # SBECmd shellbags
        "type": lambda r: "shellbag",
        "ts": [("last_write", ["LastWriteTime", "LastWriteTimestamp"]),
               ("first_interacted", "FirstInteracted"),
               ("last_interacted", "LastInteracted")],
        "desc": lambda r: f"{_p(r,'AbsolutePath','Value')} "
                          f"({_p(r,'ShellType')})",
    },

    r"_RBCmd_Output\.csv$": {              # Recycle Bin
        "type": lambda r: "recycle_bin",
        "ts": [("deleted", ["DeletedOn", "DeletedTimestamp"])],
        "desc": lambda r: f"deleted {_p(r,'FileName','FileNameOriginal')} "
                          f"({_p(r,'FileSize', default='0')} bytes)",
    },

    r"_SrumECmd_NetworkUsages_Output\.csv$": {   # bytes per process
        "type": lambda r: "srum_network",
        "ts": [("timestamp", "Timestamp")],
        "desc": lambda r: f"{_p(r,'ExeInfo','AppId')} user={_p(r,'UserName','UserId')} "
                          f"sent={_p(r,'BytesSent', default='0')} "
                          f"recv={_p(r,'BytesReceived', default='0')}",
    },

    r"_Activity\.csv$": {                  # WxTCmd (Windows Timeline)
        "type": lambda r: "activity",
        "ts": [("start", "StartTime"), ("end", "EndTime"),
               ("last_modified", ["LastModifiedTime", "LastModified"])],
        "desc": lambda r: f"{_p(r,'Executable','AppId')}: "
                          f"{_p(r,'DisplayText','Payload')}"[:280],
    },
}


def _flatten_payload(payload):

    if not payload:
        return {}
    try:
        doc = json.loads(payload) if isinstance(payload, str) else payload
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(doc, dict):
        return {}

    out = {}

    def add_named(item):
        if not isinstance(item, dict):
            return False
        name = item.get("@Name") or item.get("Name")
        if name is None:
            return False
        out[str(name)] = item.get("#text", item.get("Text", ""))
        return True

    for container in ("EventData", "UserData", "System"):
        block = doc.get(container)
        if not isinstance(block, dict):
            continue

        data = block.get("Data")
        if isinstance(data, list):                  
            for item in data:
                add_named(item)
        elif isinstance(data, dict):                 
       
            if not add_named(data):
                for k, v in data.items():
                    if not isinstance(v, (dict, list)):
                        out[str(k)] = v
        elif isinstance(data, str) and data:          
            out["Data"] = data

        for k, v in block.items():
            if k == "Data" or isinstance(v, (dict, list)):
                continue
            if v not in (None, ""):
                out.setdefault(str(k), v)

    for k, v in doc.items():
        if k not in ("EventData", "UserData", "System") and not isinstance(v, (dict, list)):
            out.setdefault(str(k), v)
    return out


def _si_before_fn(r):
    """$SI created earlier than $FN created -> the file's own metadata claims it
    predates its own directory entry. Classic timestomping signature."""
    si, fn = r.get("Created0x10"), r.get("Created0x30")
    if not si or not fn:
        return False
    return str(si) < str(fn)


# --------------------------------------------------------------------------
SKIP = [
    r"_PECmd_Output_Timeline\.csv$",
    r"_MFTECmd_\$(Boot|SDS)_Output\.csv$",
    r"_Amcache_(Device|Drive|Driver).*\.csv$",
    r"_Amcache_ShortCuts\.csv$",
    r"_Activity_PackageIDs\.csv$",
    r"_TimeZoneInfo__.*\.csv$",
    r"_MountedDevices__.*\.csv$",
    r"_AppCompatFlags2__.*\.csv$",
    r"_FileExts__.*\.csv$",
    r"_Taskband__.*\.csv$",
    r"_NetworkAdapters__.*\.csv$",
    r"_VolumeInfoCache__.*\.csv$",
    r"_DeviceClasses__.*\.csv$",
    r"_AppPaths__.*\.csv$",
    r"_Products__.*\.csv$",
    r"_UnInstall__.*\.csv$",
    r"_SrumECmd_(EnergyUsage|PushNotifications)_Output\.csv$",
]

# $MFT is only skipped unless you pass --include-mft
SKIP_UNLESS_MFT = [r"_MFTECmd_\$MFT_Output\.csv$"]


PRIMARY_TS = {
    "prefetch_execution":   "last_run",
    "amcache_file":         "key_last_write",
    "event_log":            "time_created",
    "user_assist_execution": "last_executed",
    "scheduled_task":       "created",
    "browser_download":     "download_start",
    "browser_visit":        "visit",
    "shimcache":            "last_modified",
    "service":              "name_key_last_write",
    "bam_execution":        "last_executed",
    "lnk_file":             "target_modified",
    "jumplist":             "target_modified",
    "shellbag":             "last_write",
    "recycle_bin":          "deleted",
    "srum_network":         "timestamp",
    "activity":             "start",
    "mft_file":             "si_created",
    "usn_journal":          "update",
    "registry_run":         "last_write",
    "memory_process":       "process_start",
    "memory_process_scan":  "process_start",
    "memory_network":       "connection_created",
}

# --------------------------------------------------------------------------
# Noise is a property of the ARTIFACT, evaluated once at ingest, not 13
# leading-wildcard LIKEs on every timeline query. Lowercase, backslashes.
# Matched against the artifact's DESCRIPTION only -- never against the path of
# the parsed CSV on the analysis machine. v1's "\\evidence\\windows\\raw" pattern
# was aimed at the analysis box; applied to the source path it marks EVERY
# artifact as noise and the default timeline comes back empty.
NOISE_PATTERNS = [
    "$logfile", "$extend", "$bitmap", "$secure",
    "thumbcache", "qmgr.db", "lastalive",
    "\\webcache\\", "\\inetcache\\", "settings.dat", "\\servicestate\\",
    "\\windows\\servicing\\", "\\softwaredistribution\\",
]

GENERIC_TS = [
    "TimeCreated", "Timestamp", "LastWriteTimestamp", "KeyLastWriteTimestamp",
    "LastWriteTime", "NameKeyLastWrite", "ParametersKeyLastWrite",
    "CreatedOn", "ModifiedOn", "AccessedOn", "CreationTime", "CreatedTime",
    "SourceCreated", "SourceModified", "SourceAccessed",
    "TargetCreated", "TargetModified", "TargetAccessed",
    "OpenedOn", "ExecutedOn", "ExecutionTime", "LastExecuted",
    "LastRun", "LastStart", "LastStop", "RunTime",
    "LastModified", "LastModifiedTime", "LastModifiedTimeUTC",
    "DeletedOn", "UpdateTimestamp", "StartTime", "EndTime",
    "FirstInteracted", "LastInteracted", "TrackerCreatedOn",
    "LastOpened", "LastClosed", "ExtensionLastOpened",
    "LastLoginTime", "LastPasswordChange", "LastIncorrectPassword",
    "InstallDate", "Date",
]

GENERIC_TS_EXCLUDE = {
    "ExpirationTime", "OperationExpirationTime", "Expires", "ExpiresOn",
    "FirstConnectLOCAL", "LastConnectedLOCAL",
    "LastModifiedOnClient", "OriginalLastModifiedOnClient",
    "LinkDate", "ExeTimestamp", "DriverTimeStamp", "DriverVerDate",
    "Duration", "DurationMs",
}

INTERESTING_COLUMNS = [
    "Name", "FileName", "ProgramName", "ExecutableName", "Executable", "ExeInfo",
    "Path", "FullPath", "AbsolutePath", "LocalPath", "ParentPath", "ImagePath",
    "KeyPath", "BatchKeyPath", "KeyName", "ValueName", "ValueData",
    "Url", "DisplayName", "DisplayText", "UserName", "Description",
]


def _mz(r):
    hexdump = str(r.get("Hexdump", "")).lower()
    for ch in (" ", "\n", "\r", "\t"):
        hexdump = hexdump.replace(ch, "")
    return hexdump.startswith("4d5a")

VOL_SPECS = {
    "pslist": {
        "type": "memory_process",
        "ts": [("process_start", "CreateTime")],
        "desc": lambda r: f"[pslist] {r.get('ImageFileName')} pid={r.get('PID')} "
                          f"ppid={r.get('PPID')} threads={r.get('Threads')}",
    },
    "psscan": {
        "type": "memory_process_scan",
        "ts": [("process_start", "CreateTime")],
        "desc": lambda r: f"[psscan] {r.get('ImageFileName')} pid={r.get('PID')} "
                          f"ppid={r.get('PPID')}",
    },
    "pstree": {
        "type": "memory_process_tree",
        "ts": [("process_start", "CreateTime")],
        "desc": lambda r: f"[pstree] {r.get('ImageFileName')} pid={r.get('PID')} "
                          f"ppid={r.get('PPID')}",
    },
    "netscan": {
        "type": "memory_network",
        "ts": [("connection_created", "Created")],
        "desc": lambda r: f"{r.get('Owner')} pid={r.get('PID')} "
                          f"{r.get('LocalAddr')}:{r.get('LocalPort')} -> "
                          f"{r.get('ForeignAddr')}:{r.get('ForeignPort')} [{r.get('State')}]",
    },
    "cmdline": {
        "type": "memory_cmdline",
        "ts": [],
        "desc": lambda r: f"{r.get('Process')} pid={r.get('PID')}: {r.get('Args')}",
    },
    "malfind": {
        "type": "memory_injection",
        "ts": [],
        "desc": lambda r: (f"injected region in {r.get('Process')} pid={r.get('PID')} "
                           f"at {r.get('Start VPN')} prot={r.get('Protection')}"
                           + (" [MZ HEADER]" if _mz(r) else "")),
        "enrich": lambda r: {"mz_header": _mz(r)},
    },
    "svcscan": {
        "type": "memory_service",
        "ts": [],
        "desc": lambda r: f"service {r.get('Name')} state={r.get('State')} "
                          f"binary={r.get('Binary')}",
    },
    "yarascan": {
        "type": "memory_yara_hit",
        "ts": [],
        "desc": lambda r: f"YARA {r.get('Rule')} in {r.get('Process')} "
                          f"pid={r.get('PID')} at {r.get('Offset')}",
    },
}

PRIMARY_TS.update(LINUX_PRIMARY_TS)
NOISE_PATTERNS.extend(p for p in LINUX_NOISE_PATTERNS if p not in NOISE_PATTERNS)

VOL_SPECS.update(LINUX_VOL_SPECS)
PRIMARY_TS.update(LINUX_VOL_PRIMARY_TS)