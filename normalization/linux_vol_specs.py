def _g(r, *names, default=""):
    """First non-empty value among candidate column names."""
    for n in names:
        v = r.get(n)
        if v not in (None, ""):
            return v
    return default


def _elf(r):
    """ELF magic (7f 45 4c 46) at the start of an injected region -- the Linux
    equivalent of the MZ check.

    Same leading-newline trap as Windows: Volatility renders Hexdump with a
    newline before the first byte row, so stripping only spaces makes this
    silently never match.
    """
    hexdump = str(r.get("Hexdump", "")).lower()
    for ch in (" ", "\n", "\r", "\t"):
        hexdump = hexdump.replace(ch, "")
    return hexdump.startswith("7f454c46")


def _preload(r):
    """LD_PRELOAD set in a process environment.

    This is the single most useful thing in linux.envars: LD_PRELOAD forces a
    shared object into a process, which is how most Linux userland rootkits
    operate. /etc/ld.so.preload covers the system-wide case; this covers the
    per-process one, which leaves no file behind.
    """
    key = str(_g(r, "Key", "Variable", "Name")).upper()
    return key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")


LINUX_VOL_SPECS = {
    # ==================================================================
    # CORE
    # ==================================================================
    "linux_pslist": {
        "type": "memory_process",
        "ts": [("process_start", "CreateTime")],   # absent on many builds
        "desc": lambda r: f"[pslist] {_g(r,'COMM','Name','ImageFileName')} "
                          f"pid={_g(r,'PID')} ppid={_g(r,'PPID')} "
                          f"uid={_g(r,'UID','EUID')}",
    },
    # psscan finds process structures by scanning memory rather than walking
    # the kernel's linked list, so a PID here but not in pslist is unlinked.
    # That diff is MDF-C002 and costs nothing extra.
    "linux_psscan": {
        "type": "memory_process_scan",
        "ts": [("process_start", "CreateTime")],
        "desc": lambda r: f"[psscan] {_g(r,'COMM','Name','ImageFileName')} "
                          f"pid={_g(r,'PID')} ppid={_g(r,'PPID')}",
    },
    "linux_pstree": {
        "type": "memory_process_tree",
        "ts": [("process_start", "CreateTime")],
        "desc": lambda r: f"[pstree] {_g(r,'COMM','Name')} pid={_g(r,'PID')} "
                          f"ppid={_g(r,'PPID')}",
    },
    # the Linux equivalent of windows.cmdline -- full argv per process
    "linux_psaux": {
        "type": "memory_cmdline",
        "ts": [],
        "desc": lambda r: f"{_g(r,'COMM','Name')} pid={_g(r,'PID')}: "
                          f"{_g(r,'ARGS','Args','Arguments', default='(no arguments)')}",
    },
    # bash history recovered from MEMORY. Survives `history -c` and a wiped
    # .bash_history, and unlike the on-disk copy it carries a real timestamp.
    "linux_bash": {
        "type": "memory_shell_history",
        "ts": [("executed", "CommandTime")],
        "desc": lambda r: f"[{_g(r,'Process','COMM','Name')} pid={_g(r,'PID')}] "
                          f"{_g(r,'Command')}",
    },
    # environment variables per process -- LD_PRELOAD lives here
    "linux_envars": {
        "type": "memory_environment",
        "ts": [],
        "desc": lambda r: (f"{_g(r,'COMM','Process','Name')} pid={_g(r,'PID')}: "
                           f"{_g(r,'Key','Variable','Name')}="
                           f"{_g(r,'Value')}"
                           + (" [PRELOAD]" if _preload(r) else "")),
        "enrich": lambda r: {"is_preload": _preload(r)},
    },
    # shared libraries mapped into each process. A library loaded from /tmp or
    # /dev/shm is the per-process rootkit that ld.so.preload does not show.
    "linux_library_list": {
        "type": "memory_loaded_library",
        "ts": [],
        "desc": lambda r: f"{_g(r,'Name','COMM','Process')} pid={_g(r,'PID')} "
                          f"loaded {_g(r,'Path','LoadAddress')}",
    },
    "linux_lsof": {
        "type": "memory_open_file",
        "ts": [],
        "desc": lambda r: f"{_g(r,'COMM','Process')} pid={_g(r,'PID')} "
                          f"fd={_g(r,'FD')} {_g(r,'Path','Name')}",
    },
    "linux_sockstat": {
        "type": "memory_network",
        "ts": [],
        "desc": lambda r: (f"{_g(r,'COMM','Process')} pid={_g(r,'PID')} "
                           f"{_g(r,'Proto','Protocol')} "
                           f"{_g(r,'Source Addr','LocalAddr','Source')}:"
                           f"{_g(r,'Source Port','LocalPort')} -> "
                           f"{_g(r,'Destination Addr','RemoteAddr','Destination')}:"
                           f"{_g(r,'Destination Port','RemotePort')} "
                           f"[{_g(r,'State')}]"),
    },
    # sockscan is to sockstat what psscan is to pslist: a raw memory scan
    # rather than a walk of the kernel's structures. A socket here but not in
    # sockstat is hidden.
    "linux_lsmod": {
        "type": "memory_kernel_module",
        "ts": [],
        "desc": lambda r: f"module {_g(r,'Name')} size={_g(r,'Size')} "
                          f"offset={_g(r,'Offset','Address')}",
    },
    "linux_malfind": {
        "type": "memory_injection",
        "ts": [],
        "desc": lambda r: (f"injected region in {_g(r,'Process','COMM')} "
                           f"pid={_g(r,'PID')} at {_g(r,'Start','Start VPN')} "
                           f"prot={_g(r,'Protection')}"
                           + (" [ELF HEADER]" if _elf(r) else "")),
        # mz_header stays False so the shared MDF-0009 rule does not fire on
        # Linux; elf_header is the Linux equivalent and has its own rule
        "enrich": lambda r: {"mz_header": False, "elf_header": _elf(r)},
    },

    # ==================================================================
    # MALWARE / ROOTKIT -- no Windows equivalent in this framework
    # ==================================================================
    # a module the kernel is running that is absent from the module list
    "linux_hidden_modules": {
        "type": "memory_hidden_module",
        "ts": [],
        "desc": lambda r: f"HIDDEN kernel module {_g(r,'Name')} "
                          f"at {_g(r,'Offset','Address')} size={_g(r,'Size')}",
    },
    # syscall table entries pointing outside kernel text
    "linux_check_syscall": {
        "type": "memory_syscall_hook",
        "ts": [],
        "desc": lambda r: f"syscall {_g(r,'Index')} in "
                          f"{_g(r,'Table Name','Table')} -> "
                          f"{_g(r,'Handler Symbol','Symbol','Handler')} "
                          f"@{_g(r,'Handler Address','Address')}",
    },
    # module list vs sysfs: a discrepancy means something unlinked itself
    # network protocol handler function pointers -- packet interception
    # interrupt descriptor table hooks
    # processes sharing credential structures: one process was given another's
    # privileges, which is how several rootkits escalate
    # netfilter hooks: traffic interception or a hidden backdoor port
    "linux_netfilter": {
        "type": "memory_netfilter_hook",
        "ts": [],
        "desc": lambda r: f"netfilter hook {_g(r,'Name','Symbol')} "
                          f"proto={_g(r,'Proto','Protocol')} "
                          f"hook={_g(r,'Hook')} @{_g(r,'Handler','Address')}",
    },
    # keyboard notifiers: keystroke logging in the kernel
    "linux_tty_check": {
        "type": "memory_tty_hook",
        "ts": [],
        "desc": lambda r: f"tty hook {_g(r,'Name')} -> "
                          f"{_g(r,'Symbol','Handler')} @{_g(r,'Address')}",
    },
    # cross-view: modules visible in lsmod vs sysfs vs a raw scan
    # argv[0] does not match the real executable -- process masquerading
    "linux_process_spoofing": {
        "type": "memory_process_spoof",
        "ts": [],
        "desc": lambda r: f"process spoofing: pid={_g(r,'PID')} "
                          f"argv0={_g(r,'Argv','Command Line')} "
                          f"real={_g(r,'Path','Binary Path')}",
    },
    # eBPF programs: the modern kernel-level persistence and hooking vector
    "linux_ebpf": {
        "type": "memory_ebpf_program",
        "ts": [],
        "desc": lambda r: f"eBPF program {_g(r,'Name')} type={_g(r,'Type')} "
                          f"@{_g(r,'Address','Offset')}",
    },
    # ftrace hooks: function tracing repurposed for interception
    "linux_check_ftrace": {
        "type": "memory_ftrace_hook",
        "ts": [],
        "desc": lambda r: f"ftrace hook on {_g(r,'Symbol','Name')} -> "
                          f"{_g(r,'Callback','Handler')} "
                          f"module={_g(r,'Module')}",
    },

    # ==================================================================
    # CONTEXT -- rarely a detection, often what explains one
    # ==================================================================
    # kernel ring buffer: module loads, segfaults, OOM kills, driver errors
    # mounted filesystems: a bind mount over /etc or a tmpfs on a system path
    # is a classic way to hide files from anything reading the real directory
    "linux_mountinfo": {
        "type": "memory_mount",
        "ts": [],
        "desc": lambda r: f"{_g(r,'DEVNAME','Device')} on "
                          f"{_g(r,'MOUNT_PATH','Mount Point','Path')} "
                          f"type={_g(r,'FSTYPE','Type')} "
                          f"opts={_g(r,'MNT_OPTS','Options')}",
    },
    # promiscuous mode on an interface means packet capture is running
    # a process holding CAP_SYS_MODULE or CAP_SYS_PTRACE it should not have
}


LINUX_VOL_PRIMARY_TS = {
    "memory_shell_history":     "executed",
    "memory_environment":       "acquired",
    "memory_loaded_library":    "acquired",
    "memory_open_file":         "acquired",
    "memory_kernel_module":     "acquired",
    "memory_hidden_module":     "acquired",
    "memory_syscall_hook":      "acquired",
    "memory_netfilter_hook":    "acquired",
    "memory_tty_hook":          "acquired",
    "memory_process_spoof":     "acquired",
    "memory_ebpf_program":      "acquired",
    "memory_ftrace_hook":       "acquired",
    "memory_mount":             "acquired",
}


LINUX_PLUGINS = {
    # process listing
    "linux_pslist":       "linux.pslist.PsList",
    "linux_psscan":       "linux.psscan.PsScan",      # the pslist diff = MDF-C002
    "linux_pstree":       "linux.pstree.PsTree",
    "linux_psaux":        "linux.psaux.PsAux",        # full argv, the Linux cmdline
    # user activity
    "linux_bash":         "linux.bash.Bash",          # history from MEMORY
    # resources
    "linux_lsof":         "linux.lsof.Lsof",
    "linux_sockstat":     "linux.sockstat.Sockstat",
    "linux_lsmod":        "linux.lsmod.Lsmod",
    # suspicious memory
    "linux_malfind":      "linux.malware.malfind.Malfind",
    "linux_envars":       "linux.envars.Envars",
    "linux_library_list": "linux.library_list.LibraryList",
    "linux_mountinfo":    "linux.mountinfo.MountInfo",
}


LINUX_MALWARE_PLUGINS = {
    "linux_hidden_modules":   "linux.malware.hidden_modules.Hidden_modules",
    "linux_check_syscall":    "linux.malware.check_syscall.Check_syscall",
    "linux_netfilter":        "linux.malware.netfilter.Netfilter",
    "linux_tty_check":        "linux.malware.tty_check.Tty_Check",
    "linux_process_spoofing": "linux.malware.process_spoofing.ProcessSpoofing",
    "linux_ebpf":             "linux.ebpf.EBPF",
    "linux_check_ftrace":     "linux.tracing.ftrace.CheckFtrace",
}
