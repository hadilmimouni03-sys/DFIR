import json
import re
from datetime import datetime, timedelta, timezone

EZ = "%Y-%m-%d %H:%M:%S.%f"          # what normalize_timestamp() expects


# ==========================================================================
# shared helpers -- defined ONCE. Duplicating any of these silently replaces
# the earlier version, and Python does not warn.
# ==========================================================================
def _epoch(value):
    """Unix seconds -> a string normalize_timestamp understands.

    float, not int(float()): auditd timestamps carry sub-second precision
    (1710403200.123) and truncating loses event ordering. 0 or negative means
    "unset" -- a bodyfile uses 0 for a missing crtime.
    """
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return datetime.fromtimestamp(n, timezone.utc).strftime(EZ)
    except (OSError, OverflowError, ValueError):
        return None


def _rec(artifact_type, host, timestamps, description, raw):
    return {"artifact_type": artifact_type, "source": "linux_uac", "host": host,
            "timestamps": timestamps, "description": description[:1000],
            "raw_data": raw}


def _mtime(path):
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except (OSError, OverflowError):
        return datetime.now(timezone.utc)


def _lines(path, limit=None):
    """Yield non-blank lines. `limit` caps how many lines are READ, which
    parse_systemd_unit relies on -- do not drop the parameter.

    NOTE: this skips blank lines, so it is unsuitable for any format where a
    blank line is a record separator. parse_apt_history reads the file
    directly for exactly that reason.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                return
            line = line.rstrip("\n")
            if line.strip():
                yield line


_MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

_SYSLOG_OLD = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$")
_SYSLOG_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*(?:[+-]\d{2}:?\d{2}|Z)?)\s+(.*)$")


def _syslog_line(line, ref):
    """Return (timestamp_string, rest_of_line). ref is the file's mtime.

    Modern rsyslog/systemd emit ISO with an offset, which is unambiguous.
    Traditional syslog omits the year, so we borrow it from the file and
    subtract one if that would put the entry in the future -- which is how a
    December entry in a log rotated in January lands in the right year.
    """
    m = _SYSLOG_ISO.match(line)
    if m:
        return m.group(1), m.group(2)

    m = _SYSLOG_OLD.match(line)
    if not m:
        return None, line
    mon, day, clock, rest = m.groups()
    month = _MONTHS.get(mon)
    if not month:
        return None, line
    try:
        dt = datetime(ref.year, month, int(day),
                      *map(int, clock.split(":")), tzinfo=timezone.utc)
    except ValueError:
        return None, rest
    if dt > ref + timedelta(days=1):
        dt = dt.replace(year=ref.year - 1)
    return dt.strftime(EZ), rest


# UAC puts every collected file under one of these. Anything to the LEFT of
# the marker is your analysis machine's path, not the suspect's.
_COLLECTION_MARKERS = ("[root]", "live_response", "bodyfile")


def _user_from_path(path):
    """Owner of a per-user file, derived from its path inside the collection.

    The trap: the collection sits somewhere on YOUR filesystem, e.g.
      /home/analyst/cases/IR-1/[root]/root/.ssh/authorized_keys
    Scanning the whole path for "home/<user>" returns *analyst*. Everything
    before the collection marker has to be discarded first.
    """
    parts = list(path.parts)
    start = 0
    for i, part in enumerate(parts):
        if part in _COLLECTION_MARKERS:
            start = i + 1
    inside = parts[start:]

    for i, part in enumerate(inside):
        if part in ("home", "Users") and i + 1 < len(inside):
            return inside[i + 1]
    if inside and inside[0] == "root":
        return "root"
    if "root" in inside[:2]:
        return "root"
    return "unknown"


# ==========================================================================
# timezone -- a CORRECTNESS issue, not an artifact
# ==========================================================================
def read_timezone(root):
    """Best-effort system timezone from a UAC collection. None if unknown.

    ingest_uac calls this ONCE before the parser loop and passes the result to
    parse_authlog and parse_journal. Without it, naive syslog timestamps are
    treated as UTC and every entry is off by the host's offset -- the same
    class of bug as .replace(tzinfo=utc) on the Windows side.
    """
    from pathlib import Path
    root = Path(root)

    # Debian/Ubuntu: a one-line text file
    for p in root.rglob("*/etc/timezone"):
        try:
            tz = p.read_text(encoding="utf-8", errors="replace").strip()
            if tz and "/" in tz:
                return tz
        except OSError:
            pass

    # RHEL: /etc/localtime is a symlink into /usr/share/zoneinfo/<Area>/<City>
    for p in root.rglob("*/etc/localtime"):
        try:
            target = str(p.readlink()) if p.is_symlink() else ""
        except OSError:
            target = ""
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]

    # UAC live_response often captures timedatectl
    for p in root.rglob("live_response/**/timedatectl*"):
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if "Time zone:" in line:
                    return line.split("Time zone:", 1)[1].strip().split()[0]
        except OSError:
            pass
    return None


def local_to_utc(ts_string, tz_name):
    """Reinterpret a naive EZ-format string as local time in tz_name, convert
    to UTC. Returns the input unchanged if tz is unknown or unparseable -- a
    consistent timestamp beats a crash mid-ingest."""
    if not ts_string or not tz_name:
        return ts_string
    try:
        from zoneinfo import ZoneInfo
        naive = datetime.strptime(ts_string, EZ)
        return (naive.replace(tzinfo=ZoneInfo(tz_name))
                     .astimezone(timezone.utc).strftime(EZ))
    except Exception:
        return ts_string


# ==========================================================================
# ==========================================================================
# CORE -- artifacts present on every Linux host
# ==========================================================================
# ==========================================================================

# --------------------------------------------------------------------------
# bodyfile -- the Linux $MFT. One parser, a whole filesystem timeline.
# --------------------------------------------------------------------------
def parse_bodyfile(path, host):
    """Sleuth Kit bodyfile:
    MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime

    Four timestamps per file. This single parser gives you MACB on every
    collected path -- the closest Linux equivalent to what MFTECmd gives you
    on Windows, and the highest value per line in this file.
    """
    for line in _lines(path):
        f = line.split("|")
        if len(f) < 11:
            continue
        md5, name, inode, mode, uid, gid, size = f[0], f[1], f[2], f[3], f[4], f[5], f[6]
        atime, mtime, ctime, crtime = f[7], f[8], f[9], f[10]
        ts = [(label, _epoch(v)) for label, v in
              (("accessed", atime), ("modified", mtime),
               ("changed", ctime), ("created", crtime))]
        yield _rec("file_entry", host, ts,
                   f"{name} ({size} bytes, {mode}, uid={uid} gid={gid})",
                   {"path": name, "inode": inode, "mode": mode, "uid": uid,
                    "gid": gid, "size": size, "md5": md5 if md5 != "0" else None})


# --------------------------------------------------------------------------
# auth.log / secure -- logins, sudo, su, user creation
# --------------------------------------------------------------------------
_AUTH_PATTERNS = [
    (re.compile(r"Accepted (\w+) for (\S+) from (\S+)"),      "ssh_login_success"),
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
     "ssh_login_failure"),
    (re.compile(r"session opened for user (\S+)"),            "session_open"),
    (re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)$"),         "sudo_command"),
    (re.compile(r"new user: name=(\S+)"),                     "user_added"),
    (re.compile(r"new group: name=(\S+)"),                    "group_added"),
    (re.compile(r"authentication failure"),                   "auth_failure"),
]


def parse_authlog(path, host, tz=None):
    """tz is the SYSTEM timezone read from the collection by read_timezone().

    Traditional syslog is written in LOCAL time with no offset, and
    normalize_timestamp treats naive timestamps as UTC. Without tz, every entry
    on a Europe/Paris host lands an hour late and on a Tokyo host nine hours
    early. The tz is recorded in raw_data so you can tell later whether a
    timestamp was converted or assumed.
    """
    ref = _mtime(path)
    for line in _lines(path):
        ts, rest = _syslog_line(line, ref)
        event = "auth_other"
        for pattern, name in _AUTH_PATTERNS:
            if pattern.search(rest):
                event = name
                break
        if event == "auth_other":
            continue                      # skip the cron/systemd chatter
        # the ISO branch of _syslog_line already carries an offset; only
        # convert when the timestamp came back naive
        if ts and tz and "+" not in ts and "T" not in ts:
            ts = local_to_utc(ts, tz)
        yield _rec("auth_log", host, [("logged", ts)],
                   f"[{event}] {rest}",
                   {"event": event, "line": rest, "log": path.name,
                    "tz": tz or "unknown"})


# --------------------------------------------------------------------------
# shell history -- bash / zsh / sh
# --------------------------------------------------------------------------
def parse_shell_history(path, host):
    """`#1710403200` marker lines appear only if HISTTIMEFORMAT was set.
    Without it there are no timestamps -- the commands are still ingested and
    searchable, they just do not land on the timeline.

    Also worth knowing: shell history is trivially editable, so ABSENCE proves
    nothing. Presence is still evidence. auditd covers the gap where deployed.
    """
    user = _user_from_path(path)
    pending = None
    for line in _lines(path):
        if line.startswith("#") and line[1:].strip().isdigit():
            pending = _epoch(line[1:].strip())
            continue
        if line.startswith(": ") and ":0;" in line:      # zsh extended history
            head, _, cmd = line.partition(";")
            pending = _epoch(head[2:].split(":")[0].strip())
            line = cmd
        yield _rec("shell_history", host, [("executed", pending)],
                   f"[{user}] {line}", {"user": user, "command": line,
                                        "file": path.name})
        pending = None


# --------------------------------------------------------------------------
# cron -- persistence
# --------------------------------------------------------------------------
_CRON = re.compile(
    r"^\s*([\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+|@\w+)\s+(.+)$")


def parse_cron(path, host):
    """System crontabs (/etc/crontab, /etc/cron.d/*) have a user field before
    the command; per-user crontabs do not. No timestamp of its own -- the
    file's mtime is when the job was last written, which is the interesting
    moment."""
    ts = _mtime(path).strftime(EZ)
    system_crontab = "cron.d" in str(path) or path.name == "crontab"
    for line in _lines(path):
        if line.lstrip().startswith("#"):
            continue
        m = _CRON.match(line)
        if not m:
            continue
        schedule, command = m.groups()
        user = ""
        if system_crontab:
            bits = command.split(None, 1)
            if len(bits) == 2 and "/" not in bits[0]:
                user, command = bits
        yield _rec("cron_job", host, [("file_modified", ts)],
                   f"[{user or _user_from_path(path)}] {schedule} -> {command}",
                   {"schedule": schedule, "command": command, "user": user,
                    "file": str(path.name)})


# --------------------------------------------------------------------------
# systemd units -- persistence
# --------------------------------------------------------------------------
def parse_systemd_unit(path, host):
    """limit=200 caps how much of the unit file is read: unit files are small,
    and a malformed one should not stream a gigabyte through the parser."""
    ts = _mtime(path).strftime(EZ)
    body = {}
    for line in _lines(path, limit=200):
        if "=" in line and not line.lstrip().startswith(("#", ";", "[")):
            k, _, v = line.partition("=")
            body.setdefault(k.strip(), v.strip())
    exec_start = body.get("ExecStart", "")
    if not exec_start:
        return
    yield _rec("systemd_unit", host, [("file_modified", ts)],
               f"{path.name}: ExecStart={exec_start} "
               f"(desc={body.get('Description','')})",
               {"unit": path.name, "exec_start": exec_start,
                "user": body.get("User", ""), **body})


# --------------------------------------------------------------------------
# SSH authorized_keys -- T1098.004, the most durable Linux backdoor
# --------------------------------------------------------------------------
def parse_authorized_keys(path, host):
    ts = _mtime(path).strftime(EZ)
    user = _user_from_path(path)
    for line in _lines(path):
        if line.lstrip().startswith("#"):
            continue
        bits = line.split()
        if len(bits) < 2:
            continue
        keytype = next((b for b in bits
                        if b.startswith(("ssh-", "ecdsa-", "sk-"))), bits[0])
        comment = bits[-1] if len(bits) > 2 else ""
        yield _rec("ssh_authorized_key", host, [("file_modified", ts)],
                   f"[{user}] {keytype} {comment}",
                   {"user": user, "key_type": keytype, "comment": comment,
                    "options": bits[0] if not bits[0].startswith(
                        ("ssh-", "ecdsa-", "sk-")) else "",
                    "file": str(path)})


# --------------------------------------------------------------------------
# /etc/passwd -- accounts
# --------------------------------------------------------------------------
def parse_passwd(path, host):
    ts = _mtime(path).strftime(EZ)
    for line in _lines(path):
        f = line.split(":")
        if len(f) < 7:
            continue
        user, _, uid, gid, gecos, home, shell = f[:7]
        yield _rec("user_account", host, [("file_modified", ts)],
                   f"{user} uid={uid} gid={gid} shell={shell} home={home}",
                   {"user": user, "uid": uid, "gid": gid, "shell": shell,
                    "home": home, "gecos": gecos})


# --------------------------------------------------------------------------
# live response: processes -- fills the 'live' timeline layer
# --------------------------------------------------------------------------
def parse_ps(path, host, collected_utc=None):
    """Handles both `ps aux` (11 fields) and `ps -ef` (8 fields).

    A regex here is a trap: %CPU is "0.0", not an integer, and COMMAND contains
    spaces. split(None, N) is simpler and tolerant of UAC's ps invocation
    varying by platform.

    No per-process timestamp exists in ps output, so everything anchors to the
    COLLECTION time. Without that anchor these rows have no event and never
    reach the timeline at all.
    """
    ts = collected_utc or _mtime(path).strftime(EZ)
    for line in _lines(path):
        low = line.lstrip().lower()
        if low.startswith(("user", "uid", "pid ")):
            continue

        f = line.split(None, 10)
        if len(f) >= 11 and f[1].isdigit():                       # ps aux
            user, pid, command = f[0], f[1], f[10]
            start, ppid = f[8], ""
        else:
            f = line.split(None, 7)
            if len(f) >= 8 and f[1].isdigit() and f[2].isdigit():  # ps -ef
                user, pid, ppid, command = f[0], f[1], f[2], f[7]
                start = f[4]
            else:
                continue

        yield _rec("process", host, [("collected", ts)],
                   f"[{user}] pid={pid} {command}",
                   {"user": user, "pid": pid, "ppid": ppid,
                    "start": start, "command": command})


# --------------------------------------------------------------------------
# live response: network -- also fills the 'live' layer
# --------------------------------------------------------------------------
_SS = re.compile(r"^(tcp|udp)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)(?:\s+(.*))?$", re.I)
_NETSTAT = re.compile(r"^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S*)\s*(.*)$", re.I)


def parse_network(path, host, collected_utc=None):
    ts = collected_utc or _mtime(path).strftime(EZ)
    for line in _lines(path):
        m = _SS.match(line) or _NETSTAT.match(line)
        if not m:
            continue
        g = m.groups()
        proto, local, remote, extra = g[0], g[-3], g[-2], (g[-1] or "")
        if local in ("Local", "Address") or remote in ("Peer", "Address"):
            continue
        yield _rec("network_connection", host, [("collected", ts)],
                   f"{proto} {local} -> {remote} {extra}".strip(),
                   {"proto": proto, "local": local, "remote": remote,
                    "process": extra})


# ==========================================================================
# ==========================================================================
# CONDITIONAL -- auditd, journald and package logs may not exist on a host
# ==========================================================================
# ==========================================================================

# --------------------------------------------------------------------------
# auditd -- the richest Linux source where it is deployed
# --------------------------------------------------------------------------
# One logical event is several lines sharing msg=audit(<epoch>:<serial>):
#
#   type=SYSCALL msg=audit(1710403200.123:456): ... auid=1000 uid=0 comm="curl"
#   type=EXECVE  msg=audit(1710403200.123:456): argc=3 a0="curl" a1="-s" a2="http://x"
#   type=CWD     msg=audit(1710403200.123:456): cwd="/root"
#   type=PATH    msg=audit(1710403200.123:456): name="/usr/bin/curl" ...
#
# We group by serial and merge, so ONE artifact carries the command line, the
# user and the working directory together. Parsing line-by-line would give you
# four artifacts that each tell a quarter of the story.
_AUDIT_HDR = re.compile(r"type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

# auid is the ORIGINAL login uid. It survives su and sudo, so it answers
# "who actually did this" where uid only says "what they became".
_INTERESTING = ("comm", "exe", "auid", "uid", "euid", "gid", "pid", "ppid",
                "success", "key", "cwd", "name", "terminal", "res", "acct",
                "hostname", "addr", "syscall")


def _kv(text):
    out = {}
    for k, v in _KV.findall(text):
        out[k] = v[1:-1] if v.startswith('"') else v
    return out


def _execve_cmdline(fields):
    """EXECVE stores args as a0, a1, a2... Reassemble in order."""
    args = []
    for i in range(int(fields.get("argc", 0) or 0)):
        v = fields.get(f"a{i}")
        if v is None:
            break
        args.append(v)
    return " ".join(args)


def parse_auditd(path, host):
    groups, order = {}, []
    for line in _lines(path):
        m = _AUDIT_HDR.match(line)
        if not m:
            continue
        rtype, epoch, serial, rest = m.groups()
        g = groups.get(serial)
        if g is None:
            g = groups[serial] = {"epoch": epoch, "serial": serial,
                                  "types": [], "fields": {}, "cmdline": ""}
            order.append(serial)
        g["types"].append(rtype)
        fields = _kv(rest)
        if rtype == "EXECVE":
            g["cmdline"] = _execve_cmdline(fields)
        else:
            # first writer wins: SYSCALL lands before PATH, and SYSCALL's
            # name/uid are the ones we want
            for k, v in fields.items():
                g["fields"].setdefault(k, v)

    for serial in order:
        g = groups[serial]
        f = g["fields"]
        raw = {k: f[k] for k in _INTERESTING if k in f}
        raw.update({"serial": serial, "types": ",".join(sorted(set(g["types"]))),
                    "cmdline": g["cmdline"]})

        who = f.get("auid", "?")
        if who not in ("?", "4294967295", "-1"):      # 4294967295 = unset auid
            who = f"auid={who}"
        else:
            who = f"uid={f.get('uid','?')}"

        body = g["cmdline"] or f.get("exe") or f.get("comm") or f.get("name", "")
        kind = "EXECVE" if g["cmdline"] else (g["types"][0] if g["types"] else "AUDIT")
        yield _rec("auditd", host, [("logged", _epoch(g["epoch"]))],
                   f"[{kind}] {who} {body}", raw)


# --------------------------------------------------------------------------
# package managers -- what was installed, when, and by whom
# --------------------------------------------------------------------------
# dpkg.log:  2026-03-14 09:15:01 install curl:amd64 <none> 7.81.0-1
_DPKG = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
_DPKG_ACTIONS = {"install", "upgrade", "remove", "purge", "configure", "trigproc"}


def parse_dpkg_log(path, host):
    for line in _lines(path):
        m = _DPKG.match(line)
        if not m:
            continue
        ts, action, rest = m.groups()
        # "status" lines are one per state transition -- thousands of rows
        # saying nothing. Not in _DPKG_ACTIONS, so they never match.
        if action not in _DPKG_ACTIONS:
            continue
        bits = rest.split()
        package = bits[0] if bits else ""
        yield _rec("package_event", host, [("logged", ts + ".000000")],
                   f"[dpkg] {action} {package} {' '.join(bits[1:])}",
                   {"manager": "dpkg", "action": action, "package": package,
                    "detail": rest})


def parse_apt_history(path, host):
    """apt history.log -- multi-line blocks, and the ONLY place that records
    the command line and who ran it.

    Reads the file directly rather than via _lines(), because _lines() strips
    blank lines -- which are the block separators. Flushing on the next
    Start-Date also means the parser does not depend on blank lines surviving
    collection, compression and extraction.
    """
    def flush(block):
        if not block.get("Start-Date"):
            return None
        ts = " ".join(block["Start-Date"].split())      # "2026-03-14  09:15:01"
        actions = {k: v for k, v in block.items()
                   if k in ("Install", "Remove", "Upgrade", "Purge", "Downgrade")}
        summary = "; ".join(f"{k}: {v}" for k, v in actions.items())
        return _rec("package_event", host, [("logged", ts + ".000000")],
                    f"[apt] {block.get('Commandline','')} "
                    f"by={block.get('Requested-By','root')} {summary}",
                    {"manager": "apt",
                     "commandline": block.get("Commandline", ""),
                     "requested_by": block.get("Requested-By", "root"),
                     "end_date": block.get("End-Date", ""),
                     **actions})

    block = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("Start-Date:") and block:
                rec = flush(block)
                if rec:
                    yield rec
                block = {}
            if ":" in line and line.strip():
                k, _, v = line.partition(":")
                block[k.strip()] = v.strip()
    rec = flush(block)
    if rec:
        yield rec


# yum.log:      Mar 14 09:15:01 Installed: curl-7.81.0-1.x86_64
# dnf.rpm.log:  2026-03-14T09:15:01+0000 SUBDEBUG Installed: curl-...
_YUM = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+T\S+)\s+"
                  r"(?:\w+\s+)?(Installed|Erased|Updated|Obsoleted|Upgraded):\s*(.+)$")


def parse_yum_log(path, host, ref_year=None):
    year = ref_year or _mtime(path).year
    for line in _lines(path):
        m = _YUM.match(line)
        if not m:
            continue
        raw_ts, action, package = m.groups()
        if "T" in raw_ts:
            ts = raw_ts                       # already ISO with an offset
        else:
            mon, day, clock = raw_ts.split()
            ts = f"{year}-{_MONTHS.get(mon,1):02d}-{int(day):02d} {clock}.000000"
        yield _rec("package_event", host, [("logged", ts)],
                   f"[yum] {action} {package}",
                   {"manager": "yum", "action": action.lower(),
                    "package": package.strip()})


# --------------------------------------------------------------------------
# journald
# --------------------------------------------------------------------------
# Handles the two formats journalctl produces that are parseable: JSON lines
# (-o json) and the default short format, which is syslog-shaped.
#
# NOT handled: the binary /var/log/journal/*/*.journal files -- those need
# systemd itself. If UAC copied the raw journal rather than exporting it, run
# `journalctl --file=<path> -o json` on a systemd box first.
_JSHORT = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
                     r"([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$")


def parse_journal(path, host, tz=None, ref_year=None):
    year = ref_year or _mtime(path).year

    for line in _lines(path):
        if line.startswith("{"):
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            # __REALTIME_TIMESTAMP is microseconds since epoch -- already UTC,
            # so no tz conversion here
            us = d.get("__REALTIME_TIMESTAMP")
            ts = _epoch(int(us) / 1_000_000) if us and str(us).isdigit() else None
            unit = d.get("_SYSTEMD_UNIT") or d.get("SYSLOG_IDENTIFIER") or "?"
            yield _rec("journal", host, [("logged", ts)],
                       f"[{unit}] {d.get('MESSAGE','')}",
                       {"unit": unit, "message": str(d.get("MESSAGE", ""))[:600],
                        "pid": d.get("_PID"), "uid": d.get("_UID"),
                        "exe": d.get("_EXE"), "cmdline": d.get("_CMDLINE"),
                        "priority": d.get("PRIORITY"), "tz": "utc"})
            continue

        m = _JSHORT.match(line)
        if not m:
            continue
        raw_ts, hostname, unit, pid, message = m.groups()
        mon, day, clock = raw_ts.split()
        ts = f"{year}-{_MONTHS.get(mon,1):02d}-{int(day):02d} {clock}.000000"
        # short format is LOCAL time, same problem as traditional syslog
        if tz:
            ts = local_to_utc(ts, tz)
        yield _rec("journal", host, [("logged", ts)],
                   f"[{unit.strip()}] {message}",
                   {"unit": unit.strip(), "pid": pid, "message": message[:600],
                    "hostname": hostname, "tz": tz or "unknown"})


# ==========================================================================
# ==========================================================================
# GENERIC -- files where the PATH is the meaning
# ==========================================================================
# ==========================================================================
# rc.local, .bashrc, /etc/profile.d/*, modprobe.d, autostart entries, init.d
# scripts, cron.daily scripts, ld.so.preload, sudoers.d, .timer units,
# /etc/group, known_hosts -- all have the same shape:
#
#     a text file whose MTIME is the event, and whose CONTENT is the payload.
#
# Fifteen near-identical parsers would be fifteen places for a bug. One parser
# plus a glob table is the whole thing. Where a file has structure worth
# extracting -- passwd, cron, systemd units, auditd -- it keeps its own parser.
_COMMENT = ("#", ";", "//")


def _persistence_kind(path):
    p = str(path).lower().replace("\\", "/")
    for needle, kind in (
            ("ld.so.preload", "ld_preload"),
            ("/etc/profile.d/", "shell_startup"),
            (".bashrc", "shell_startup"), (".bash_profile", "shell_startup"),
            (".profile", "shell_startup"), (".zshrc", "shell_startup"),
            (".bash_logout", "shell_startup"),
            ("/autostart/", "desktop_autostart"),
            (".xprofile", "x_startup"), (".xinitrc", "x_startup"),
            ("/modprobe.d/", "kernel_module"),
            ("/modules-load.d/", "kernel_module"), ("/etc/modules", "kernel_module"),
            ("rc.local", "boot_script"),
            ("/init.d/", "sysv_init"), ("/rc.d/", "sysv_init"),
            ("/etc/init/", "upstart"),
            ("/cron.hourly/", "cron_script"), ("/cron.daily/", "cron_script"),
            ("/cron.weekly/", "cron_script"), ("/cron.monthly/", "cron_script"),
            ("/var/spool/at/", "at_job"),
            ("/sudoers", "sudoers"),
            (".timer", "systemd_timer"),
            ("/etc/group", "group_membership"),
            ("known_hosts", "ssh_known_hosts"),
    ):
        if needle in p:
            return kind
    return "config"


def parse_persistence_file(path, host, kind=None):
    try:
        ts = _mtime(path).strftime(EZ)
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = [l.strip() for l in body.splitlines()
             if l.strip() and not l.strip().startswith(_COMMENT)]

    # An EMPTY rc.local or .bashrc is not evidence. An empty ld.so.preload IS:
    # on a clean system the file usually does not exist at all, so its mere
    # presence is the finding.
    if not lines and "ld.so.preload" not in str(path):
        return

    kind = kind or _persistence_kind(path)
    yield _rec("persistence_file", host, [("file_modified", ts)],
               f"[{kind}] {path.name}: " + " ; ".join(lines[:4]),
               {"kind": kind, "path": str(path), "name": path.name,
                "lines": len(lines),
                "content": "\n".join(lines[:80])[:3000]})


# --------------------------------------------------------------------------
# system identity -- context, not detections
# --------------------------------------------------------------------------
_IDENTITY_FILES = {
    "hostname": "hostname", "machine-id": "machine_id",
    "os-release": "os_release", "timezone": "timezone",
    "hosts": "hosts_file", "sshd_config": "sshd_config",
}


def parse_system_identity(path, host):
    """os-release tells you which log paths and formats to expect; machine-id
    identifies the host across collections; /etc/hosts pins C2 domains;
    sshd_config records PermitRootLogin."""
    name = _IDENTITY_FILES.get(path.name, path.name)
    ts = _mtime(path).strftime(EZ)
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    interesting = [l.strip() for l in body.splitlines()
                   if l.strip() and not l.lstrip().startswith("#")]
    yield _rec("system_identity", host, [("file_modified", ts)],
               f"[{name}] " + "; ".join(interesting[:6]),
               {"file": name, "path": str(path),
                "content": "\n".join(interesting[:60])[:2000]})


# --------------------------------------------------------------------------
# Trash -- deletion evidence, better metadata than the Windows Recycle Bin
# --------------------------------------------------------------------------
# Each .trashinfo records the ORIGINAL FULL PATH and the deletion time:
#
#     [Trash Info]
#     Path=/home/jdoe/Documents/report.docx
#     DeletionDate=2026-03-14T09:15:01
#
# Direct evidence of cleanup, and it survives even though the content is gone.
def parse_trashinfo(path, host):
    from urllib.parse import unquote
    info = {}
    for line in _lines(path):
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip()
    original = unquote(info.get("Path", ""))
    if not original:
        return
    deleted = info.get("DeletionDate", "").replace("T", " ")
    yield _rec("trash_item", host, [("deleted", deleted)],
               f"deleted {original}",
               {"original_path": original, "deleted": deleted,
                "trashinfo": path.name})


# ==========================================================================
# ==========================================================================
# DISPATCH
# ==========================================================================
# ==========================================================================
# Patterns are matched against the path RELATIVE to the extracted UAC root,
# lowercased. Order matters: FIRST MATCH WINS, so put specific patterns before
# general ones.
#
# This is ONE list on purpose. Splitting it and merging later is how the
# auditd, package, journald, persistence, trash and identity parsers all
# became unreachable in the previous version -- the merge line was lost and
# nothing warned.
LINUX_SPECS = [
    # ---- core ----
    ("bodyfile/*",                              parse_bodyfile),
    ("*/var/log/auth.log*",                     parse_authlog),
    ("*/var/log/secure*",                       parse_authlog),
    ("*/.bash_history",                         parse_shell_history),
    ("*/.zsh_history",                          parse_shell_history),
    ("*/.sh_history",                           parse_shell_history),
    ("*/etc/crontab",                           parse_cron),
    ("*/etc/cron.d/*",                          parse_cron),
    ("*/var/spool/cron/*",                      parse_cron),
    ("*/var/spool/cron/crontabs/*",             parse_cron),
    ("*/etc/systemd/system/*.service",          parse_systemd_unit),
    ("*/lib/systemd/system/*.service",          parse_systemd_unit),
    ("*/.config/systemd/user/*.service",        parse_systemd_unit),
    ("*/.ssh/authorized_keys*",                 parse_authorized_keys),
    ("*/etc/passwd",                            parse_passwd),
    ("live_response/process/ps*",               parse_ps),
    ("live_response/process/*process*",         parse_ps),
    ("live_response/network/ss*",               parse_network),
    ("live_response/network/netstat*",          parse_network),

    # ---- conditional ----
    ("*/var/log/audit/audit.log*",              parse_auditd),
    ("*/var/log/dpkg.log*",                     parse_dpkg_log),
    ("*/var/log/apt/history.log*",              parse_apt_history),
    ("*/var/log/yum.log*",                      parse_yum_log),
    ("*/var/log/dnf.rpm.log*",                  parse_yum_log),
    ("live_response/*journal*",                 parse_journal),
    ("*/var/log/journal*.txt",                  parse_journal),
    ("*/var/log/journal*.json",                 parse_journal),

    # ---- system identity / context ----
    ("*/etc/timezone",                          parse_system_identity),
    ("*/etc/hostname",                          parse_system_identity),
    ("*/etc/machine-id",                        parse_system_identity),
    ("*/etc/os-release",                        parse_system_identity),
    ("*/etc/hosts",                             parse_system_identity),
    ("*/etc/ssh/sshd_config",                   parse_system_identity),

    # ---- generic persistence: one parser, many paths ----
    ("*/etc/ld.so.preload",                     parse_persistence_file),
    ("*/etc/rc.local",                          parse_persistence_file),
    ("*/etc/profile.d/*",                       parse_persistence_file),
    ("*/.bashrc",                               parse_persistence_file),
    ("*/.bash_profile",                         parse_persistence_file),
    ("*/.profile",                              parse_persistence_file),
    ("*/.zshrc",                                parse_persistence_file),
    ("*/.xprofile",                             parse_persistence_file),
    ("*/.xinitrc",                              parse_persistence_file),
    ("*/.config/autostart/*",                   parse_persistence_file),
    ("*/etc/modprobe.d/*",                      parse_persistence_file),
    ("*/etc/modules-load.d/*",                  parse_persistence_file),
    ("*/etc/modules",                           parse_persistence_file),
    ("*/etc/init.d/*",                          parse_persistence_file),
    ("*/etc/init/*",                            parse_persistence_file),
    ("*/etc/cron.hourly/*",                     parse_persistence_file),
    ("*/etc/cron.daily/*",                      parse_persistence_file),
    ("*/etc/cron.weekly/*",                     parse_persistence_file),
    ("*/etc/cron.monthly/*",                    parse_persistence_file),
    ("*/var/spool/at/*",                        parse_persistence_file),
    ("*/etc/sudoers",                           parse_persistence_file),
    ("*/etc/sudoers.d/*",                       parse_persistence_file),
    ("*/etc/group",                             parse_persistence_file),
    ("*/.ssh/known_hosts*",                     parse_persistence_file),
    ("*/etc/systemd/system/*.timer",            parse_persistence_file),
    ("*/lib/systemd/system/*.timer",            parse_persistence_file),

    # ---- user activity ----
    ("*/.local/share/Trash/info/*.trashinfo",   parse_trashinfo),
]


# Which timestamp represents each Linux artifact on the timeline.
# specs.py does PRIMARY_TS.update(LINUX_PRIMARY_TS), so anything missing here
# silently falls back to min(timestamps) -- which for a file_entry means
# "accessed" rather than "modified".
LINUX_PRIMARY_TS = {
    # core
    "file_entry":         "modified",
    "auth_log":           "logged",
    "shell_history":      "executed",
    "cron_job":           "file_modified",
    "systemd_unit":       "file_modified",
    "ssh_authorized_key": "file_modified",
    "user_account":       "file_modified",
    "process":            "collected",
    "network_connection": "collected",
    # conditional
    "auditd":             "logged",
    "package_event":      "logged",
    "journal":            "logged",
    # generic
    "system_identity":    "file_modified",
    "persistence_file":   "file_modified",
    "trash_item":         "deleted",
}


# Merged into NOISE_PATTERNS by specs.py. Matched against the artifact's
# DESCRIPTION, and is_noise() tests both separator forms, so forward slashes
# are correct here.
LINUX_NOISE_PATTERNS = [
    "/proc/", "/sys/", "/run/", "/dev/shm/.x11",
    "/var/lib/dpkg/info/", "/usr/share/man/", "/usr/share/doc/",
    "/var/cache/apt/", "/snap/",
]


# --------------------------------------------------------------------------
# self-check: run this file directly to confirm the dispatch table is intact
#     python normalization/linux_specs.py
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import inspect

    parsers = {p.__name__ for _g, p in LINUX_SPECS}
    print(f"dispatch entries : {len(LINUX_SPECS)}")
    print(f"distinct parsers : {len(parsers)}")
    print(f"PRIMARY_TS types : {len(LINUX_PRIMARY_TS)}")

    expected = {"parse_bodyfile", "parse_authlog", "parse_shell_history",
                "parse_cron", "parse_systemd_unit", "parse_authorized_keys",
                "parse_passwd", "parse_ps", "parse_network", "parse_auditd",
                "parse_dpkg_log", "parse_apt_history", "parse_yum_log",
                "parse_journal", "parse_system_identity",
                "parse_persistence_file", "parse_trashinfo"}
    missing = expected - parsers
    print(f"\nunreachable parsers: {sorted(missing) or 'none'}")

    print(f"_lines accepts limit= : "
          f"{'limit' in inspect.signature(_lines).parameters}")
    print(f"parse_authlog accepts tz= : "
          f"{'tz' in inspect.signature(parse_authlog).parameters}")
    print(f"parse_journal accepts tz= : "
          f"{'tz' in inspect.signature(parse_journal).parameters}")

    # every artifact_type a parser can emit should have a PRIMARY_TS entry
    emitted = {"file_entry", "auth_log", "shell_history", "cron_job",
               "systemd_unit", "ssh_authorized_key", "user_account", "process",
               "network_connection", "auditd", "package_event", "journal",
               "system_identity", "persistence_file", "trash_item"}
    print(f"types with no PRIMARY_TS: "
          f"{sorted(emitted - set(LINUX_PRIMARY_TS)) or 'none'}")