import csv
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from database.database import clear_detections, connection, insert_detections

log = logging.getLogger(__name__)


RE_HEX = re.compile(r"^[a-f0-9]+$")
RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
RE_DOMAIN = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}

SKIP_HASH_LABELS = ("imphash", "impfuzzy", "ssdeep", "tlsh", "authentihash")


DEFANG = [("[.]", "."), ("(.)", "."), ("[dot]", "."), (" dot ", "."),
          ("hxxp://", "http://"), ("hxxps://", "https://"),
          ("[:]", ":"), ("[://]", "://"), ("\\.", ".")]

IGNORE_IP_PREFIX = ("127.", "0.", "255.", "10.", "192.168.", "169.254.",
                    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
                    "172.31.", "224.", "239.", "8.8.8.8", "1.1.1.1")

IGNORE_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "google.com", "gstatic.com", "googleapis.com", "cloudflare.com",
    "akamai.net", "akamaiedge.net", "amazonaws.com", "office.com",
    "office365.com", "live.com", "msn.com", "bing.com", "digicert.com",
    "verisign.com", "ubuntu.com", "canonical.com", "debian.org",
    "mozilla.org", "apple.com", "icloud.com", "github.com",
}


NOT_TLDS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "jar", "scr", "msi", "lnk", "hta", "cpl", "ocx", "drv", "bin", "dat",
    "tmp", "log", "txt", "ini", "conf", "cfg", "yaml", "yml", "json", "xml",
    "csv", "md", "zip", "rar", "7z", "gz", "tar", "cab", "iso", "img",
    "apk", "doc", "docx", "xls", "xlsx", "xlsm", "xlam", "ppt", "pptx",
    "pdf", "rtf", "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "mp3",
    "mp4", "avi", "py", "pl", "rb", "php", "go", "rs", "db", "sqlite", "elf",

    "sh", "wsf", "ws", "reg", "chm", "url", "pif", "ppc", "arm", "arm5",
    "arm6", "arm7", "mips", "mpsl", "m68k", "i686", "x86", "spc", "arc",
}


IOC_COLUMNS = ("sha256_hash", "sha1_hash", "md5_hash", "sha256", "sha1",
               "md5", "hash", "ioc", "indicator", "value", "domain",
               "hostname", "url", "ip", "ip_address", "dst_ip", "c2",
               "address", "first_seen_ip")
SKIP_COLUMNS = ("imphash", "impfuzzy", "ssdeep", "tlsh", "authentihash",
                "file_name", "filename", "reporter", "signature", "clamav",
                "file_type", "mime_type", "tags", "comment", "description",
                "vtpercent")


def _clean(value):

    v = str(value).replace("\ufeff", "").strip()
    v = v.strip('"\'').strip()
    v = v.rstrip(".,;:|")
    for a, b in DEFANG:
        v = v.replace(a, b)
    return v.strip()


def classify(value):
    
    v = _clean(value)
    if not v or v.startswith(("#", "//", ";")):
        return None, None

    low = v.lower()

    if len(low) in HASH_BY_LEN and RE_HEX.match(low):
        return HASH_BY_LEN[len(low)], low

    if RE_IPV4.match(v):
        if any(v.startswith(p) for p in IGNORE_IP_PREFIX):
            return None, None
        try:
            if all(0 <= int(o) <= 255 for o in v.split(".")):
                return "ip", v
        except ValueError:
            pass
        return None, None

    if "://" in low:
        low = low.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    low = low.rstrip(".")
    if RE_DOMAIN.match(low):
       
        if low.rsplit(".", 1)[-1] in NOT_TLDS:
            return None, None
        if low in IGNORE_DOMAINS or ".".join(low.split(".")[-2:]) in IGNORE_DOMAINS:
            return None, None
        return "domain", low

    return None, None


def load_feed(path, name=None, column=None):
    path = Path(path)
    name = name or path.stem

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.error("cannot read feed %s: %s", path, e)
        return {}, {"name": name, "path": str(path), "counts": {}, "error": str(e)}

    rows = []
    if path.suffix.lower() in (".csv", ".tsv"):
        delim = "\t" if path.suffix.lower() == ".tsv" else ","
        lines = text.splitlines()
        body, header = [], None
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("#"):
                candidate = stripped.lstrip("# ").strip()
                if any(k in candidate.lower() for k in IOC_COLUMNS):
                    header = candidate
                continue
            body.append(line)
        if header:
            log.info("  recovered the commented-out header")
            body.insert(0, header)
        try:
            reader = csv.DictReader(body, delimiter=delim)
            fields = [x for x in (reader.fieldnames or []) if x]
            if column:
                wanted = [column]
            else:
                wanted = [x for x in fields
                          if any(k in x.strip().lower() for k in IOC_COLUMNS)
                          and not any(sk in x.strip().lower()
                                      for sk in SKIP_COLUMNS)]
            if not wanted:
            
                log.warning("%s: no indicator column found among %s -- reading "
                            "as plain lines instead of exploding every cell",
                            name, ", ".join(fields[:6]) or "(no header)")
                rows = text.splitlines()
            else:
                log.info("  columns used: %s", ", ".join(wanted))
                for row in reader:
                    rows.extend(row[x] for x in wanted if row.get(x))
        except csv.Error:
            rows = text.splitlines()
    else:
        rows = text.splitlines()

    iocs, skipped = {}, 0
    for raw in rows:
        kind, value = classify(raw)
        if kind:
            iocs.setdefault(kind, {})[value] = str(raw).strip()[:120]
        elif str(raw).strip() and not str(raw).strip().startswith(("#", "//", ";")):
            skipped += 1

    try:
        dated = datetime.fromtimestamp(path.stat().st_mtime,
                                       timezone.utc).strftime("%Y-%m-%d")
    except OSError:
        dated = "unknown"

    counts = {k: len(v) for k, v in iocs.items()}
    log.info("feed %-30s %s  (%d unparsed line(s))", name, counts, skipped)
    if not counts and skipped:
        log.warning("  %s parsed to ZERO IOCs from %d lines. Check the format: "
                    "one value per line, or CSV. Values are auto-detected by "
                    "shape.", name, skipped)
    return iocs, {"name": name, "path": str(path), "dated": dated,
                  "counts": counts, "skipped": skipped}


def load_all(feeds_dir):

    feeds_dir = Path(feeds_dir)
    if not feeds_dir.is_dir():
        log.warning("no IOC feeds directory at %s. Drop hash/IP/domain lists "
                    "there -- plain text one per line, or CSV.", feeds_dir)
        return {}, []

    merged, origin, sources = {}, {}, []
    for f in sorted(feeds_dir.rglob("*")):
        if not f.is_file():
            continue
      
        if any(p.startswith(".") for p in f.relative_to(feeds_dir).parts):
            continue
        if f.suffix.lower() not in (".txt", ".csv", ".tsv", ".ioc", ".list", ""):
            continue
        iocs, meta = load_feed(f)
        sources.append(meta)
        for kind, values in iocs.items():
            bucket = merged.setdefault(kind, set())
            for v, raw in values.items():
                bucket.add(v)
                # EVERY feed that lists this indicator, not just the first.
                # Two independent feeds agreeing is materially stronger
                # evidence than one, and "listed by 3 feeds" is a better line
                # in a report than "listed by abusech_bazaar".
                origin.setdefault((kind, v), []).append(
                    (meta["name"], meta["dated"], raw))

    total = sum(len(v) for v in merged.values())
    log.info("%d IOC(s) from %d feed(s): %s", total, len(sources),
             {k: len(v) for k, v in merged.items()})
    return {"iocs": merged, "origin": origin}, sources


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------
def _hashes_from(raw):
    """{algorithm: {values}} for one artifact.

    Sysmon formats EventID 1 hashes as ONE LABELLED STRING:
        MD5=6AE9...,SHA256=7B79...,IMPHASH=A1B2...
    so the label is parsed rather than the blob regexed. That is what lets
    IMPHASH be dropped -- a plain regex would pull it in as an MD5.
    """
    out = {}

    def add(value, label=""):
        if label.lower() in SKIP_HASH_LABELS:
            return
        v = str(value).strip().strip('"').lower()
        kind = HASH_BY_LEN.get(len(v))
        if kind and RE_HEX.match(v):
            out.setdefault(kind, set()).add(v)

    payload = (raw.get("_enrich") or {}).get("payload") or {}
    blob = payload.get("Hashes") or payload.get("Hash") or ""
    for part in str(blob).split(","):
        if "=" in part:
            label, _, value = part.partition("=")
            add(value, label.strip())
        elif part.strip():
            add(part)

    for field in ("SHA1", "SHA256", "MD5", "sha1", "sha256", "md5"):
        if raw.get(field):
            add(raw[field], field)
    return out


def _ips_from(raw):
    payload = (raw.get("_enrich") or {}).get("payload") or {}
    out = set()
    for v in (payload.get("DestinationIp"), payload.get("SourceIp"),
              raw.get("ForeignAddr"), raw.get("remote"),
              raw.get("Destination Addr"), raw.get("DestinationIp")):
        if not v:
            continue
        ip = str(v).strip().strip("[]")
        if RE_IPV4.match(ip) and not any(ip.startswith(p)
                                         for p in IGNORE_IP_PREFIX):
            out.add(ip)
    return out


def _domains_from(raw):
    payload = (raw.get("_enrich") or {}).get("payload") or {}
    out = set()
    # DestinationHostname is Sysmon EventID 3's RESOLVED domain -- a C2
    # domain in a network-connection event was never correlated without it,
    # even though LOGSOURCES already routes EID 3.
    for v in (payload.get("QueryName"), payload.get("DestinationHostname"),
              payload.get("QueryResults"), raw.get("url"), raw.get("host"),
              raw.get("QueryName"), raw.get("original_path")):
        if not v:
            continue
        low = str(v).strip().lower()
        if "://" in low:
            low = low.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        # a DNS log records the FQDN with a terminating root dot
        low = low.rstrip(".")
        if RE_DOMAIN.match(low) and low not in IGNORE_DOMAINS:
            out.add(low)
    return out


# Artifact types that can carry a hash, address or domain. usn_journal is
# 324,242 rows of filesystem events with none of those fields, so scanning it
# is 60% of the work for zero possible hits.
IOC_SCOPE = ("event_log", "memory_network", "memory_process", "memory_cmdline",
             "memory_yara_hit", "browser_visit", "browser_download",
             "srum_network", "amcache_file", "network_connection",
             "yara_file_hit", "auditd", "journal", "process")

SEVERITY = {"sha256": "critical", "sha1": "critical", "md5": "high",
            "ip": "high", "domain": "high"}
# md5 scores lower than sha256: collisions are computationally feasible, and a
# 32-char value in a feed is likelier to be something else entirely
SCORE = {"sha256": 90, "sha1": 85, "md5": 65, "ip": 60, "domain": 60}
ATTACK = {"sha256": ["T1204.002"], "sha1": ["T1204.002"], "md5": ["T1204.002"],
          "ip": ["T1071.001"], "domain": ["T1071.004"]}


def _hit(artifact_id, case_id, kind, value, sources, atype):
    """One detection. `sources` is every feed that listed this indicator.

    The feed AND its date go in matched_on because "IOC matched" is not a
    finding. A reader can check the named feed, see when it was current, and
    judge the confidence -- and feeds AGE: an address that was
    command-and-control in 2024 may be an ordinary hosting provider now.
    """
    names = ", ".join(f"{n} ({d})" for n, d, _ in sources)
    n = len(sources)
    title = (f"Known-bad {kind} listed by {sources[0][0]}" if n == 1
             else f"Known-bad {kind} listed by {n} independent feeds")
    return {
        "artifact_id": artifact_id, "case_id": case_id, "engine": "ioc",
        "rule_id": f"IOC-{kind.upper()}",
        "rule_title": title,
        # more feeds agreeing = stronger evidence, capped so it cannot
        # outrank a hash match on volume alone
        "severity": SEVERITY[kind],
        "score": min(SCORE[kind] + 5 * (n - 1), 95),
        "attack": ATTACK[kind],
        "matched_on": f"{kind}={value} | feeds: {names} | {atype}",
    }


def run(case_id, feeds_dir=None, host=None, reset=True):
    """Match every artifact against the loaded feeds.

    Streams rather than fetchall(): on half a million artifacts the IOC sets
    are what should live in memory, not the table.
    """
    try:
        from config import IOC_FEEDS_DIR
        default_dir = IOC_FEEDS_DIR
    except ImportError:
        default_dir = Path("intel") / "feeds"
    feeds_dir = Path(feeds_dir or default_dir)

    loaded, sources = load_all(feeds_dir)
    if reset:
        cleared = clear_detections(case_id, engine="ioc")
        if cleared:
            log.info("cleared %d IOC detection(s) from the previous pass",
                     cleared)

    if not loaded or not loaded.get("iocs"):
        log.warning("no IOCs loaded from %s; NO IOC correlation was performed. "
                    "That is a coverage gap, not a clean result.", feeds_dir)
        return {"hits": 0, "scanned": 0, "sources": sources, "ioc_counts": {}}

    iocs, origin = loaded["iocs"], loaded["origin"]

    hits, seen, scanned = [], set(), 0
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        scope = " OR ".join("artifact_type LIKE ? ESCAPE '\\'"
                            for _ in IOC_SCOPE)
        sql = (f"SELECT id, artifact_type, raw_data FROM {A} "
               f"WHERE case_id = ? AND ({scope})")
        params = [case_id] + [t.replace("_", "\\_") + "%" for t in IOC_SCOPE]
        if host:
            sql += " AND host = ?"
            params.append(host)

        cur = conn.execute(sql, params)
        while True:
            chunk = cur.fetchmany(5000)
            if not chunk:
                break
            for aid, atype, raw_json in chunk:
                scanned += 1
                try:
                    raw = json.loads(raw_json) if raw_json else {}
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(raw, dict):
                    continue

                # hashes: each algorithm against ITS OWN SET ONLY. Checking a
                # 64-char value against the MD5 set is wasted work, and a
                # stray 32-char value in a feed must not be able to match an
                # IMPHASH-length field.
                for kind, values in _hashes_from(raw).items():
                    pool = iocs.get(kind)
                    if not pool:
                        continue
                    for h in values:
                        if h in pool and (aid, kind, h) not in seen:
                            seen.add((aid, kind, h))
                            hits.append(_hit(aid, case_id, kind, h,
                                             origin[(kind, h)], atype))

                for kind, extract in (("ip", _ips_from), ("domain", _domains_from)):
                    pool = iocs.get(kind)
                    if not pool:
                        continue
                    for v in extract(raw):
                        if v in pool and (aid, kind, v) not in seen:
                            seen.add((aid, kind, v))
                            hits.append(_hit(aid, case_id, kind, v,
                                             origin[(kind, v)], atype))

        n = insert_detections(hits, conn=conn) if hits else 0

    log.info("IOC correlation: %d hit(s) across %d artifacts", n, scanned)
    if not n:
        log.info("no matches. That is a RESULT, not an absence -- the feeds "
                 "were applied and nothing on this host appeared in them.")
    return {"hits": n, "scanned": scanned, "sources": sources,
            "ioc_counts": {k: len(v) for k, v in iocs.items()}}


def summary(case_id):
    """IOC hits for the report, grouped by severity then time."""
    with connection() as conn:
        objs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        A = "v_artifacts" if "v_artifacts" in objs else "artifacts"
        return conn.execute(f"""
            SELECT d.rule_id, d.severity, d.matched_on, a.artifact_type,
                   a.timestamp_utc, a.description, a.host
            FROM detections d JOIN {A} a ON a.id = d.artifact_id
            WHERE a.case_id = ? AND d.engine = 'ioc'
            ORDER BY d.score DESC, a.timestamp_utc""", (case_id,)).fetchall()