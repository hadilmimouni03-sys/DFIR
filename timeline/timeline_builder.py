import csv
import html
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

from config import output_dir
from database.database import connection
from normalization.normalizer import CANONICAL, normalize_timestamp

log = logging.getLogger(__name__)

LAYERS = {
    "execution":   ["prefetch_execution", "amcache_file", "shimcache",
                    "user_assist_execution", "bam_execution", "activity",
                    "shell_history", "memory_shell_history", "memory_cmdline",
                    "auditd", "process", "memory_process",
                    "memory_process_tree",
                    "registry_program_execution"],

    "persistence": ["registry_run", "registry_autoruns", "registry_services",
                    "registry_user_accounts", "registry_installed_software",
                    "scheduled_task", "service", "memory_service",
                    "cron_job", "systemd_unit", "ssh_authorized_key",
                    "user_account", "persistence_file", "package_event",
                    "memory_kernel_module", "memory_hidden_module",
                    "memory_ebpf_program"],

    "files":       ["usn_journal", "lnk_file", "jumplist", "shellbag",
                    "recycle_bin", "mft_file", "file_entry", "trash_item",
                    "memory_open_file", "memory_loaded_library",
                    "yara_file_hit", "memory_yara_hit",
                    "registry_user_activity", "registry_cloud_storage",
                    "registry_microsoft_office", "registry_volume_shadow_copies"],

    "browser":     ["browser_download", "browser_visit",
                    "registry_web_browsers"],

    "network":     ["srum_network", "memory_network", "network_connection",
                    "memory_netfilter_hook", "memory_net_interface",
                    "registry_network_shares"],

    "logs":        ["event_log", "auth_log", "journal", "auditd"],

    "rootkit":     ["memory_injection", "memory_hidden_module",
                    "memory_module_discrepancy", "memory_kernel_module",
                    "memory_ebpf_program", "memory_syscall_hook",
                    "memory_idt_hook", "memory_tty_hook",
                    "memory_ftrace_hook", "memory_netfilter_hook",
                    "memory_protocol_hook", "memory_process_spoof",
                    "memory_network_scan", "memory_mount"],

    "context":     ["system_identity", "registry_system_info",
                    "registry_devices", "registry_threat_hunting",
                    "package_event", "registry_",
                    "memory_environment", "memory_capability",
                    "memory_shared_creds"],
}


COLUMNS = ("ts_utc", "ts_type", "artifact_id", "host", "artifact_type",
           "description", "hits", "score")


def _build_query(case_id, start=None, end=None, artifact_type=None, layer=None,
                 host=None, keyword=None, hide_noise=True, flagged_only=False,
                 limit=None):
    sql = ["SELECT " + ", ".join(COLUMNS) + " FROM v_timeline WHERE case_id = ?"]
    params = [case_id]

    if hide_noise:
        sql.append("AND is_noise = 0")
    if flagged_only:
        sql.append("AND hits > 0")
    if start:
        sql.append("AND ts_utc >= ?"); params.append(start)
    if end:
        sql.append("AND ts_utc <= ?"); params.append(end)
    if host:
        sql.append("AND host = ?"); params.append(host)
    if layer:
        types = LAYERS.get(layer)
        if types is None:
            raise ValueError(f"unknown layer {layer!r}; valid: {', '.join(LAYERS)}")
        sql.append("AND (" + " OR ".join("artifact_type LIKE ?" for _ in types) + ")")
        params += [f"{t}%" for t in types]
    if artifact_type:
        sql.append("AND artifact_type LIKE ?"); params.append(f"%{artifact_type}%")
    if keyword:
        sql.append("AND description LIKE ?"); params.append(f"%{keyword}%")

    sql.append("ORDER BY ts_utc")
    if limit:
        sql.append(f"LIMIT {int(limit)}")      
    return " ".join(sql), params


def iter_timeline(case_id, **kw):
 
    sql, params = _build_query(case_id, **kw)
    with connection() as conn:
        cur = conn.execute(sql, params)
        while True:
            chunk = cur.fetchmany(10000)
            if not chunk:
                return
            yield from chunk


def get_timeline(case_id, **kw):
    return list(iter_timeline(case_id, **kw))


def pivot(case_id, timestamp, minutes=15, **kw):

    canon = normalize_timestamp(timestamp)
    if canon is None:
        raise ValueError(f"cannot parse timestamp {timestamp!r}")
    t = datetime.strptime(canon, CANONICAL)
    return get_timeline(case_id,
                        start=(t - timedelta(minutes=minutes)).strftime(CANONICAL),
                        end=(t + timedelta(minutes=minutes)).strftime(CANONICAL), **kw)


def show(rows, width=120):
    for ts, ts_type, aid, host, atype, desc, hits, score in rows:
        mark = "!" if hits else " "
        print(f"{mark}{ts}  {host:<12}  {atype:<22}  {(ts_type or ''):<18}  {desc[:width]}")


def export_csv(case_id, path, **kw):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        for row in iter_timeline(case_id, **kw):     # streamed, not fetchall()
            w.writerow(row)
            n += 1
    log.info("%d rows -> %s", n, path)
    return n


HTML_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>__TITLE__</title><style>
body{font:13px/1.4 -apple-system,Segoe UI,sans-serif;margin:0;padding:12px;background:#0f1115;color:#d8dee9}
#bar{position:sticky;top:0;z-index:2;background:#0f1115;padding:8px 0;border-bottom:1px solid #2a2f3a}
input,select,button{background:#1a1f27;color:#d8dee9;border:1px solid #2a2f3a;padding:6px;border-radius:4px;font-size:13px}
#q{width:320px}
button{cursor:pointer}
table{border-collapse:collapse;width:100%;margin-top:8px}
th{text-align:left;padding:6px;border-bottom:2px solid #2a2f3a;position:sticky;top:46px;background:#0f1115;cursor:pointer;z-index:1}
td{padding:4px 6px;border-bottom:1px solid #1a1f27;vertical-align:top}
td:nth-child(1){white-space:nowrap;color:#88c0d0;font-family:monospace}
td:nth-child(2){white-space:nowrap;color:#a3be8c}
td:nth-child(3){white-space:nowrap;color:#ebcb8b}
td:nth-child(4){white-space:nowrap;color:#7b8394;font-size:11px}
tr:hover{background:#1a1f27}
tr.flag{background:#3b2a2e}
tr.flag td:nth-child(1){color:#bf616a;font-weight:bold}
#count{margin-left:12px;color:#7b8394}
#note{color:#7b8394;font-size:11px;margin-left:12px}
</style></head><body>
<div id="bar">
<input id="q" placeholder="search (space = AND, -word = exclude)">
<select id="host"><option value="">all hosts</option></select>
<select id="type"><option value="">all types</option></select>
<button id="flagonly">flagged only</button>
<span id="count"></span><span id="note">__NOTE__</span>
</div>
<table><thead><tr>
<th data-k="t">Time</th><th data-k="h">Host</th><th data-k="a">Type</th>
<th data-k="k">Which timestamp</th><th data-k="d">Description</th>
</tr></thead>
<tbody id="rows"></tbody></table>
<script>
const DATA = __DATA__;
let view = DATA, sortKey = null, asc = true, flagOnly = false;
const sel = document.getElementById('type'), hsel = document.getElementById('host');
[...new Set(DATA.map(r=>r.a))].sort().forEach(t=>{
  const o=document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o);});
[...new Set(DATA.map(r=>r.h))].sort().forEach(h=>{
  const o=document.createElement('option'); o.value=h; o.textContent=h; hsel.appendChild(o);});
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML;}
function render(){
  document.getElementById('rows').innerHTML = view.slice(0,3000).map(r=>
    `<tr class="${r.f?'flag':''}"><td>${esc(r.t)}</td><td>${esc(r.h)}</td><td>${esc(r.a)}</td><td>${esc(r.k)}</td><td>${esc(r.d)}</td></tr>`
  ).join('');
  document.getElementById('count').textContent =
    view.length.toLocaleString() + ' rows' + (view.length>3000 ? ' (showing first 3000)' : '');
}
function filter(){
  const q = document.getElementById('q').value.toLowerCase().trim();
  const type = sel.value, host = hsel.value;
  const terms = q ? q.split(/\\s+/) : [];
  view = DATA.filter(r=>{
    if(flagOnly && !r.f) return false;
    if(type && r.a !== type) return false;
    if(host && r.h !== host) return false;
    const hay = (r.t+' '+r.h+' '+r.a+' '+r.k+' '+r.d).toLowerCase();
    return terms.every(t => t.startsWith('-') ? !hay.includes(t.slice(1)) : hay.includes(t));
  });
  if(sortKey) applySort();
  render();
}
function applySort(){
  view = [...view].sort((x,y)=>{
    const a=x[sortKey]??'', b=y[sortKey]??'';
    return (a<b?-1:a>b?1:0) * (asc?1:-1);   // stable on ties, unlike (a>b?1:-1)
  });
}
document.getElementById('q').addEventListener('input', filter);
sel.addEventListener('change', filter);
hsel.addEventListener('change', filter);
document.getElementById('flagonly').onclick = function(){
  flagOnly = !flagOnly;
  this.style.background = flagOnly ? '#bf616a' : '#1a1f27';
  filter();
};
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{
  const k = th.dataset.k;
  if(k === sortKey){ asc = !asc; } else { sortKey = k; asc = true; }
  applySort(); render();
});
filter();
</script></body></html>"""

MAX_EMBEDDED_ROWS = 20000


def export_html(case_id, path, title="DFIR Timeline", max_rows=MAX_EMBEDDED_ROWS, **kw):
    rows, truncated = [], False
    for i, r in enumerate(iter_timeline(case_id, **kw)):
        if i >= max_rows:
            truncated = True
            break
        ts, ts_type, aid, host, atype, desc, hits, score = r
        # FIX (P1-4): flagged is driven by detections joined on artifact_id, not
        # by matching timestamp strings. Event logs share timestamps constantly.
        rows.append({"t": ts, "h": host, "a": atype, "k": ts_type or "",
                     "d": desc or "", "f": 1 if hits else 0, "i": aid})

    # FIX (P0-6): json.dumps does not escape "/". A literal </script> inside any
    # URL or command line terminates the script element and blanks the page.
    payload = json.dumps(rows, ensure_ascii=False).replace("</", "<\\/")
    note = (f"capped at {max_rows:,} rows - use the CSV export for the full set"
            if truncated else "")

    # __DATA__ last: it holds attacker-influenced text, and substituting it
    # first would let a description containing "__TITLE__" rewrite the page.
    page = (HTML_PAGE
            .replace("__TITLE__", html.escape(title))
            .replace("__NOTE__", html.escape(note))
            .replace("__DATA__", payload))

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(page, encoding="utf-8")
    log.info("%d rows -> %s%s", len(rows), path, " (truncated)" if truncated else "")
    return len(rows)


def export_all(case_id, outdir=None):
    outdir = Path(outdir or output_dir(case_id))
    written = {}
    for name in LAYERS:
        n = export_html(case_id, outdir / f"timeline_{name}.html",
                        title=f"DFIR Timeline - {name}", layer=name)
        if n:
            written[name] = n
        else:
            (outdir / f"timeline_{name}.html").unlink(missing_ok=True)
    n = export_html(case_id, outdir / "timeline_flagged.html",
                    title="DFIR Timeline - flagged", flagged_only=True,
                    hide_noise=False)
    written["flagged"] = n
    return written
