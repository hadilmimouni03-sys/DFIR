import logging
from pathlib import Path

from acquisition.run_tool import run_tool
from config import VOLATILITY_CMD, VOLATILITY_SYMBOLS_DIR
from database.database import register_evidence
from normalization.linux_vol_specs import LINUX_MALWARE_PLUGINS, LINUX_PLUGINS

log = logging.getLogger(__name__)

PLUGIN_TIMEOUT = 2 * 3600
YARA_TIMEOUT = 4 * 3600

try:
    from config import VOLATILITY_VERSION
except ImportError:
    VOLATILITY_VERSION = "volatility3 (version not recorded in config.py)"

WINDOWS_PLUGINS = {
    "pslist":  "windows.pslist.PsList",
    "psscan":  "windows.psscan.PsScan",
    "pstree":  "windows.pstree.PsTree",
    "netscan": "windows.netscan.NetScan",
    "cmdline": "windows.cmdline.CmdLine",
    "malfind": "windows.malfind.Malfind",
    "svcscan": "windows.svcscan.SvcScan",
}


PLUGIN_SETS = {
    "windows": {
        "core": WINDOWS_PLUGINS,
        "malware": {},
    },
    "linux": {
        "core":    LINUX_PLUGINS,
        "malware": LINUX_MALWARE_PLUGINS,
    },
}





def select_plugins(os_name="windows", plugin_set="core"):

    groups = PLUGIN_SETS.get(os_name, PLUGIN_SETS["windows"])
    wanted = ["core", "malware"] if plugin_set == "all" \
        else [s.strip() for s in str(plugin_set).split(",") if s.strip()]

    plugins = {}
    for g in wanted:
        if g not in groups:
            log.warning("unknown plugin set %r for %s; valid: %s",
                        g, os_name, ", ".join(groups))
            continue
        if not groups[g]:
            log.info("no %s plugins defined for %s", g, os_name)
            continue
        plugins.update(groups[g])
    return plugins


def _check_specs(plugins):
 
    try:
        from normalization.specs import VOL_SPECS
    except ImportError:
        return
    missing = [k for k in plugins if k not in VOL_SPECS]
    if missing:
        log.warning("%d plugin(s) have no VOL_SPECS entry, so their output "
                    "will be ingested as NOTHING: %s",
                    len(missing), ", ".join(sorted(missing)))


def _base_cmd():
  
    cmd = list(VOLATILITY_CMD) + ["-q", "-r", "json"]
    if Path(VOLATILITY_SYMBOLS_DIR).is_dir():
        cmd += ["-s", str(VOLATILITY_SYMBOLS_DIR)]
    return cmd


# --------------------------------------------------------------------------
def run_volatility(dump_path, out_dir, case_id=None, host=None,
                   os_name="windows", plugins=None, plugin_set="core",
                   dry_run=False):
 
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if plugins is None:
        plugins = select_plugins(os_name, plugin_set)
    if not plugins:
        log.error("no plugins selected for os=%s set=%s", os_name, plugin_set)
        return {"results": {}, "failed": [], "out_dir": out_dir}

    _check_specs(plugins)
    log.info("running %d %s plugin(s) [%s]", len(plugins), os_name, plugin_set)

    results, failed = {}, []
    for name, plugin in plugins.items():
        target = out_dir / f"{name}.json"
        res = run_tool(_base_cmd() + ["-f", str(dump_path), plugin],
                       timeout=PLUGIN_TIMEOUT, stdout_path=target,
                       dry_run=dry_run)
        results[name] = res
        if res["ok"]:
            log.info("  %-22s ok (%.0fs)", name, res["seconds"])
        else:
            failed.append(name)
            log.warning("  %-22s FAILED: %s", name, (res["stderr"] or "")[:160])

            target.unlink(missing_ok=True)

    if case_id and host and not dry_run:
        register_evidence(
            case_id, host, "volatility", out_dir,
            tool_version=VOLATILITY_VERSION,
            tool_cmdline=f"{len(plugins)} plugins [{plugin_set}] against {dump_path}",
            os_name=os_name, status="ok" if not failed else "partial",
            error=None if not failed else f"plugins failed: {', '.join(failed)}")

    if failed:
        log.warning("%d of %d plugins failed. That gap belongs in the report's "
                    "limitations section, not in silence.", len(failed), len(plugins))
    return {"results": results, "failed": failed, "out_dir": out_dir,
            "plugins": list(plugins)}
