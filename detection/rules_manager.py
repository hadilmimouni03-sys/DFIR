import json
import logging
import re
import shutil
import subprocess
import urllib.request
import zipfile
import yaml
from datetime import datetime, timezone
from pathlib import Path

from config import YARA_RULES_DIR

log = logging.getLogger(__name__)


MANIFEST = "rulesets.json"

SOURCES = {
    "dfir_report": {
        "kind": "yara",
        "url": "https://github.com/The-DFIR-Report/Yara-Rules",
        "branch": "main",
        "licence": "GPL-3.0 -- commercial use requires their permission",
        "note": "One folder per published incident report. A hit can cite "
                "thedfirreport.com/<report>, which is a materially better "
                "finding than 'a community rule matched'.",
    },
    "sigmahq": {
        "kind": "sigma",
        "url": "https://github.com/SigmaHQ/sigma",
        "branch": "master",          
        "licence": "DRL-1.1 -- use and modification permitted, "
                   "ATTRIBUTION REQUIRED",
        "translate": True,
        "note": "Used two ways. INDEXED into a worksheet pairing each internal "
                "rule with the Sigma rules sharing its technique, for their "
                "exclusion logic and externally-argued severity levels. And "
                "TRANSLATED automatically where the translation is EXACT: "
                "Sigma's condition grammar is arbitrary boolean, ours is "
                "all/any with nesting, so a rule whose shape, field modifiers "
                "or logsource cannot be expressed is REFUSED with a stated "
                "reason in sigma_refused.txt. Never approximated -- an "
                "approximated rule compiles, validates, scans and matches "
                "nothing, which is indistinguishable from a clean host. Every "
                "translated rule is verified against real evidence before "
                "being written. The worksheet is still produced, because the "
                "refusals need human review.",
    },
}



RULE_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", re.M)
IMPORT_RE = re.compile(r'^\s*import\s+"(\w+)"', re.M)
META_RE = re.compile(r'([\w&.]+)\s*=\s*"([^"]*)"')
SIGMA_DIRS = ("rules",)
SIGMA_DIRS_EXTRA = ("rules-threat-hunting", "rules-emerging-threats")
_SIGMA_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)

FILE_ONLY = [
    (re.compile(r"\bpe\.\w+"),     "pe module"),
    (re.compile(r"\belf\.\w+"),    "elf module"),
    (re.compile(r"\bmacho\.\w+"),  "macho module"),
    (re.compile(r"\bdotnet\.\w+"), "dotnet module"),
    (re.compile(r"\bhash\.\w+"),   "hash module"),
    (re.compile(r"\bmath\.\w+"),   "math module"),
    (re.compile(r"\bfilesize\b"),  "filesize"),
    (re.compile(r"\bat\s+0\b"),    "offset anchor 'at 0'"),
]

ATTACK_KEYS = ("attack", "mitre", "mitre_att&ck", "mitre_attack", "technique",
               "att&ck", "tactic")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

def split_rules(text):
  
    for m in RULE_RE.finditer(text):
        start = m.start()
        i = text.find("{", m.end())
        if i == -1:
            continue
        depth, opened = 0, False
        while i < len(text):
            c = text[i]
 
            if c == '"':
                i += 1
                while i < len(text):
                    if text[i] == "\\":
                        i += 2
                        continue
                    if text[i] == '"':
                        break
                    i += 1
                i += 1
                continue
 
            if c == "/" and text[i + 1:i + 2] == "*":
                end = text.find("*/", i + 2)
                i = len(text) if end == -1 else end + 2
                continue
 
            if c == "/" and text[i + 1:i + 2] == "/":
                end = text.find("\n", i)
                i = len(text) if end == -1 else end + 1
                continue
 
            if c == "{":
                depth += 1
                opened = True
            elif c == "}":
                depth -= 1
                if opened and depth == 0:
                    yield m.group(1), text[start:i + 1]
                    break
            i += 1
 


def extract_attack(body):
   
    head = body.split("strings:")[0]
    meta = dict(META_RE.findall(head))
    found = []
    for k, v in meta.items():
        if k.lower() in ATTACK_KEYS or "attack" in k.lower():
            found += _TECHNIQUE.findall(v)
    return sorted({t.upper() for t in found})



def _git_version(repo):
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def fetch(name, dest=None, use_git=True):
   
    src = SOURCES[name]
    dest = Path(dest or (Path(YARA_RULES_DIR).parent / "_sources" / name))
    dest.parent.mkdir(parents=True, exist_ok=True)

    if use_git and shutil.which("git"):
        if (dest / ".git").is_dir():
            log.info("updating %s", name)
            subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                           capture_output=True, text=True, timeout=300)
        else:
            log.info("cloning %s from %s", name, src["url"])
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            subprocess.run(["git", "clone", "--depth", "1",
                            "--branch", src["branch"], src["url"], str(dest)],
                           capture_output=True, text=True, timeout=600)
        version = _git_version(dest)
        if version:
            return dest, f"git:{version}"

    url = f"{src['url']}/archive/refs/heads/{src['branch']}.zip"
    log.info("git unavailable, downloading %s", url)
    tmp = dest.with_suffix(".zip")
    try:
        urllib.request.urlretrieve(url, tmp)
    except OSError as e:
        raise SystemExit(f"could not fetch {name}: {e}\n"
                         f"Clone it by hand into {dest} and re-run "
                         f"`main.py rules --update --no-fetch`.")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    with zipfile.ZipFile(tmp) as z:
        z.extractall(dest.parent)
    inner = next(dest.parent.glob(f"{Path(src['url']).name}-{src['branch']}"), None)
    if inner:
        inner.rename(dest)
    tmp.unlink(missing_ok=True)
    return dest, "zip:" + datetime.now(timezone.utc).strftime("%Y-%m-%d")



def _rule_priority(entry):
 
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev = str(entry.get("severity", "")).lower()
    return (order.get(sev, 5), 0 if entry["attack"] else 1, entry["name"])


def triage(name, src_dir, out_dir=None, max_memory_rules=None):
   
    src_dir = Path(src_dir)
    out_dir = Path(out_dir or YARA_RULES_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    cap = max_memory_rules

    files = sorted(list(src_dir.rglob("*.yar")) + list(src_dir.rglob("*.yara")))
    memory, fileonly, seen = [], [], set()
    reasons, modules, duplicates = {}, set(), []
    with_attack = 0

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        modules |= set(IMPORT_RE.findall(text))
        rel = f.relative_to(src_dir)
        report = rel.parts[0] if len(rel.parts) > 1 else "root"

        for rule_name, body in split_rules(text):
            if rule_name in seen:
                duplicates.append(f"{rule_name} ({rel})")
                continue
            seen.add(rule_name)
            attack = extract_attack(body)
            if attack:
                with_attack += 1
            sev = re.search(r'severity\s*=\s*"(\w+)"', body.split("strings:")[0])
            entry = {"name": rule_name, "body": body, "report": report,
                     "path": str(rel), "attack": attack,
                     "severity": sev.group(1) if sev else ""}
            why = [w for pat, w in FILE_ONLY if pat.search(body)]
            for w in why:
                reasons[w] = reasons.get(w, 0) + 1
            (fileonly if why else memory).append(entry)

    def write(path, entries, limit=None, kind=""):
        if limit and len(entries) > limit:
    
            entries = sorted(entries, key=_rule_priority)
            kept, dropped = entries[:limit], entries[limit:]
            log.warning("%s: capped at %d of %d %s rules. These %d were NOT "
                        "written and will NOT run: %s",
                        name, limit, len(entries), kind, len(dropped),
                        ", ".join(e["name"] for e in dropped[:20])
                        + (" ..." if len(dropped) > 20 else ""))
            log.warning("  a capped ruleset can miss the one rule that "
                        "mattered. Remove the cap unless you hit a real "
                        "resource limit.")
        else:
            kept = entries
            src = SOURCES.get(name, {})
            used = sorted(modules)
            imports = "".join(f'import "{m}"\n' for m in used)
            header = (f"/*\n"
                  f"    {name} -- {len(kept)} {kind} rules\n"
                  f"    Generated by detection/rules_manager.py. Do not edit.\n"
                  f"    Source:  {src.get('url','?')}\n"
                  f"    Licence: {src.get('licence','unknown')}\n"
                  f"*/\n{imports}\n")
        path.write_text(header + "\n\n".join(
            f"// {name} report {e['report']}  ({e['path']})"
            + (f"  attack={','.join(e['attack'])}" if e["attack"] else "")
            + f"\n{e['body']}" for e in kept), encoding="utf-8")
        return len(kept)

    if duplicates:
        log.info("%s: %d rule(s) skipped as duplicate names (YARA requires "
                 "unique names, so this is correct -- but a rule you expected "
                 "may be absent): %s", name, len(duplicates),
                 ", ".join(duplicates[:8])
                 + (" ..." if len(duplicates) > 8 else ""))

    n_file = write(out_dir / f"{name}_files.yar", fileonly, kind="file")
    n_mem = write(out_dir / f"{name}_memory.yar", memory, cap, kind="memory")

    return {
        "rules_total": len(memory) + len(fileonly),
        "file_rules": n_file, "memory_rules": n_mem,
        "memory_available": len(memory), "capped_at": cap or "none",
        "with_attack_tags": with_attack,
        "file_only_reasons": reasons,
        "modules": sorted(modules),
        "source_files": len(files),
        "duplicates": len(duplicates),
    }

def index_sigma(name, src_dir, out_dir=None, include_extra=False):
    """Index a Sigma corpus by ATT&CK technique and write the mining worksheet.
index
    Nothing here is compiled or executed -- see the note in SOURCES. What we
    extract is the part that does not need translating:

      * `filter*` blocks   -- exclusion logic proven across many environments,
                              which is the baseline we cannot derive ourselves
                              from a single host.
      * `falsepositives:`  -- the authors' plain-English list of benign causes.
      * `level:`           -- an externally justified severity to calibrate
                              against, instead of our own 88% high-or-critical.
    """
    src_dir = Path(src_dir)
    out_dir = Path(out_dir or YARA_RULES_DIR)
    worksheet = out_dir.parent / "sigma_worksheet.md"

    by_tech, scanned, with_filters = {}, 0, 0
    dirs = SIGMA_DIRS + (SIGMA_DIRS_EXTRA if include_extra else ())
    for base in dirs:
        root = src_dir / base
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.yml")):
            try:
                doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            scanned += 1
            det = doc.get("detection") or {}
            if any(str(k).startswith("filter") for k in det):
                with_filters += 1
            for tag in (doc.get("tags") or []):
                m = _SIGMA_TECH.match(str(tag))
                if m:
                    by_tech.setdefault(m.group(1).upper(), []).append((p, doc))

    _write_sigma_worksheet(worksheet, src_dir, by_tech, scanned)

    log.info("%s: indexed %d rules covering %d techniques (%d carry exclusion "
             "logic) -> %s", name, scanned, len(by_tech), with_filters, worksheet)
    return {
        "rules_total": scanned,
        "file_rules": 0, "memory_rules": 0,   # nothing is compiled
        "techniques_indexed": len(by_tech),
        "rules_with_filters": with_filters,
        "worksheet": str(worksheet),
    }


def _write_sigma_worksheet(path, src_dir, by_tech, scanned):
    """One section per OUR rule, with the Sigma rules that share a technique."""
    try:
        from detection.engine import load_rules          # lazy: avoids a cycle
        mine = load_rules()
    except Exception as e:
        log.warning("no internal rules to cross-reference (%s); "
                    "writing the technique index only", str(e)[:120])
        mine = []

    out = [f"# Sigma worksheet\n\n{len(mine)} internal rules vs "
           f"{scanned:,} Sigma rules covering {len(by_tech)} techniques.\n\n"
           "For each rule: read `falsepositives`, copy exclusion logic from "
           "`filter*`, compare `level` against your severity, then record "
           "`sigma_source:` and `sigma_licence: DRL-1.1` on the rule.\n"]

    mine = [r for r in mine if not str(r.get("_file", "")).startswith("sigma_derived")]
    orphans = []
    for r in sorted(mine, key=lambda x: x["id"]):
        techs = [str(t).upper() for t in (r.get("attack") or [])]
        matches = {str(p): d for t in techs for p, d in by_tech.get(t, [])}
        out.append(f"\n---\n\n## {r['id']} -- {r['title']}\n\n"
                   f"- yours: severity `{r['severity']}`, attack `{techs}`\n")
        if not matches:
            orphans.append(r["id"])
            out.append("- **NO SIGMA COUNTERPART.** No external evidence about "
                       "this rule's precision exists. Highest risk: review by "
                       "hand and record `sigma_source: none  # <why>`.\n")
            continue
        out.append(f"- {len(matches)} Sigma rule(s) share a technique\n")
        for p, doc in sorted(matches.items())[:6]:
            det = doc.get("detection") or {}
            filters = {k: v for k, v in det.items() if str(k).startswith("filter")}
            out.append(f"\n### {doc.get('title')} &mdash; `level: "
                       f"{doc.get('level')}`\n\n"
                       f"`{Path(p).relative_to(src_dir)}`\n")
            for fp in (doc.get("falsepositives") or []):
                out.append(f"- known FP: {fp}\n")
            if filters:
                out.append("\n```yaml\n"
                           + yaml.dump(filters, default_flow_style=False)
                           + "```\n")

    out.append(f"\n---\n\n## No Sigma counterpart ({len(orphans)})\n\n"
               + (", ".join(orphans) or "none") + "\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(out), encoding="utf-8")

def validate(out_dir=None):
    out_dir = Path(out_dir or YARA_RULES_DIR)
    try:
        import yara
    except ImportError:
        log.warning("yara-python not installed; cannot verify rulesets compile. "
                    "Volatility will fail with a less clear message.")
        return {}
    results = {}
    for f in sorted(out_dir.glob("*.yar")):
        try:
            yara.compile(str(f))
            results[f.name] = "ok"
        except Exception as e:
            results[f.name] = f"FAILED: {str(e)[:160]}"
    return results



def manifest_path(out_dir=None):
    return Path(out_dir or YARA_RULES_DIR).parent / MANIFEST


def read_manifest(out_dir=None):
    p = manifest_path(out_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _write_manifest(data, out_dir=None):
    manifest_path(out_dir).write_text(json.dumps(data, indent=2), encoding="utf-8")


def update(names=None, out_dir=None, fetch_remote=True,
           max_memory_rules=None, translate=False, verify_case=None, refresh=False):

    names = names or list(SOURCES)
    data = read_manifest(out_dir)

    for name in names:
        if name not in SOURCES:
            log.error("unknown ruleset %r; known: %s", name, ", ".join(SOURCES))
            continue
        local = Path(YARA_RULES_DIR).parent / "_sources" / name
        if fetch_remote and (refresh or not local.is_dir()):
            path, version = fetch(name)
        elif local.is_dir():
            path = local
            version = _git_version(path) or "local"
            log.info("%s: using the local copy at %s (%s). Pass --refresh to "
                     "pull updates.", name, path, version)
        else:
            path = Path(YARA_RULES_DIR).parent / "_sources" / name
            version = _git_version(path) or "local"
            if not path.is_dir():
                log.error("%s not present at %s and --no-fetch given", name, path)
                continue

        kind = SOURCES[name].get("kind", "yara")
        if kind == "sigma":
           
            if translate and SOURCES[name].get("translate"):
                from config import DETECTION_RULES_DIR
                stale = Path(DETECTION_RULES_DIR) / "sigma_derived.yaml"
                if stale.exists():
                    stale.unlink()
                    log.info("removed the previous sigma_derived.yaml before "
                             "re-indexing")

            stats = index_sigma(name, path, out_dir)
            if translate and SOURCES[name].get("translate"):
                from detection.sigma_translator import translate_corpus
                stats.update(translate_corpus(path, verify_case=verify_case, min_level="high" ))
            elif SOURCES[name].get("translate"):
                log.info("%s: indexed only. Pass --translate to import rules.",
                         name)
        else:
            stats = triage(name, path, out_dir,
                           max_memory_rules=max_memory_rules)

        data[name] = {
            "kind": kind,
            "version": version,
            "updated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_url": SOURCES[name]["url"],
            "licence": SOURCES[name]["licence"],
            "source_path": str(path),
            **stats,
        }
        if kind == "yara":
            log.info("%s %s: %d rules -> %d file, %d memory (of %d, capped at %s)",
                     name, version, stats["rules_total"], stats["file_rules"],
                     stats["memory_rules"], stats["memory_available"],stats["capped_at"])
            if stats["with_attack_tags"] < stats["rules_total"] * 0.5:
                log.warning("%s: only %d of %d rules carry ATT&CK ids. Detections "
                        "from the rest cannot be placed on the matrix -- "
                        "attack_mapper counts them as unmapped.",
                        name, stats["with_attack_tags"], stats["rules_total"])

    own = Path(out_dir or YARA_RULES_DIR) / "memory.yar"
    if own.exists():
        n = len(RULE_RE.findall(own.read_text(encoding="utf-8", errors="replace")))
        data["minidfir_memory"] = {
            "version": "bundled", "rules_total": n, "memory_rules": n,
            "file_rules": 0, "source_url": "hand-written",
            "licence": "same as the project",
            "updated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    data["_validation"] = validate(out_dir)
    _write_manifest(data, out_dir)
    return data


def status(out_dir=None):
    data = read_manifest(out_dir)
    if not data:
        print("no rulesets installed. Run:  python main.py rules --update")
        return data
    print(f"{'ruleset':<22} {'version':<18} {'file':>6} {'mem':>6} {'attack':>7}  updated")
    print("-" * 88)
    for name, d in data.items():
        if name.startswith("_"):
            continue
        print(f"{name:<22} {str(d.get('version','?')):<18} "
              f"{d.get('file_rules',0):>6} {d.get('memory_rules',0):>6} "
              f"{d.get('with_attack_tags','-'):>7}  {d.get('updated_utc','?')}")
    v = data.get("_validation", {})
    if v:
        print("\ncompilation:")
        for f, r in v.items():
            print(f"  [{'ok  ' if r == 'ok' else 'FAIL'}] {f}"
                  + ("" if r == "ok" else f"\n         {r}"))
    return data