from pathlib import Path
import shutil
import sys
import os

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "database" / "dfir_db.db"))

EVIDENCE_ROOT = BASE_DIR / "evidence"
OUTPUT_DIR = BASE_DIR / "output"
WINPMEM_VERSION    = os.getenv("WINPMEM_VERSION", "go-winpmem 1.0-rc2")
VOLATILITY_VERSION = os.getenv("VOLATILITY_VERSION", "volatility3 2.28.0")  
KAPE_VERSION = os.getenv("KAPE_VERSION", "KAPE 1.3.0.2")   
AVML_VERSION = os.getenv("AVML_VERSION", "avml 0.14.0")
UAC_VERSION  = os.getenv("UAC_VERSION",  "uac 3.x")        

def _safe(name: str) -> str:
    keep = "-_. "
    cleaned = "".join(c if (c.isalnum() or c in keep) else "_" for c in str(name))
    return cleaned.strip().strip(".") or "unnamed"


def evidence_dir(case_id: str, host: str, os_name: str = "windows") -> Path:
    return EVIDENCE_ROOT / _safe(case_id) / _safe(host) / os_name


def output_dir(case_id: str) -> Path:
    return OUTPUT_DIR / _safe(case_id)


KAPE_EXE_PATH = os.getenv(
    "KAPE_PATH", r"C:\Users\hadil\Desktop\DF Tools\KAPE\kape.exe")

WINPMEM_EXE_PATH = os.getenv(
    "WINPMEM_PATH",
    r"C:\Users\hadil\Desktop\DF Tools\go-winpmem_amd64_1.0-rc2_signed.exe")

MFTECMD_PATH = os.getenv("MFTECMD_PATH") or str(
    Path(KAPE_EXE_PATH).parent / "Modules" / "bin" / "MFTECmd.exe")


def _volatility_cmd():
    explicit = os.getenv(
        "VOL_PATH", r"C:\Users\hadil\Desktop\DF Tools\volatility3-develop\vol.py")
    if explicit and Path(explicit).exists():
        return [sys.executable, explicit] if explicit.endswith(".py") else [explicit]
    exe = shutil.which("vol")
    if exe:
        return [exe]
    return [sys.executable, "-m", "volatility3.cli"]


VOLATILITY_CMD = _volatility_cmd()

VOLATILITY_SYMBOLS_DIR = Path(os.getenv("VOL_SYMBOLS", BASE_DIR / "symbols"))

UAC_PATH = os.getenv("UAC_PATH", str(BASE_DIR / "acquisition" / "linux" / "uac"))
AVML_PATH = os.getenv("AVML_PATH", str(BASE_DIR / "acquisition" / "linux" / "avml"))

RULES_DIR = BASE_DIR / "rules"
DETECTION_RULES_DIR = Path(os.getenv("DFIR_RULES", RULES_DIR / "yaml"))
YARA_RULES_DIR = RULES_DIR / "yara"
SIGMA_RULES_DIR = RULES_DIR / "sigma"
INTEL_DIR = BASE_DIR / "intel"
IOC_FEEDS_DIR = Path(os.getenv("IOC_FEEDS_DIR", RULES_DIR / "ioc_feeds"))

BATCH_SIZE = 5000
MAX_YARA_FILE_MB = 100