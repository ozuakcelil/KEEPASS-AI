"""Shared settings loader for vault.py, guard.py and install.py. Standard library only."""
import json
import os
import pathlib
import sys

GATE_DIR = pathlib.Path(__file__).resolve().parent

# Optional config keys and their defaults. Wrong types fall back to the default instead of crashing,
# because the guard must keep working (and keep blocking) even with a sloppy config.
DEFAULTS = {
    "db": "",
    "key": "",
    "deny": [],           # extra strings the guard denies in shell commands
    "pipe_allow": [],     # if non-empty: the only programs `pipe` may run (basenames, e.g. "ssh")
    "keep_backups": 50,   # how many vault backups to keep (0 = keep all)
    "pipe_timeout": 300,  # seconds before a `pipe` program is killed
}


class ConfigError(Exception):
    pass


def vault_home() -> pathlib.Path:
    """Working folder: venv, backups, logs, config.json. Default: ~/.keepassai"""
    return pathlib.Path(os.environ.get("KEEPASSAI_HOME") or (pathlib.Path.home() / ".keepassai")).expanduser()


def config_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("KEEPASSAI_CONFIG") or (vault_home() / "config.json")).expanduser()


def expand(p: str) -> str:
    # only ~ and the home variables are expanded; a literal "$" elsewhere in a path is kept
    p = p.strip()
    for var in ("$HOME", "${HOME}", "%USERPROFILE%"):
        if p.startswith(var):
            p = str(pathlib.Path.home()) + p[len(var):]
    return str(pathlib.Path(p).expanduser())


def _clean(raw) -> dict:
    cfg = dict(DEFAULTS)
    if not isinstance(raw, dict):
        return cfg
    for k in ("db", "key"):
        if isinstance(raw.get(k), str) and raw[k].strip():
            cfg[k] = expand(raw[k])
    for k in ("deny", "pipe_allow"):
        if isinstance(raw.get(k), list):
            cfg[k] = [x for x in raw[k] if isinstance(x, str) and x.strip()]
    for k in ("keep_backups", "pipe_timeout"):
        if isinstance(raw.get(k), int) and not isinstance(raw.get(k), bool) and raw[k] >= 0:
            cfg[k] = raw[k]
    return cfg


def load_config(required: bool = True) -> dict:
    """Read config.json. required=True: exit with a message if missing or unreadable.
    required=False: return defaults if missing; raise ConfigError if it exists but is broken."""
    p = config_path()
    if not p.exists():
        if required:
            sys.exit(f"ERROR: config file not found: {p} (run install.py, see INSTALL.md)")
        return dict(DEFAULTS)
    try:
        raw = json.loads(p.read_text(encoding="utf-8-sig"))  # tolerate a BOM (Windows editors)
    except (OSError, ValueError) as e:
        if required:
            sys.exit(f"ERROR: cannot read config file {p}: {type(e).__name__}")
        raise ConfigError(f"cannot read {p}: {type(e).__name__}") from None
    return _clean(raw)


def venv_python() -> pathlib.Path:
    if os.environ.get("KEEPASSAI_PYTHON"):
        return pathlib.Path(os.environ["KEEPASSAI_PYTHON"])
    v = vault_home() / "venv"
    return v / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
