"""KeePassAI installer (Windows, macOS, Linux). Run it with any Python 3.9+:

    python install.py --db <vault file> --key <key file> [--hook] [--home DIR] [--settings FILE]

What it does:
  1. creates the working folder (default ~/.keepassai) and a private venv inside it
  2. installs requirements.txt into that venv
  3. writes config.json (vault and key file locations)
  4. self-test: opens the vault through the gate and prints the entry count
  5. with --hook: adds the guard hook to Claude Code's user settings (a backup is made first)
Run it again any time; existing pieces are kept. It never prints secrets.
"""
import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import venv

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common  # noqa: E402

GATE = common.GATE_DIR
GUARD = GATE / "guard.py"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def step(msg):
    print(f"==> {msg}")


def fail(msg):
    sys.exit(f"ERROR: {msg}")


def default_settings() -> pathlib.Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or (pathlib.Path.home() / ".claude")
    return pathlib.Path(base) / "settings.json"


def hook_entry(py: pathlib.Path, home) -> dict:
    args = ["-I", str(GUARD)]
    if home:
        args += ["--home", str(home)]
    return {"type": "command", "command": str(py), "args": args,
            "timeout": 15, "onFailure": "block", "statusMessage": "KeePassAI guard"}


def is_ours(h) -> bool:
    if not isinstance(h, dict):
        return False
    if h.get("statusMessage") == "KeePassAI guard":
        return True
    args = h.get("args") if isinstance(h.get("args"), list) else []
    target = os.path.normcase(str(GUARD))
    return any(os.path.normcase(str(a)) == target for a in args) or target in os.path.normcase(str(h.get("command", "")))


def add_hook(settings: pathlib.Path, py: pathlib.Path, home):
    data = {}
    if settings.exists():
        text = settings.read_text(encoding="utf-8-sig")
        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError:
            fail(f"{settings} is not valid JSON (comments are not allowed); fix it, or add the snippet by hand")
        if not isinstance(data, dict):
            fail(f"{settings} does not contain a JSON object")
        bak = settings.with_name(f"{settings.name}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}")
        shutil.copy2(settings, bak)
        print(f"    settings backup: {bak}")
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = data["hooks"] = {}
    groups = hooks.get("PreToolUse")
    if not isinstance(groups, list):
        groups = hooks["PreToolUse"] = []
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            g["hooks"] = [h for h in g["hooks"] if not is_ours(h)]
    groups[:] = [g for g in groups if not isinstance(g, dict) or g.get("hooks")]
    groups.append({"hooks": [hook_entry(py, home)]})  # no matcher = every tool
    settings.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings.with_name(settings.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, settings)
    print(f"    hook written to {settings}")


def make_venv(home: pathlib.Path, py: pathlib.Path):
    if py.exists():
        return
    step("creating venv")
    target = home / "venv"
    try:
        venv.EnvBuilder(with_pip=True, clear=target.exists()).create(target)
    except Exception as e:
        shutil.rmtree(target, ignore_errors=True)
        hint = " On Debian/Ubuntu install python3-venv first." if sys.platform.startswith("linux") else ""
        fail(f"cannot create the venv ({type(e).__name__}: {e}).{hint}")
    if not py.exists():
        shutil.rmtree(target, ignore_errors=True)
        fail("the venv was created without a python executable; is the venv module complete?")


def main():
    ap = argparse.ArgumentParser(description="KeePassAI installer")
    ap.add_argument("--db", help="path of the vault file")
    ap.add_argument("--key", help="path of the key file that unlocks it")
    ap.add_argument("--home", help="working folder (default ~/.keepassai or $KEEPASSAI_HOME)")
    ap.add_argument("--hook", action="store_true", help="add the guard hook to Claude Code user settings")
    ap.add_argument("--settings", default=str(default_settings()),
                    help="settings file for --hook (default ~/.claude/settings.json)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing config.json")
    ap.add_argument("--skip-test", action="store_true", help="do not open the vault as a self-test")
    a = ap.parse_args()

    if sys.version_info < (3, 9):
        fail("Python 3.9 or newer is required")
    custom_home = None
    if a.home:
        custom_home = pathlib.Path(a.home).expanduser().resolve()
        os.environ["KEEPASSAI_HOME"] = str(custom_home)
    elif os.environ.get("KEEPASSAI_HOME"):
        custom_home = pathlib.Path(os.environ["KEEPASSAI_HOME"]).expanduser().resolve()
    home = common.vault_home()

    step(f"working folder: {home}")
    home.mkdir(parents=True, exist_ok=True)
    (home / "backups").mkdir(exist_ok=True)
    if os.name != "nt":
        os.chmod(home, 0o700)
        os.chmod(home / "backups", 0o700)
        try:
            (GATE / "vault.sh").chmod(0o755)
        except OSError:
            print("    note: could not chmod vault.sh; run: chmod +x vault.sh")

    py = common.venv_python()
    make_venv(home, py)
    step("installing requirements")
    subprocess.run([str(py), "-m", "pip", "install", "--disable-pip-version-check", "-q",
                    "-r", str(GATE / "requirements.txt")], check=True)

    cfg_path = common.config_path()
    if a.db or a.key:
        if not (a.db and a.key):
            fail("give --db and --key together")
        if cfg_path.exists() and not a.force:
            print(f"    config exists, keeping it (use --force to replace): {cfg_path}")
        else:
            cfg = {"db": str(pathlib.Path(a.db).expanduser().resolve()),
                   "key": str(pathlib.Path(a.key).expanduser().resolve()),
                   "deny": [], "pipe_allow": ["ssh"], "keep_backups": 50, "pipe_timeout": 300}
            cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
            if os.name != "nt":
                os.chmod(cfg_path, 0o600)
            step(f"config written: {cfg_path}")
    elif not cfg_path.exists():
        fail(f"no config yet; run again with --db and --key (or copy config.example.json to {cfg_path})")

    if not a.skip_test:
        step("self-test: opening the vault through the gate")
        r = subprocess.run([str(py), "-I", str(GATE / "vault.py"), "list"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            fail(f"self-test failed: {r.stderr.strip()}")
        print("    " + (r.stdout.strip().splitlines() or ["?"])[-1])

    if a.hook:
        step("adding the guard hook to Claude Code")
        add_hook(pathlib.Path(a.settings).expanduser(), py, custom_home)
    else:
        step("hook NOT added (run again with --hook). Settings snippet:")
        print(json.dumps({"hooks": {"PreToolUse": [{"hooks": [hook_entry(py, custom_home)]}]}},
                         indent=2, ensure_ascii=False))

    if custom_home:
        print(f"    NOTE: custom working folder. Set KEEPASSAI_HOME={custom_home} permanently in your "
              f"environment so the wrappers find it.")
    wrapper = GATE / ("vault.ps1" if os.name == "nt" else "vault.sh")
    step("done. Try:")
    print(f'    {"& " if os.name == "nt" else ""}"{wrapper}" list')


if __name__ == "__main__":
    main()
