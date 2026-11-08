import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A fake user home with a working folder, a key file and a config. No vault is created."""
    home = tmp_path / "home"
    work = home / ".keepassai"
    keydir = home / ".vaultkey"
    for d in (work / "backups", keydir, home / "project"):
        d.mkdir(parents=True)
    key = keydir / "lab.keyx"
    key.write_bytes(os.urandom(100))
    db = home / "Vault" / "lab.kdbx"
    db.parent.mkdir()
    cfg = {"db": str(db), "key": str(key), "deny": [], "pipe_allow": [], "keep_backups": 3, "pipe_timeout": 30}
    (work / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (work / "gate.log").write_text("", encoding="utf-8")
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("KEEPASSAI_HOME", str(work))
    monkeypatch.delenv("KEEPASSAI_CONFIG", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return {"home": home, "work": work, "key": key, "db": db, "cfg": cfg, "project": home / "project"}


def write_config(sb, **changes):
    sb["cfg"].update(changes)
    (sb["work"] / "config.json").write_text(json.dumps(sb["cfg"]), encoding="utf-8")
