"""End-to-end tests of the gate against a throwaway vault in a temp folder."""
import base64
import sys

import pytest

pk = pytest.importorskip("pykeepass")

import vault  # noqa: E402
from conftest import write_config  # noqa: E402

PY = sys.executable


@pytest.fixture
def sb(sandbox, monkeypatch):
    pk.create_database(str(sandbox["db"]), keyfile=str(sandbox["key"]))
    monkeypatch.setattr(vault, "gui_running", lambda: False)
    return sandbox


def gate(capsys, *args):
    rc = vault.main(list(args))
    out = capsys.readouterr()
    return rc, out.out, out.err


def secret(sb, title, field="password"):
    kp = pk.PyKeePass(str(sb["db"]), keyfile=str(sb["key"]))
    e = next(e for e in kp.entries if e.title == title)
    return e.password if field == "password" else e.custom_properties[field]


def test_add_list_show_never_print_secrets(sb, capsys):
    rc, out, _ = gate(capsys, "add", "Containers/postgres", "--user", "app", "--url", "https://u:pw@db.lan/?t=1")
    assert rc == 0 and "added: Containers/postgres" in out
    pw = secret(sb, "postgres")
    assert len(pw) == 28
    rc, out, _ = gate(capsys, "list")
    assert "Containers/postgres | user=app" in out and pw not in out and "pw@" not in out
    rc, out, _ = gate(capsys, "show", "Containers/postgres")
    assert rc == 0 and "password: set" in out and pw not in out and "t=1" not in out
    rc, out, _ = gate(capsys, "show", "postgres")
    assert rc == 0


def test_errors_and_validation(sb, capsys):
    gate(capsys, "add", "svc")
    assert gate(capsys, "add", "svc")[0] == vault.GATE_ERROR
    assert gate(capsys, "show", "nope")[0] == vault.GATE_ERROR
    assert gate(capsys, "add", "short", "--length", "8")[0] == vault.GATE_ERROR
    assert gate(capsys, "add", "huge", "--length", "100000")[0] == vault.GATE_ERROR
    assert gate(capsys, "rotate", "svc", "--field", "MISSING")[0] == vault.GATE_ERROR
    # failed validation must not leave a backup behind
    assert not list((sb["work"] / "backups").glob("*-before*"))[1:]


def test_rotate_gen_attr_set_attr(sb, capsys):
    gate(capsys, "add", "svc")
    before = secret(sb, "svc")
    assert gate(capsys, "rotate", "svc", "--charset", "urlsafe")[0] == 0
    after = secret(sb, "svc")
    assert after != before and all(c.isalnum() or c in "-_.~" for c in after)
    assert gate(capsys, "gen-attr", "svc", "TOKEN", "--charset", "alnum")[0] == 0
    assert secret(sb, "svc", "TOKEN").isalnum()
    assert gate(capsys, "set-attr", "svc", "TOKEN", "clear")[0] == vault.GATE_ERROR
    assert gate(capsys, "set-attr", "svc", "DB_USER", "app")[0] == 0
    assert gate(capsys, "trash", "svc")[0] == 0
    rc, out, _ = gate(capsys, "list")
    assert "(0 entries" in out


def test_backups_are_rotated(sb, capsys):
    gate(capsys, "add", "svc")
    for _ in range(5):
        gate(capsys, "rotate", "svc")
    assert len(list((sb["work"] / "backups").iterdir())) == 3


def test_gui_running_blocks_writes(sb, capsys, monkeypatch):
    monkeypatch.setattr(vault, "gui_running", lambda: True)
    assert gate(capsys, "add", "svc")[0] == vault.GATE_ERROR
    assert gate(capsys, "add", "svc", "--force-gui")[0] == 0


def test_pipe_refuses_interpreters_by_default(sb, capsys):
    gate(capsys, "add", "svc")
    rc, _, err = gate(capsys, "pipe", "svc", "python", "-c", "print(input())")
    assert rc == vault.GATE_ERROR and "refuses" in err
    rc, _, err = gate(capsys, "pipe", "svc", PY, "-c", "print(input())")
    assert rc == vault.GATE_ERROR and "by name" in err


def test_pipe_masks_secret_and_encodings(sb, capsys):
    write_config(sb, pipe_allow=[PY])
    gate(capsys, "add", "svc")
    pw = secret(sb, "svc")
    code = ("import sys,base64;s=sys.stdin.readline().rstrip();"
            "print(s);print(s[::-1]);print(base64.b64encode(s.encode()).decode());print(s.encode().hex())")
    rc, out, _ = gate(capsys, "pipe", "svc", PY, "-c", code)
    assert rc == 0
    assert pw not in out and pw[::-1] not in out and base64.b64encode(pw.encode()).decode() not in out
    assert out.count(vault.MASK) == 4


def test_pipe_env_and_no_stdin(sb, capsys):
    write_config(sb, pipe_allow=[PY])
    gate(capsys, "add", "svc")
    gate(capsys, "set-attr", "svc", "PLAIN", "not-protected-value")
    code = "import os,sys;print(os.environ['K']);print(repr(sys.stdin.read()))"
    rc, out, _ = gate(capsys, "pipe", "--no-stdin", "--env", "K=PLAIN", "svc", "--", PY, "-c", code)
    assert rc == 0 and "not-protected-value" not in out and "''" in out
    assert gate(capsys, "pipe", "--env", "PATH=password", "svc", PY, "-c", "0")[0] == vault.GATE_ERROR


def test_pipe_exit_code_and_timeout(sb, capsys):
    write_config(sb, pipe_allow=[PY])
    gate(capsys, "add", "svc")
    assert gate(capsys, "pipe", "svc", PY, "-c", "raise SystemExit(7)")[0] == 7
    rc, _, err = gate(capsys, "pipe", "--timeout", "1", "svc", PY, "-c", "import time;time.sleep(5)")
    assert rc == 124 and "killed" in err


def test_pipe_allow_list(sb, capsys):
    write_config(sb, pipe_allow=["ssh"])
    gate(capsys, "add", "svc")
    rc, _, err = gate(capsys, "pipe", "svc", PY, "-c", "0")
    assert rc == vault.GATE_ERROR and "pipe_allow" in err


def test_safe_url():
    assert vault.safe_url("https://a:b@h.lan:8080/p?token=x&y=2#f") == \
        "https://<hidden>@h.lan:8080/p?token=<hidden>&y=<hidden>#<hidden>"
    assert vault.safe_url("") == "-"


def test_generator_bounds():
    for cs in vault.CHARSETS:
        pw = vault.gen(12, cs)
        assert len(pw) == 12 and set(pw) <= set(vault.CHARSETS[cs])
    with pytest.raises(vault.GateError):
        vault.gen(11)
    with pytest.raises(vault.GateError):
        vault.gen(257)


def test_program_planted_in_project_is_refused(sb, capsys, monkeypatch, tmp_path):
    write_config(sb, pipe_allow=["ssh"])
    gate(capsys, "add", "svc")
    fake = sb["project"] / ("ssh.exe" if vault.os.name == "nt" else "ssh")
    fake.write_bytes(b"")
    fake.chmod(0o755)
    monkeypatch.chdir(sb["project"])
    monkeypatch.setenv("PATH", str(sb["project"]))
    rc, _, err = gate(capsys, "pipe", "svc", "ssh", "x")
    assert rc == vault.GATE_ERROR
    rc, _, err = gate(capsys, "pipe", "svc", str(fake), "x")
    assert rc == vault.GATE_ERROR and "by name" in err


def test_missing_config_and_bad_timeout(sb, capsys):
    (sb["work"] / "config.json").unlink()
    assert gate(capsys, "list")[0] == vault.GATE_ERROR
    with pytest.raises(SystemExit):
        vault.main(["pipe", "--timeout", "-1", "svc", "ssh"])


def test_duplicate_with_messy_group(sb, capsys):
    assert gate(capsys, "add", "T", "--group", "A//B")[0] == 0
    assert gate(capsys, "add", "A/B/T")[0] == vault.GATE_ERROR
