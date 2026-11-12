"""Tests of the gate's `ssh` command, reserved server fields and expiry display.
paramiko is replaced by a fake: no network."""
import base64
import datetime
import hashlib
import logging
import sys
import types

import pytest

pk = pytest.importorskip("pykeepass")

import vault  # noqa: E402
from conftest import write_config  # noqa: E402

HOSTNAME, IP, PW, USER = "web01.example.lan", "10.0.0.11", "Zx9-secret-PASS_42", "alice"
PW2, USER2 = "Qw7-other-PASS_77", "bob"


class FakeKey:
    def __init__(self, name="ssh-ed25519", blob=b"key-blob-1"):
        self.name, self.blob = name, blob

    def get_name(self):
        return self.name

    def asbytes(self):
        return self.blob

    def get_base64(self):
        return base64.b64encode(self.blob).decode()


class FakeChannel:
    def __init__(self, tr):
        self.tr, self.closed, self.chunks = tr, False, None

    def exec_command(self, command):
        self.tr.ran.append(command)
        self.chunks = [list(FakeTransport.out), list(FakeTransport.err)]

    def recv_ready(self):
        return bool(self.chunks and self.chunks[0])

    def recv(self, n):
        return self.chunks[0].pop(0)

    def recv_stderr_ready(self):
        return bool(self.chunks and self.chunks[1])

    def recv_stderr(self, n):
        return self.chunks[1].pop(0)

    def exit_status_ready(self):
        return not FakeTransport.hang

    def recv_exit_status(self):
        return FakeTransport.rc

    def close(self):
        self.closed = True


class SecOpts:
    """Like paramiko's SecurityOptions: refuses names the library does not know (it has no "ssh-rsa")."""
    KNOWN = {"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256"}

    def __init__(self, tr):
        self.tr = tr

    @property
    def key_types(self):
        return self.tr.key_types

    @key_types.setter
    def key_types(self, value):
        if not set(value) <= self.KNOWN:
            raise ValueError("unknown cipher")
        self.tr.key_types = list(value)


class FakeTransport:
    """Class attributes configure the next connection; `instances` records what happened."""
    key = FakeKey()
    out, err, rc, hang = [b"ok\n"], [], 0, False
    auth_error = None
    start_error = None
    instances = []

    def __init__(self, sock):
        self.sock, self.ran, self.auth, self.key_types, self.is_closed = sock, [], None, None, False
        FakeTransport.instances.append(self)

    def get_security_options(self):
        return SecOpts(self)

    def start_client(self, timeout=None):
        if FakeTransport.start_error:
            raise FakeTransport.start_error

    def get_remote_server_key(self):
        return FakeTransport.key

    def auth_password(self, user, pw):
        if FakeTransport.auth_error:
            raise FakeTransport.auth_error
        self.auth = (user, pw)

    def open_session(self, timeout=None):
        return FakeChannel(self)

    def close(self):
        self.is_closed = True


class AuthenticationException(Exception):
    pass


@pytest.fixture
def sb(sandbox, monkeypatch):
    pk.create_database(str(sandbox["db"]), keyfile=str(sandbox["key"]))
    monkeypatch.setattr(vault, "gui_running", lambda: False)
    fake = types.SimpleNamespace(Transport=FakeTransport, AuthenticationException=AuthenticationException)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    connects = []
    monkeypatch.setattr(vault.socket, "create_connection",
                        lambda addr, timeout=None: connects.append(addr) or object())
    FakeTransport.key = FakeKey()
    FakeTransport.out, FakeTransport.err, FakeTransport.rc, FakeTransport.hang = [b"ok\n"], [], 0, False
    FakeTransport.auth_error = FakeTransport.start_error = None
    FakeTransport.instances = []
    sandbox["connects"] = connects
    kp = pk.PyKeePass(str(sandbox["db"]), keyfile=str(sandbox["key"]))
    srv_g, pw_g = kp.add_group(kp.root_group, "SERVERS"), kp.add_group(kp.root_group, "PASSWORDS")
    srv = kp.add_entry(srv_g, "TEST-WEB01", "", "")
    srv.set_custom_property("HOSTNAME", HOSTNAME)
    srv.set_custom_property("IP", IP)
    srv.set_custom_property("PASSWORD", "SSH-ALICE")
    kp.add_entry(pw_g, "SSH-ALICE", USER, PW)
    kp.add_entry(pw_g, "SSH-BOB", USER2, PW2)
    kp.save()
    pin(sandbox)
    return sandbox


def pin(sb, targets=((IP, 22), (HOSTNAME, 22), (HOSTNAME, 2222)), key=None):
    key = key or FakeKey()
    (sb["work"] / "known_hosts").write_text(
        "".join(f"[{t}]:{p} {key.get_name()} {key.get_base64()}\n" for t, p in targets), encoding="utf-8")


def edit(sb, fn):
    kp = pk.PyKeePass(str(sb["db"]), keyfile=str(sb["key"]))
    fn(kp)
    kp.save()


def entry(kp, title):
    return next(e for e in kp.entries if e.title == title)


def gate(capsys, *args):
    rc = vault.main(list(args))
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_resolution_by_title_and_full_name(sb, capsys):
    rc, out, _ = gate(capsys, "ssh", "TEST-WEB01", "uptime")
    assert rc == 0 and out == "ok\n"
    tr = FakeTransport.instances[-1]
    assert tr.auth == (USER, PW) and tr.ran == ["uptime"] and tr.is_closed
    assert sb["connects"] == [(IP, 22)]                       # IP wins over HOSTNAME
    rc, *_ = gate(capsys, "ssh", "SERVERS/TEST-WEB01", "--", "ls", "-l", "/tmp")
    assert rc == 0 and FakeTransport.instances[-1].ran == ["ls -l /tmp"]

    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "PASSWORDS/SSH-ALICE"))
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0
    assert FakeTransport.instances[-1].auth == (USER, PW)


def test_hostname_fallback_and_port(sb, capsys):
    def f(kp):
        e = entry(kp, "TEST-WEB01")
        e.delete_custom_property("IP")
        e.set_custom_property("port", "2222")           # field names are case-insensitive
    edit(sb, f)
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0
    assert sb["connects"] == [(HOSTNAME, 2222)]


@pytest.mark.parametrize("bad", ["0", "70000", "abc"])
def test_invalid_port(sb, capsys, bad):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PORT", bad))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "invalid PORT" in err and not sb["connects"]


def test_credential_list_and_as(sb, capsys):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "SSH-ALICE, PASSWORDS/SSH-BOB"))
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0                       # default: first
    assert FakeTransport.instances[-1].auth == (USER, PW)
    assert gate(capsys, "ssh", "--as", "PASSWORDS/SSH-BOB", "TEST-WEB01", "id")[0] == 0
    assert FakeTransport.instances[-1].auth == (USER2, PW2)
    n = len(FakeTransport.instances)
    # an entry that exists in the vault but is not in this server's list is refused
    edit(sb, lambda kp: kp.add_entry(kp.root_group, "SSH-OTHER", "carol", "Another-PASS-9999"))
    for bad in ("SSH-OTHER", "SSH-BOB", "ssh-alice"):       # SSH-BOB: only the listed spelling counts
        rc, _, err = gate(capsys, "ssh", "--as", bad, "TEST-WEB01", "id")
        assert rc == vault.GATE_ERROR and "not one of the credentials" in err
    assert len(FakeTransport.instances) == n and len(sb["connects"]) == 2
    # the other credential's password is not printed in the refusal
    assert PW2 not in err


def test_missing_and_ambiguous_references(sb, capsys):
    assert gate(capsys, "ssh", "NOPE", "id")[0] == vault.GATE_ERROR
    assert gate(capsys, "ssh", "TEST-WEB01")[0] == vault.GATE_ERROR           # no command

    edit(sb, lambda kp: entry(kp, "TEST-WEB01").delete_custom_property("PASSWORD"))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "no PASSWORD field" in err

    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "MISSING-CRED"))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "missing or ambiguous" in err

    def ambiguous(kp):
        entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "SSH-ALICE")
        kp.add_entry(kp.add_group(kp.root_group, "OLD"), "SSH-ALICE", "mallory", "another-pass-123")
    edit(sb, ambiguous)
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "missing or ambiguous" in err

    edit(sb, lambda kp: kp.add_entry(kp.add_group(kp.root_group, "OLD2"), "TEST-WEB01", "", ""))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "share the title" in err
    assert not sb["connects"]


def test_jump_host_is_refused_not_ignored(sb, capsys):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("JUMP_HOST", "TEST-JUMP01"))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "not supported yet" in err and not sb["connects"]


def test_no_host_and_short_password(sb, capsys):
    edit(sb, lambda kp: setattr(entry(kp, "SSH-ALICE"), "password", "short"))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "shorter than" in err and not sb["connects"]

    def f(kp):
        e = entry(kp, "TEST-WEB01")
        e.delete_custom_property("IP")
        e.delete_custom_property("HOSTNAME")
    edit(sb, f)
    assert "no HOSTNAME or IP" in gate(capsys, "ssh", "TEST-WEB01", "id")[2]


def test_output_masks_password_hosts_and_encodings(sb, capsys):
    b64 = base64.b64encode(PW.encode()).decode()
    FakeTransport.out = [f"pw={PW} rev={PW[::-1]} b64={b64}\nhost {HOSTNAME} / {HOSTNAME.upper()} ip {IP}".encode()]
    FakeTransport.err = [f"err {PW} at {IP}, {HOSTNAME.title()}\n".encode()]
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == 0
    for text in (out, err):
        for leak in (PW, PW[::-1], b64, HOSTNAME, HOSTNAME.upper(), IP):
            assert leak not in text
    assert out.count(vault.MASK) == 6 and vault.MASK in err


def test_mask_hosts_can_be_disabled(sb, capsys):
    write_config(sb, mask_hosts=False)
    FakeTransport.out = [f"{PW} {IP}\n".encode()]
    rc, out, _ = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert PW not in out and IP in out


def test_exit_codes(sb, capsys):
    FakeTransport.rc = 7
    assert gate(capsys, "ssh", "TEST-WEB01", "false")[0] == 7
    FakeTransport.rc = -1                                     # no status from the server
    assert gate(capsys, "ssh", "TEST-WEB01", "x")[0] == 255
    FakeTransport.rc, FakeTransport.hang = 0, True
    rc, _, err = gate(capsys, "ssh", "--timeout", "1", "TEST-WEB01", "sleep", "9")
    assert rc == 124 and "killed after 1s" in err
    assert FakeTransport.instances[-1].is_closed


def test_errors_are_masked_and_exit_3(sb, capsys, monkeypatch):
    FakeTransport.start_error = OSError(f"cannot reach {IP} / {HOSTNAME.upper()} with {PW}")
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and out == ""
    assert PW not in err and IP not in err and HOSTNAME.upper() not in err and "OSError" in err
    assert FakeTransport.instances[-1].is_closed and FakeTransport.instances[-1].auth is None

    FakeTransport.start_error = None
    FakeTransport.auth_error = AuthenticationException(f"bad {PW}")
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "authentication failed" in err and PW not in err

    def refuse(addr, timeout=None):
        raise ConnectionRefusedError(f"refused {addr[0]} {PW}")
    monkeypatch.setattr(vault.socket, "create_connection", refuse)
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and PW not in err and IP not in err


def test_host_key_first_use_pins_only_and_sends_nothing(sb, capsys):
    (sb["work"] / "known_hosts").unlink()
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and out == ""
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(b"key-blob-1").digest()).decode().rstrip("=")
    assert "ssh-ed25519" in err and fp in err and "run the command again" in err
    assert f"'ssh-ed25519 {fp}'" in err and "HOST_KEY" in err
    assert IP not in err and HOSTNAME not in err and PW not in err
    tr = FakeTransport.instances[-1]
    assert tr.auth is None and tr.ran == [] and tr.is_closed          # no password was sent
    lines = (sb["work"] / "known_hosts").read_text(encoding="utf-8").splitlines()
    assert lines == [f"[{IP}]:22 ssh-ed25519 {base64.b64encode(b'key-blob-1').decode()}"]
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")               # the next run authenticates
    assert rc == 0 and "first connection" not in err
    assert FakeTransport.instances[-1].auth == (USER, PW)
    assert len((sb["work"] / "known_hosts").read_text(encoding="utf-8").splitlines()) == 1
    assert FakeTransport.instances[-1].key_types == ["ssh-ed25519"]


def test_host_key_mismatch_refuses_before_auth(sb, capsys):
    gate(capsys, "ssh", "TEST-WEB01", "id")
    FakeTransport.key = FakeKey(blob=b"evil-key")
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    tr = FakeTransport.instances[-1]
    assert rc == vault.GATE_ERROR and "MISMATCH" in err and "no credential was sent" in err
    assert tr.auth is None and tr.ran == [] and tr.is_closed and out == ""
    assert PW not in err and IP not in err
    FakeTransport.key = FakeKey(name="ssh-rsa", blob=b"key-blob-1")        # same blob, other type
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == vault.GATE_ERROR


def test_rsa_pin_uses_rsa_sha2_key_types(sb, capsys):
    FakeTransport.key = FakeKey(name="ssh-rsa", blob=b"rsa-blob")
    pin(sb, key=FakeTransport.key)
    rc, *_ = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == 0
    assert FakeTransport.instances[-1].key_types == ["rsa-sha2-512", "rsa-sha2-256"]


def test_malformed_or_duplicate_known_hosts_line_fails_closed(sb, capsys):
    kh = sb["work"] / "known_hosts"
    good = f"[{IP}]:22 ssh-ed25519 {FakeKey().get_base64()}"
    for text in (good + " extra\n", good + "\n" + good + "\n", f"[{IP}]:22 ssh-ed25519\n"):
        kh.write_text(text, encoding="utf-8")
        n = len(FakeTransport.instances)
        rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
        assert rc == vault.GATE_ERROR and "known_hosts" in err
        assert kh.read_text(encoding="utf-8") == text                     # not re-pinned
        assert FakeTransport.instances[n:] == [] or FakeTransport.instances[-1].auth is None


@pytest.mark.parametrize("field,value", [("HOSTNAME", "web01.example.lan evil"), ("IP", "10.0.0.11,10.0.0.12"),
                                          ("HOSTNAME", "web01\texample.lan"), ("IP", "10.0.0.1]:22 x")])
def test_host_with_whitespace_or_commas_is_refused(sb, capsys, field, value):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property(field, value))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "spaces or commas" in err and not sb["connects"]


def test_paramiko_logging_is_silenced(sb, capsys, monkeypatch):
    lg = logging.getLogger("paramiko")
    monkeypatch.setattr(lg, "handlers", [])
    monkeypatch.setattr(lg, "propagate", True)

    def noisy(self, timeout=None):
        try:
            raise RuntimeError(f"boom {IP} {PW}")
        except RuntimeError:
            logging.getLogger("paramiko.transport").error("Exception (client)", exc_info=True)
        raise OSError("failed")
    monkeypatch.setattr(FakeTransport, "start_client", noisy)
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and PW not in err and IP not in err
    assert "Traceback" not in err and "Exception (client)" not in err


def test_known_hosts_honours_keepassai_home(sb, capsys, monkeypatch, tmp_path):
    other = tmp_path / "other-home"
    other.mkdir()
    (sb["work"] / "known_hosts").unlink()
    (other / "config.json").write_text((sb["work"] / "config.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setenv("KEEPASSAI_HOME", str(other))
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == vault.GATE_ERROR     # first use: pinned, not used
    assert (other / "known_hosts").exists() and not (sb["work"] / "known_hosts").exists()


def test_log_has_no_secrets(sb, capsys):
    gate(capsys, "ssh", "TEST-WEB01", "echo", PW)
    log = (sb["work"] / "gate.log").read_text(encoding="utf-8")
    assert '"command": "ssh"' in log and "TEST-WEB01" in log and "SSH-ALICE" in log
    assert PW not in log and IP not in log and HOSTNAME not in log


# ---- reserved fields

@pytest.mark.parametrize("name", ["HOSTNAME", "hostname", "Ip", "PORT", "PASSWORD", " password ", "JUMP_HOST", "HOST_KEY", "host_key"])
def test_reserved_fields_cannot_be_written(sb, capsys, name):
    for args in (("set-attr", "TEST-WEB01", name, "attacker.example"),
                 ("gen-attr", "TEST-WEB01", name, "--overwrite"),
                 ("rotate", "TEST-WEB01", "--field", name)):
        rc, _, err = gate(capsys, *args)
        assert rc == vault.GATE_ERROR and "reserved" in err
    kp = pk.PyKeePass(str(sb["db"]), keyfile=str(sb["key"]))
    assert entry(kp, "TEST-WEB01").custom_properties == {"HOSTNAME": HOSTNAME, "IP": IP, "PASSWORD": "SSH-ALICE"}


def test_reserved_fields_cannot_be_created_on_new_entry(sb, capsys):
    gate(capsys, "add", "NEW-SRV")
    for n in ("HOSTNAME", "IP", "PORT", "PASSWORD", "JUMP_HOST", "HOST_KEY"):
        assert gate(capsys, "set-attr", "NEW-SRV", n, "x")[0] == vault.GATE_ERROR
    assert gate(capsys, "ssh", "NEW-SRV", "id")[0] == vault.GATE_ERROR and not sb["connects"]
    # other attributes and other writing commands still work
    assert gate(capsys, "set-attr", "NEW-SRV", "DB_USER", "app")[0] == 0
    assert gate(capsys, "set-url", "TEST-WEB01", "https://x.example.lan")[0] == 0
    assert gate(capsys, "rotate", "SSH-ALICE")[0] == 0


# ---- expiry

def test_show_and_list_expiry(sb, capsys):
    now = datetime.datetime.now(datetime.timezone.utc)

    def f(kp):
        for title, delta in (("SSH-ALICE", datetime.timedelta(days=-3)), ("SSH-BOB", datetime.timedelta(days=5)),
                             ("TEST-WEB01", datetime.timedelta(days=400))):
            e = entry(kp, title)
            e.expires, e.expiry_time = True, now + delta
    edit(sb, f)
    _, out, _ = gate(capsys, "list")
    lines = {ln.split(" | ")[0]: ln for ln in out.splitlines()}
    assert lines["PASSWORDS/SSH-ALICE"].endswith(" | EXPIRED")
    assert f" | expires {(now + datetime.timedelta(days=5)).astimezone():%Y-%m-%d}" in lines["PASSWORDS/SSH-BOB"]
    assert "expires" not in lines["SERVERS/TEST-WEB01"] and "EXPIRED" not in lines["SERVERS/TEST-WEB01"]
    assert "expires: " + f"{(now + datetime.timedelta(days=400)).astimezone():%Y-%m-%d}" in \
        gate(capsys, "show", "TEST-WEB01")[1]
    assert "(EXPIRED)" in gate(capsys, "show", "SSH-ALICE")[1]

    edit(sb, lambda kp: setattr(entry(kp, "SSH-BOB"), "expires", False))
    assert "expires: never" in gate(capsys, "show", "SSH-BOB")[1]
    assert "expires" not in [ln for ln in gate(capsys, "list")[1].splitlines() if "SSH-BOB" in ln][0]


# ---- strict credential references and trash protection

def add_pair(sb):
    """A bare-title reference 'deploy' with both a root entry and PROD/deploy (the re-pointing attack)."""
    def f(kp):
        kp.add_entry(kp.root_group, "deploy", "lab", "Lab-secret-PASS_1")
        kp.add_entry(kp.add_group(kp.root_group, "PROD"), "deploy", "root", "Prod-secret-PASS_2")
        entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "deploy")
    edit(sb, f)


def test_bare_title_never_falls_back_from_full_name(sb, capsys):
    add_pair(sb)
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "missing or ambiguous" in err and not sb["connects"]


def test_trash_refuses_referenced_credentials(sb, capsys):
    for ref in ("SSH-ALICE", "PASSWORDS/SSH-ALICE"):
        edit(sb, lambda kp, ref=ref: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", ref))
        for name in ("SSH-ALICE", "PASSWORDS/SSH-ALICE"):
            rc, _, err = gate(capsys, "trash", name)
            assert rc == vault.GATE_ERROR and "credential or jump host" in err
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("JUMP_HOST", "SSH-BOB"))
    assert gate(capsys, "trash", "SSH-BOB")[0] == vault.GATE_ERROR
    kp = pk.PyKeePass(str(sb["db"]), keyfile=str(sb["key"]))
    assert {e.title for e in vault.live_entries(kp)} >= {"SSH-ALICE", "SSH-BOB"}
    # an unreferenced entry can still be trashed, and a trashed entry is never resolved again
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").delete_custom_property("JUMP_HOST"))
    assert gate(capsys, "trash", "SSH-BOB")[0] == 0


def test_trashed_entry_is_not_a_credential(sb, capsys):
    assert gate(capsys, "trash", "SSH-BOB")[0] == 0
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "SSH-BOB"))
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "missing or ambiguous" in err


def test_adding_a_same_title_entry_cannot_hijack_a_reference(sb, capsys):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "SSH-ALICE"))
    assert gate(capsys, "add", "SSH-ALICE", "--user", "mallory")[0] == 0           # root entry, same title
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "missing or ambiguous" in err and not sb["connects"]


# ---- HOST_KEY field

def fp_of(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def set_host_key(sb, value):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("HOST_KEY", value))


@pytest.mark.parametrize("form", ["ssh-ed25519 {fp}", "{fp}", "{bare}", "  {bare}=  ", "ssh-ed25519   {fp}\n"])
def test_host_key_field_match_connects_without_known_hosts(sb, capsys, form):
    (sb["work"] / "known_hosts").unlink()
    fp = fp_of(FakeKey())
    set_host_key(sb, form.format(fp=fp, bare=fp[len("SHA256:"):]))
    rc, out, _ = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == 0 and out == "ok\n" and FakeTransport.instances[-1].auth == (USER, PW)
    assert not (sb["work"] / "known_hosts").exists()                 # nothing pinned, nothing needed


def test_host_key_field_restricts_key_type(sb, capsys):
    set_host_key(sb, f"ssh-ed25519 {fp_of(FakeKey())}")
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0
    assert FakeTransport.instances[-1].key_types == ["ssh-ed25519"]
    rsa = FakeKey(name="ssh-rsa", blob=b"rsa-blob")
    FakeTransport.key = rsa
    set_host_key(sb, f"ssh-rsa {fp_of(rsa)}")
    (sb["work"] / "known_hosts").unlink()
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0
    assert FakeTransport.instances[-1].key_types == ["rsa-sha2-512", "rsa-sha2-256"]
    set_host_key(sb, fp_of(rsa))                                     # no type: no restriction
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0
    assert FakeTransport.instances[-1].key_types is None


def test_host_key_field_mismatch_refuses_before_auth(sb, capsys):
    (sb["work"] / "known_hosts").unlink()
    set_host_key(sb, fp_of(FakeKey()))
    FakeTransport.key = FakeKey(blob=b"evil-key")
    rc, out, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    tr = FakeTransport.instances[-1]
    assert rc == vault.GATE_ERROR and "MISMATCH" in err and out == ""
    assert fp_of(FakeKey()) in err and fp_of(FakeKey(blob=b"evil-key")) in err
    assert tr.auth is None and tr.ran == [] and tr.is_closed and PW not in err
    assert not (sb["work"] / "known_hosts").exists()


@pytest.mark.parametrize("bad", ["garbage", "SHA256:short", "ssh-ed25519", "a b c " + "A" * 43, "A" * 44 + "=="])
def test_host_key_field_malformed_is_refused(sb, capsys, bad):
    set_host_key(sb, bad)
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "HOST_KEY field is malformed" in err and not sb["connects"]


def test_host_key_field_and_known_hosts_must_agree(sb, capsys):
    set_host_key(sb, fp_of(FakeKey(blob=b"other-key")))               # known_hosts pins key-blob-1
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "disagree" in err and not sb["connects"]
    set_host_key(sb, f"ssh-rsa {fp_of(FakeKey())}")                  # same key, different type
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and "disagree" in err and not sb["connects"]
    set_host_key(sb, f"ssh-ed25519 {fp_of(FakeKey())}")              # agrees
    assert gate(capsys, "ssh", "TEST-WEB01", "id")[0] == 0


def test_trash_refuses_either_entry_of_an_ambiguous_reference(sb, capsys):
    add_pair(sb)                                                     # PASSWORD=deploy; root deploy + PROD/deploy
    for name in ("deploy", "PROD/deploy"):
        rc, _, err = gate(capsys, "trash", name)
        assert rc == vault.GATE_ERROR and "credential or jump host" in err
    kp = pk.PyKeePass(str(sb["db"]), keyfile=str(sb["key"]))
    assert len([e for e in vault.live_entries(kp) if e.title == "deploy"]) == 2


def test_add_same_title_then_trash_cannot_repoint(sb, capsys):
    edit(sb, lambda kp: entry(kp, "TEST-WEB01").set_custom_property("PASSWORD", "SSH-ALICE"))
    assert gate(capsys, "add", "Evil/SSH-ALICE", "--user", "mallory")[0] == 0
    for name in ("PASSWORDS/SSH-ALICE", "Evil/SSH-ALICE"):
        assert gate(capsys, "trash", name)[0] == vault.GATE_ERROR
    rc, _, err = gate(capsys, "ssh", "TEST-WEB01", "id")
    assert rc == vault.GATE_ERROR and not sb["connects"]
