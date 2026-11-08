"""KeePassAI vault gate - the single entry point an AI assistant uses to reach a KeePass vault.

This script NEVER prints secret values. It shows names and metadata only, generates secrets
itself, and when a secret has to be used it hands it straight to a program's stdin or to an
environment variable; the secrets of that entry (and common encodings of them) are masked in
the program's output. Every call is appended (without secrets) to <KEEPASSAI_HOME>/gate.log.

Usage:
  Windows    : & "C:/path/to/vault.ps1" <command> ...
  macOS/Linux: /path/to/vault.sh <command> ...
Run "<wrapper> <command> --help" for the options of one command.

Exit codes: 0 ok, 2 bad arguments, 3 gate error; `pipe` returns the program's own exit code.
"""
import argparse
import base64
import datetime
import io
import json
import os
import pathlib
import secrets
import shutil
import string
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # needed under python -I
import common  # noqa: E402

MASK = "<hidden>"
CHARSETS = {
    "full": string.ascii_letters + string.digits + "-_.!@#%+=",
    "urlsafe": string.ascii_letters + string.digits + "-_.~",
    "alnum": string.ascii_letters + string.digits,
}
MIN_LEN, MAX_LEN, MIN_PIPE_LEN = 12, 256, 8
GATE_ERROR = 3
# Programs `pipe` refuses unless the user lists them in config "pipe_allow": they can print or
# transform the secret locally.
PIPE_DENY = {"python", "python3", "py", "pythonw", "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
             "cmd", "powershell", "pwsh", "node", "deno", "bun", "perl", "ruby", "php", "lua", "tclsh", "wsh",
             "cscript", "wscript", "mshta", "env", "xargs", "busybox", "awk", "gawk", "sed", "cat", "tee", "rev",
             "base64", "base32", "xxd", "od", "hexdump", "certutil", "openssl", "gpg", "tr", "cut", "dd", "echo",
             "printf", "type", "more", "less", "head", "tail", "sort", "uniq", "fold", "nl", "paste", "strings"}
ENV_DENY_PREFIX = ("LD_", "DYLD_", "PYTHON", "KEEPASSAI_", "BASH_", "NODE_", "PERL", "RUBY")
ENV_DENY = {"PATH", "PATHEXT", "HOME", "USERPROFILE", "COMSPEC", "SHELL", "ENV", "IFS", "TEMP", "TMP", "TMPDIR",
            "SYSTEMROOT", "WINDIR", "APPDATA", "LOCALAPPDATA", "PS1", "PS4", "PROMPT_COMMAND", "GIT_SSH_COMMAND",
            "GIT_ASKPASS", "SSH_ASKPASS", "EDITOR", "VISUAL", "PAGER"}
GUI_NAMES_WIN = ("KeePassXC.exe", "KeePass.exe")

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class GateError(Exception):
    pass


def die(msg):
    raise GateError(msg)


# ---------------------------------------------------------------- context

class Ctx:
    def __init__(self):
        if not common.config_path().exists():
            die(f"config file not found: {common.config_path()} (run install.py, see INSTALL.md)")
        try:
            self.cfg = common.load_config(required=False)
        except common.ConfigError as e:
            die(str(e))
        if not self.cfg["db"] or not self.cfg["key"]:
            die("config.json needs both 'db' and 'key'")
        self.home = common.vault_home()
        self.db = pathlib.Path(self.cfg["db"])
        self.key = pathlib.Path(self.cfg["key"])
        self.backups = self.home / "backups"
        self.log_file = self.home / "gate.log"
        self.mtime = None

    def open(self):
        try:
            from pykeepass import PyKeePass
        except ImportError:
            die("the KeePass library is not installed in the gate's venv (run install.py, see INSTALL.md)")
        if not self.db.exists():
            die("vault file not found (check 'db' in config.json)")
        if not self.key.exists():
            die("key file not found (check 'key' in config.json)")
        self.mtime = self.db.stat().st_mtime_ns
        try:
            return PyKeePass(str(self.db), keyfile=str(self.key))
        except Exception as e:
            die(f"cannot open vault: {type(e).__name__} (wrong key file, or the vault also has a master password)")

    def log(self, cmd, **kw):
        rec = {"time": datetime.datetime.now().isoformat(timespec="seconds"), "command": cmd, **kw}
        try:
            self.home.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass


# ---------------------------------------------------------------- helpers

def in_trash(kp, obj):
    rb = kp.recyclebin_group
    if rb is None:
        return False
    g = obj if not hasattr(obj, "title") else obj.group   # an entry has a title, a group does not
    while g is not None:
        if g.uuid == rb.uuid:
            return True
        g = g.parentgroup
    return False


def live_entries(kp):
    return [e for e in kp.entries if not in_trash(kp, e)]


def path_of(e):
    parts, g = [], e.group
    while g is not None and g.parentgroup is not None:
        parts.append(g.name)
        g = g.parentgroup
    return "/".join(reversed(parts))


def full_name(e):
    return f"{path_of(e)}/{e.title}" if path_of(e) else e.title


def find(kp, title):
    """Match an entry by its title or by its full "Group/Sub/Title" name."""
    ents = live_entries(kp)
    hits = [e for e in ents if full_name(e) == title] or [e for e in ents if e.title == title]
    if not hits:
        die(f"no such entry: {title!r}")
    if len(hits) > 1:
        die(f"{len(hits)} entries share the title {title!r}; use the full name, e.g. "
            f"{full_name(hits[0])!r}")
    return hits[0]


def gen(n, charset="full"):
    if not MIN_LEN <= n <= MAX_LEN:
        die(f"length must be between {MIN_LEN} and {MAX_LEN}")
    alphabet = CHARSETS[charset]
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        classes = [any(c.islower() for c in pw), any(c.isupper() for c in pw), any(c.isdigit() for c in pw)]
        if charset != "alnum":
            classes.append(any(not c.isalnum() for c in pw))
        if all(classes):
            return pw


def safe_url(url):
    """Drop user:password@ and query/fragment values from a URL before showing it."""
    if not url:
        return "-"
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return MASK
    netloc = u.netloc
    if "@" in netloc:
        netloc = MASK + "@" + netloc.rsplit("@", 1)[1]
    query = "&".join(f"{k}={MASK}" for k, _ in urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    return urllib.parse.urlunsplit((u.scheme, netloc, u.path, query, MASK if u.fragment else ""))


def describe(e):
    props = e.custom_properties or {}
    attrs = ", ".join(f"{k}{' (secret)' if e.is_custom_property_protected(k) else ''}" for k in props) or "-"
    return (f"{e.title}\n  group: {path_of(e) or '(root)'}\n  username: {e.username or '-'}\n"
            f"  url: {safe_url(e.url)}\n  password: {'set' if e.password else 'empty'}\n"
            f"  attributes: {attrs}\n  notes: {str(len(e.notes)) + ' chars' if e.notes else '-'}\n"
            f"  modified: {e.mtime.astimezone():%Y-%m-%d %H:%M}")


def get_field(e, field):
    v = e.password if field == "password" else (e.custom_properties or {}).get(field)
    if not v:
        die(f"field {field!r} of {e.title!r} is empty or missing")
    return v


def variants(v):
    """The secret and the encodings a program is most likely to print it in."""
    b = v.encode("utf-8")
    out = {v, v[::-1], json.dumps(v)[1:-1], urllib.parse.quote(v, safe=""), urllib.parse.quote_plus(v),
           b.hex(), b.hex().upper()}
    for enc in (base64.b64encode, base64.urlsafe_b64encode, base64.b32encode):
        s = enc(b).decode()
        out.update({s, s.rstrip("=")})
    return out


def secrets_of(e, used):
    vals = set(used)
    if e.password:
        vals.add(e.password)
    for k, v in (e.custom_properties or {}).items():
        if v and e.is_custom_property_protected(k):
            vals.add(v)
    masks = set()
    for v in vals:
        masks |= {x for x in variants(v) if len(x) >= 4}
    return sorted(masks, key=len, reverse=True)


def redact(text, masks):
    for m in masks:
        text = text.replace(m, MASK)
    return text


def ensure_group(kp, path):
    g = kp.root_group
    for name in [p for p in (path or "").split("/") if p]:
        sub = next((x for x in g.subgroups if x.name == name and not in_trash(kp, x)), None)
        g = sub if sub else kp.add_group(g, name)
    return g


def gui_running():
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/NH", "/FO", "CSV"], capture_output=True, text=True,
                                 errors="replace", timeout=10).stdout.casefold()
            return any(f'"{n.casefold()}"' in out for n in GUI_NAMES_WIN)
        for args in (["pgrep", "-x", "-i", "keepassxc"], ["pgrep", "-x", "keepassxc"], ["pgrep", "-x", "KeePassXC"]):
            r = subprocess.run(args, capture_output=True, timeout=10)
            if r.returncode == 0:
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------- writing safely

class Lock:
    def __init__(self, path, wait=30, stale=120):
        self.path, self.wait, self.stale = path, wait, stale

    def __enter__(self):
        deadline = time.time() + self.wait
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        self.path.unlink()
                        continue
                except FileNotFoundError:
                    continue
                if time.time() > deadline:
                    die("another gate write is in progress (lock file busy); try again")
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def backup(ctx, tag):
    ctx.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    dst = ctx.backups / f"{ctx.db.stem}-{datetime.datetime.now():%Y%m%d-%H%M%S-%f}-{tag}{ctx.db.suffix}"
    shutil.copy2(ctx.db, dst)
    if os.name != "nt":
        os.chmod(dst, 0o600)
    keep = ctx.cfg["keep_backups"]
    if keep:
        old = sorted(ctx.backups.glob(f"{ctx.db.stem}-*{ctx.db.suffix}"), key=lambda p: p.name)
        for p in old[:-keep]:
            p.unlink()
    return dst.name


def save(ctx, kp):
    """Write the vault atomically: build in memory, write a temp file, fsync, rename over."""
    if ctx.db.stat().st_mtime_ns != ctx.mtime:
        die("the vault changed on disk since it was opened (GUI or another write); nothing was saved, try again")
    buf = io.BytesIO()
    kp.save(buf)
    tmp = ctx.db.with_name(f".{ctx.db.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(buf.getvalue())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, ctx.db)
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        die(f"cannot write the vault ({type(e).__name__}); it is unchanged. Is it open or locked by a sync app?")


# ---------------------------------------------------------------- commands

def cmd_list(ctx, kp, a):
    ents = sorted(live_entries(kp), key=lambda e: (path_of(e), e.title))
    for e in ents:
        props = ",".join((e.custom_properties or {}).keys()) or "-"
        print(f"{full_name(e)} | user={e.username or '-'} | url={safe_url(e.url)} | attributes={props}")
    print(f"({len(ents)} entries, Recycle Bin excluded)")
    ctx.log("list")


def cmd_show(ctx, kp, a):
    print(describe(find(kp, a.title)))
    ctx.log("show", title=a.title)


def _norm(p):
    return os.path.normcase(os.path.realpath(p))


def resolve_program(prog, cfg):
    """Find the program to run. A bare name in pipe_allow only matches a program found on PATH
    outside the user's home and the current folder (places the assistant can write to); to allow
    a program inside home, the user lists its absolute path in pipe_allow."""
    allow = cfg["pipe_allow"]
    allowed_paths = {_norm(x) for x in allow if os.path.isabs(os.path.expanduser(x))}
    if os.path.dirname(prog):
        exe = _norm(os.path.expanduser(prog))
        if exe not in allowed_paths:
            die(f"run programs by name, not by path ({prog!r}); or the user lists the absolute path in "
                f"'pipe_allow'")
        return exe
    name = prog.casefold()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(ext):
            name = name[:-len(ext)]
    if name.startswith("python"):
        name = "python"
    names = {x.casefold() for x in allow if not os.path.dirname(x)}
    if allow and name not in names:
        die(f"program {name!r} is not in 'pipe_allow' in config.json (the user maintains that list)")
    if not allow and name in PIPE_DENY:
        die(f"program {name!r} could print or transform the secret; pipe refuses it. The user can allow it "
            f"with 'pipe_allow' in config.json")
    cwd = _norm(os.getcwd())
    search = os.pathsep.join(d for d in os.environ.get("PATH", "").split(os.pathsep)
                             if d and _norm(d) != cwd and d != ".")
    exe = shutil.which(prog, path=search)
    if not exe:
        die(f"program not found on PATH: {prog!r}")
    exe = _norm(exe)
    home = _norm(str(pathlib.Path.home()))
    if exe not in allowed_paths and (exe.startswith(home + os.sep) or exe.startswith(cwd + os.sep)):
        die(f"{prog!r} resolves to {exe}, inside your home or the current folder; the user must list that "
            f"absolute path in 'pipe_allow' to allow it")
    return exe


def cmd_pipe(ctx, kp, a):
    prog = list(a.program)
    if prog and prog[0] == "--":
        prog = prog[1:]
    if not prog:
        die("no program to run")
    exe = resolve_program(prog[0], ctx.cfg)
    e = find(kp, a.title)
    env = os.environ.copy()
    used = []
    for spec in a.env:
        var, _, field = spec.partition("=")
        if not var or not field or not var.replace("_", "a").isalnum() or var[0].isdigit():
            die(f"--env must look like VAR=FIELD: {spec!r}")
        if var.upper() in ENV_DENY or var.upper().startswith(ENV_DENY_PREFIX):
            die(f"--env may not set {var!r}")
        env[var] = get_field(e, field)
        used.append(env[var])
    data = None
    if not a.no_stdin:
        v = get_field(e, a.field)
        used.append(v)
        data = (v + "\n").encode("utf-8")
    for v in used:
        if len(v) < MIN_PIPE_LEN:
            die(f"refusing to pipe a secret shorter than {MIN_PIPE_LEN} characters (it could not be masked "
                f"reliably); rotate it first")
    masks = secrets_of(e, used)
    timeout = a.timeout if a.timeout is not None else ctx.cfg["pipe_timeout"]
    io_args = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
    try:
        r = subprocess.run([exe] + prog[1:], env=env, capture_output=True, timeout=timeout or None, **io_args)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as t:
        rc, out, err = 124, t.stdout or b"", (t.stderr or b"") + f"\n[gate] killed after {timeout}s".encode()
    out = redact(out.decode("utf-8", "replace"), masks)
    err = redact(err.decode("utf-8", "replace"), masks)
    if out:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    if err:
        sys.stderr.write(err if err.endswith("\n") else err + "\n")
    if rc < 0:
        rc = 128 - rc
    ctx.log("pipe", title=a.title, field=None if a.no_stdin else a.field,
            env=[s.partition("=")[0] for s in a.env], program=os.path.basename(exe), rc=rc)
    return rc


def cmd_add(ctx, kp, a):
    title, group = a.title, a.group
    if "/" in title and not group:
        group, title = title.rsplit("/", 1)
    group = "/".join(p for p in group.split("/") if p)
    if not title:
        die("empty title")
    name = f"{group}/{title}" if group else title
    if any(full_name(e) == name for e in live_entries(kp)):
        die(f"already exists: {name!r} (use rotate)")
    pw = gen(a.length, a.charset)

    def apply():
        kp.add_entry(ensure_group(kp, group), title, a.user, pw, url=a.url or None, notes=a.notes or None)
    return apply, f"added: {name} (generated a {a.length}-char password)"


def cmd_rotate(ctx, kp, a):
    e = find(kp, a.title)
    if a.field != "password" and a.field not in (e.custom_properties or {}):
        die(f"no such attribute: {a.field!r}")
    val = gen(a.length, a.charset)

    def apply():
        if a.field == "password":
            e.password = val
        else:
            e.set_custom_property(a.field, val, protect=True)
    return apply, f"rotated: {a.title} / {a.field} ({a.length} chars)"


def cmd_gen_attr(ctx, kp, a):
    e = find(kp, a.title)
    if a.name in (e.custom_properties or {}) and not a.overwrite:
        die(f"attribute already exists: {a.name!r} (use --overwrite or rotate)")
    val = gen(a.length, a.charset)
    return (lambda: e.set_custom_property(a.name, val, protect=True)), \
        f"generated secret attribute: {a.title} / {a.name}"


def cmd_set_attr(ctx, kp, a):
    e = find(kp, a.title)
    if a.name in (e.custom_properties or {}) and e.is_custom_property_protected(a.name):
        die(f"{a.name!r} is a secret attribute; it cannot be overwritten with a clear value")
    return (lambda: e.set_custom_property(a.name, a.value, protect=False)), \
        f"wrote clear attribute: {a.title} / {a.name}"


def cmd_set_user(ctx, kp, a):
    e = find(kp, a.title)
    return (lambda: setattr(e, "username", a.username)), f"username updated: {a.title}"


def cmd_set_url(ctx, kp, a):
    e = find(kp, a.title)
    return (lambda: setattr(e, "url", a.url)), f"url updated: {a.title}"


def cmd_trash(ctx, kp, a):
    e = find(kp, a.title)
    return (lambda: kp.trash_entry(e)), f"moved to Recycle Bin: {a.title}"


def run_write(ctx, a, handler):
    if gui_running() and not a.force_gui:
        die("a KeePass app is running. Save and close (or lock) the vault there first, then retry; "
            "or pass --force-gui if it has no unsaved changes")
    ctx.home.mkdir(parents=True, exist_ok=True)
    with Lock(ctx.home / "vault.lock"):
        kp = ctx.open()
        apply, msg = handler(ctx, kp, a)        # validates; may raise GateError, nothing written yet
        print(f"vault backup: {backup(ctx, 'before')}")
        apply()
        save(ctx, kp)
        backup(ctx, "after")
    print(msg)
    ctx.log(a.cmd, title=a.title, field=getattr(a, "field", None) or getattr(a, "name", None))


# ---------------------------------------------------------------- CLI

def nonneg(s):
    v = int(s)
    if v < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return v


def build_parser():
    ap = argparse.ArgumentParser(prog="vault", description="KeePassAI vault gate (never prints secret values)")
    sp = ap.add_subparsers(dest="cmd", required=True, metavar="<command>")

    def sub(name, help_, writes=False):
        p = sp.add_parser(name, help=help_, description=help_)
        if writes:
            p.add_argument("--force-gui", action="store_true", help="write even if a KeePass app is running")
        return p

    def gen_opts(p):
        p.add_argument("--length", type=int, default=28, help=f"{MIN_LEN}-{MAX_LEN}, default 28")
        p.add_argument("--charset", choices=sorted(CHARSETS), default="full",
                       help="full (default), urlsafe (safe in URLs/.env) or alnum")

    sub("list", "entries: full name, username, url, attribute NAMES")
    p = sub("show", "metadata of one entry")
    p.add_argument("title", help='title or full name "Group/Title"')

    p = sub("add", "new entry with a generated password", writes=True)
    p.add_argument("title", help='title, or "Group/Sub/Title" to put it in a group')
    p.add_argument("--user", default="")
    p.add_argument("--url", default="")
    p.add_argument("--group", default="", help="group path A/B (created if missing)")
    p.add_argument("--notes", default="", help="NOT for secrets: stored in clear and visible in the transcript")
    gen_opts(p)

    p = sub("rotate", "regenerate the password or a secret attribute", writes=True)
    p.add_argument("title")
    p.add_argument("--field", default="password", help='"password" or an attribute name')
    gen_opts(p)

    p = sub("gen-attr", "generate a secret (protected) attribute", writes=True)
    p.add_argument("title")
    p.add_argument("name")
    p.add_argument("--overwrite", action="store_true")
    gen_opts(p)

    p = sub("set-attr", "write a NON-secret attribute (stored in clear)", writes=True)
    p.add_argument("title")
    p.add_argument("name")
    p.add_argument("value")

    p = sub("set-user", "set the username", writes=True)
    p.add_argument("title")
    p.add_argument("username")
    p = sub("set-url", "set the URL", writes=True)
    p.add_argument("title")
    p.add_argument("url")
    p = sub("trash", "move to the Recycle Bin (never hard-deletes)", writes=True)
    p.add_argument("title")

    p = sub("pipe", "run a program with a secret on its stdin and/or in env vars; its output is masked")
    p.add_argument("--field", default="password", help="field for stdin (default: password)")
    p.add_argument("--env", action="append", default=[], metavar="VAR=FIELD", help="put FIELD into env var VAR")
    p.add_argument("--no-stdin", action="store_true", help="give the program no stdin")
    p.add_argument("--timeout", type=nonneg, default=None, help="seconds, 0 = none (default from config, 300)")
    p.add_argument("title")
    p.add_argument("program", nargs=argparse.REMAINDER, help="program and its arguments")
    return ap


READERS = {"list": cmd_list, "show": cmd_show, "pipe": cmd_pipe}
WRITERS = {"add": cmd_add, "rotate": cmd_rotate, "gen-attr": cmd_gen_attr, "set-attr": cmd_set_attr,
           "set-user": cmd_set_user, "set-url": cmd_set_url, "trash": cmd_trash}


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        ctx = Ctx()
        if a.cmd in READERS:
            return READERS[a.cmd](ctx, ctx.open(), a) or 0
        run_write(ctx, a, WRITERS[a.cmd])
        return 0
    except GateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return GATE_ERROR
    except Exception as e:  # never show a traceback: library errors may quote data
        print(f"ERROR: unexpected {type(e).__name__}; nothing was printed from the vault", file=sys.stderr)
        return GATE_ERROR


if __name__ == "__main__":
    sys.exit(main())
