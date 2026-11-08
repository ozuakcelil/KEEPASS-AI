"""KeePassAI guard - a pre-tool-call hook for AI coding assistants.

Reads one tool call as JSON on stdin and denies it when the call would
  * read or write the secret files: the key file, the vault file, the working folder
    (venv, config, backups; only gate.log / guard.log may be read), or
  * modify protected files: the gate folder, the assistants' settings and hook files
    (Claude Code, Gemini CLI, Codex CLI, Cursor), shell profiles, Python start-up files, or
  * use KeePass tooling or obfuscation tricks in a shell command,
unless the call is the gate itself (vault.ps1 / vault.sh). Everything else is allowed silently.

Input: {"tool_name": ..., "tool_input": {...}, "cwd": ...} (Claude Code, Gemini CLI and
similar), or a flat {"command": ..., "cwd": ...} / {"file_path": ...} event.
Output (--format):
  claude (default) a Claude Code PreToolUse JSON decision on stdout, exit 0
  exit2            the reason on stderr and exit code 2 on deny (the common hook convention)

Decisions are made on resolved paths (symlinks, junctions, hard links, 8.3 names, \\\\?\\ paths,
Git Bash /c/ paths, ~ and home variables, wildcards, brace expansion, escapes, relative paths
after cd), not on raw text. If the guard itself fails, it denies (fail closed).

This is a strong seatbelt, not a cryptographic boundary: code that builds a path at run time
can still get past it. See README.md, "Security model".
"""
import datetime
import glob
import json
import os
import pathlib
import re
import sys
import sysconfig
import unicodedata

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # needed under python -I
import common  # noqa: E402

# Tool names differ per assistant: a tool counts as writing if its name says so.
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file", "replace", "apply_patch",
               "edit_file", "create_file", "delete_file", "str_replace", "insert"}
WRITE_HINT = re.compile(r"write|edit|replace|patch|create|delete|insert|move|rename|append", re.I)
SEARCH_HINT = re.compile(r"grep|search", re.I)
PATH_FIELDS = ("file_path", "notebook_path", "path", "absolute_path", "target_file", "filename", "file",
               "dir_path", "directory", "source", "destination", "target")
PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+?)\s*$|^\*\*\* Move to: (.+?)\s*$", re.M)
# Folders of assistants whose settings or hook files must not be changed by the assistant.
AGENT_DIRS = (".claude", ".gemini", ".codex", ".cursor")
AGENT_CONFIG = re.compile(r"^(settings[\w.-]*\.json|config\.toml|hooks\.json|mcp\.json)$")
LOG_NAMES = {"gate.log", "guard.log", "guard.log.1", "gate.log.1"}
LOG_LIMIT = 1_000_000

# Words that mean "using KeePass tooling directly" when they appear in a shell command.
TOOL_NAMES = [".kdbx", ".keyx", "keepassxc", "pykeepass", "kpcli", "keepass2", "libkeepass"]
# Variables that redirect the gate to another interpreter or config.
ENV_NAMES = ["keepassai_home", "keepassai_config", "keepassai_python"]
# Text that hides what a command does, anywhere in the command.
OBFUSCATION = [r"frombase64string", r"\bbase64\s+(-d|-D|--decode)\b", r"\[char\]", r"scriptblock\]::create"]
# Commands that run a string as code.
EVAL_VERBS = {"eval", "iex", "invoke-expression", "invoke-command", "icm"}
PS_VERBS = {"powershell", "pwsh"}
PS_ENCODED = re.compile(r"^-(e|ec|en|enc|enco\w*|encodedcommand)$", re.I)
# Redirections that cannot write a file.
HARMLESS_REDIRECT = re.compile(r"\d?>>?\s*(&\d|/dev/null|\$null|nul\b)", re.I)
# Commands that may follow the gate in a pipeline (they cannot write files).
SAFE_FILTERS = {"head", "tail", "grep", "findstr", "select-string", "sls", "out-null", "select-object", "select",
                "sort", "sort-object", "wc", "more", "measure-object", "out-string", "format-table", "ft",
                "format-list", "fl", "where-object", "where", "?"}
# Python start-up hooks: writing one of these could change how the guard runs.
STARTUP_FILES = re.compile(r"(^|/)(sitecustomize|usercustomize)\.py$|/(site|dist)-packages/[^/]*\.pth$")
SCRIPT_EXT = (".py", ".pyw", ".ps1", ".psm1", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".js", ".mjs",
              ".ts", ".rb", ".pl", ".php", ".lua", ".vbs")

READ_VERBS = {"cat", "type", "gc", "get-content", "head", "tail", "less", "more", "ls", "dir", "gci",
              "get-childitem", "wc", "stat", "file", "grep", "rg", "findstr", "select-string", "sls",
              "diff", "cmp", "fc", "test-path", "get-item", "gi", "resolve-path", "get-filehash", "sha256sum"}
GIT_READ = {"status", "log", "diff", "show", "blame", "ls-files", "rev-parse", "branch", "remote"}
CD_VERBS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
GREP_VERBS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr", "select-string", "sls"}
BULK_VERBS = GREP_VERBS | {"tar", "zip", "7z", "compress-archive", "robocopy", "xcopy", "cp", "copy",
                           "copy-item", "cpi", "rsync", "scp", "mv", "move", "move-item", "mi"}
SHELL_PREFIX = {"bash", "sh", "zsh", "pwsh", "pwsh.exe", "powershell", "powershell.exe", "&"}

IS_WIN = os.name == "nt"
OFF_LIMITS = "the key file, the vault file and the gate's working folder are off limits"
READ_ONLY = "the gate, its logs, assistant settings and hooks, shell profiles and Python start-up files " \
            "are read-only for the assistant"
NARROW = "bulk read, copy or search of a folder that contains the key file; give a narrower path"


class Denied(Exception):
    pass


# ---------------------------------------------------------------- paths

def fold(s: str) -> str:
    s = unicodedata.normalize("NFC", s).replace("\\", "/")
    s = re.sub(r"/{2,}", "/", s)
    return s.casefold()


def strip_device_prefix(p: str) -> str:
    m = re.match(r"^[\\/]{2}[?.][\\/](unc[\\/])?", p, re.I)
    if not m:
        return p
    return ("\\\\" if m.group(1) else "") + p[m.end():]


def real(p) -> str:
    p = strip_device_prefix(str(p))
    try:
        r = os.path.realpath(os.path.abspath(p))
    except (OSError, ValueError):
        r = os.path.abspath(p)
    return fold(strip_device_prefix(r)).rstrip("/") or "/"


def inside(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


def file_id(p):
    try:
        st = os.stat(p)
    except (OSError, ValueError):
        return None
    return (st.st_dev, st.st_ino) if st.st_ino else None


def expand_braces(t: str):
    m = re.search(r"\{([^{}]*,[^{}]*)\}", t)
    if not m:
        return [t]
    out = []
    for alt in m.group(1).split(",")[:20]:
        out += expand_braces(t[:m.start()] + alt + t[m.end():])
    return out[:200]


def expand_token(tok: str) -> str:
    home = str(pathlib.Path.home())
    t = strip_device_prefix(tok)
    t = re.sub(r"(?i)\$env:(\w+)", lambda m: os.environ.get(m.group(1), m.group(0)), t)
    t = re.sub(r"(?i)^\$\{?home\}?(?=[/\\]|$)", lambda m: home, t)
    if t.startswith("~") and (len(t) == 1 or t[1] in "/\\"):
        t = home + t[1:]
    t = os.path.expandvars(t)
    if IS_WIN:
        m = re.match(r"^/(?:mnt/|cygdrive/)?([a-zA-Z])(/|$)", t)
        if m:
            t = m.group(1) + ":/" + t[m.end():]
    return t


def candidates(tok: str, cwd: str):
    """Every real path a shell token might name (braces and wildcards expanded)."""
    out = []
    for word in expand_braces(tok):
        t = expand_token(word.strip("{}"))
        if not t or "://" in t:
            continue
        base = t if os.path.isabs(t) or re.match(r"^[a-zA-Z]:", t) else os.path.join(cwd or os.getcwd(), t)
        out.append(base)
        if any(c in base for c in "*?["):
            try:
                out += glob.glob(base)[:500]
                parent, leaf = os.path.split(base)
                if any(c in parent for c in "*?["):
                    out += [os.path.join(d, leaf) for d in glob.glob(parent)[:200]]
            except (OSError, ValueError, re.error):
                pass
    return [real(p) for p in out]


class Rules:
    def __init__(self, home_arg=None):
        if home_arg:
            os.environ["KEEPASSAI_HOME"] = home_arg
        try:
            self.cfg = common.load_config(required=False)
        except common.ConfigError as e:
            raise Denied(f"config problem ({e}); fix config.json yourself")
        home = pathlib.Path.home()
        self.work = real(common.vault_home())
        self.gate = real(common.GATE_DIR)
        self.key = real(self.cfg["key"]) if self.cfg["key"] else None
        self.db = real(self.cfg["db"]) if self.cfg["db"] else None
        self.ids = {i for i in (file_id(self.cfg["key"]) if self.key else None,
                                file_id(self.cfg["db"]) if self.db else None) if i}
        self.protected = [self.gate]
        agent_homes = [home / d for d in AGENT_DIRS]
        for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CONFIG_DIR"):
            if os.environ.get(var):
                agent_homes.append(pathlib.Path(os.environ[var]))
        for d in agent_homes:
            self.protected += [real(d / "hooks"), real(d / "settings.json"), real(d / "settings.local.json"),
                               real(d / "config.toml"), real(d / "hooks.json")]
        for name in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
                     ".zlogin", ".config/fish", ".config/powershell", "Documents/PowerShell",
                     "Documents/WindowsPowerShell"):
            self.protected.append(real(home / name))
        # the standard library the guard itself runs on (not all of /usr on Linux)
        self.stdlib = real(sysconfig.get_paths()["stdlib"])
        self.text_deny = TOOL_NAMES + ENV_NAMES + [fold(x) for x in self.cfg["deny"] if len(x.strip()) >= 4]
        for p in (self.key, self.db):
            if p:
                name = p.rsplit("/", 1)[-1]
                if len(name) >= 4:
                    self.text_deny.append(name)

    def is_log(self, p: str) -> bool:
        return p.rsplit("/", 1)[0] == self.work and p.rsplit("/", 1)[-1] in LOG_NAMES

    def secret(self, p: str) -> bool:
        if self.key and inside(p, self.key):
            return True
        if self.db and p == self.db:
            return True
        if inside(p, self.work):
            return not self.is_log(p)
        return bool(self.ids) and file_id(p) in self.ids   # hard links and other names of the same file

    def write_protected(self, p: str) -> bool:
        if self.is_log(p) or any(inside(p, r) for r in self.protected):
            return True
        parts = p.split("/")
        if len(parts) >= 2 and parts[-2] in AGENT_DIRS and AGENT_CONFIG.match(parts[-1]):
            return True          # project-level settings/hook files of any assistant
        if len(parts) >= 3 and parts[-3] in AGENT_DIRS and parts[-2] == "hooks":
            return True
        return bool(STARTUP_FILES.search(p))

    def key_ancestor(self, p: str) -> bool:
        return bool(self.key) and p != self.key and inside(self.key, p)


# ---------------------------------------------------------------- shell parsing

def lex(cmd: str, posix: bool):
    """Split a command into segments of tokens, the way bash (posix=True) or PowerShell would.
    Quotes are removed and escapes undone. Returns (segments, piped, redirect): piped[i] is True
    when segment i reads the previous one's output."""
    segs, piped, cur, tok = [], [], [], []
    q, redirect, sep = None, False, ""
    i, n = 0, len(cmd)

    def end_tok():
        if tok:
            t = "".join(tok)
            if not posix and not IS_WIN:
                t = t.replace("\\", "/")    # PowerShell on macOS/Linux accepts \ as a path separator
            cur.append(t)
            tok.clear()

    def end_seg(next_sep):
        nonlocal sep
        end_tok()
        if cur:
            segs.append(list(cur))
            piped.append(sep == "|")
            cur.clear()
        sep = next_sep

    while i < n:
        c = cmd[i]
        nxt = cmd[i + 1] if i + 1 < n else ""
        if q == "'":
            if c == "'":
                q = None
            else:
                tok.append(c)
        elif posix and c == "\\" and nxt and (q is None or nxt in '$`"\\\n'):
            i += 1
            if nxt != "\n":
                tok.append(nxt)
        elif not posix and c == "`" and nxt:          # PowerShell escape
            i += 1
            if nxt not in "\r\n":
                tok.append(nxt)
        elif posix and c == "`":                        # bash command substitution
            end_seg("")
        elif q == '"':
            if c == '"':
                q = None
            elif c == "$" and nxt == "(":
                end_seg("")
                i += 1
            else:
                tok.append(c)
        elif c in "'\"":
            q = c
        elif c == "|":
            end_seg("|" if nxt != "|" else "")
            if nxt == "|":
                i += 1
        elif c in ";&\n\r()":
            end_seg("")
        elif c == "$" and nxt == "(":
            end_seg("")
            i += 1
        elif c in "{}" and not tok and (i + 1 >= n or cmd[i + 1].isspace() or cmd[i + 1] in ";|&"):
            end_seg("")                                 # a block such as "{ ... }", not a brace expansion
        elif c in "<>":
            redirect = True
            end_tok()
        elif c.isspace() or c in ",=" and q is None and not ("{" in "".join(tok) and "}" not in "".join(tok)):
            end_tok()
        else:
            tok.append(c)
        i += 1
    end_seg("")
    return segs, piped, redirect


def verb(seg):
    v = seg[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return v[:-4] if v.endswith(".exe") else v


def git_subcommand(seg):
    i = 1
    while i < len(seg):
        t = seg[i]
        if t in ("-C", "-c", "--git-dir", "--work-tree"):
            if t == "-c":
                return None  # inline config can run programs
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t.casefold()
    return None


def is_read_only(segs, redirect) -> bool:
    if redirect or len(segs) != 1:
        return False
    s = segs[0]
    v = verb(s)
    if v == "git":
        return git_subcommand(s) in GIT_READ
    return v in READ_VERBS and not any(t.casefold() in {"-i", "--in-place"} for t in s[1:])


def gate_call(segs, redirect, rules, cwd):
    """If the command is one call of the gate wrapper (optionally piped into read-only filters),
    return the index of the wrapper token inside the first segment; else None."""
    if redirect or not segs or any(verb(s) not in SAFE_FILTERS for s in segs[1:]):
        return None
    s = segs[0]
    i = 0
    while i < len(s) and (s[i].casefold() in SHELL_PREFIX or (i and s[i].startswith("-"))):
        if s[i].casefold() in {"-executionpolicy", "-ep"}:
            i += 1
        i += 1
    if i >= len(s):
        return None
    target = candidates(s[i], cwd)
    ok = {rules.gate + "/vault.ps1", rules.gate + "/vault.sh"}
    return i if target and target[0] in ok else None


def words_of(seg, skip_upto):
    """(index, word) pairs worth resolving as paths: option values and the words inside
    quoted strings ("bash -c '...'") are included."""
    out = []
    for ti, tok in enumerate(seg):
        if ti <= skip_upto:
            continue
        if tok.startswith("-") and ti:
            m = re.match(r"^--?[\w-]+[:=](.+)$", tok)       # -Path:value, --file=value
            if not m:
                continue
            tok = m.group(1)
        out.append((ti, tok))
        if any(c.isspace() for c in tok):
            out += [(ti, w.strip("'\"")) for w in tok.split()]
    return out


def check_lexed(segs, piped, redirect, rules, cwd, low):
    g = gate_call(segs, redirect, rules, cwd)
    hit = next((w for w in rules.text_deny if w and w in low), None)
    if hit and g is None:
        raise Denied(f"direct use of vault tooling or files ('{hit}')")
    for seg in segs:
        v = verb(seg)
        if v in EVAL_VERBS:
            raise Denied(f"running strings as code is not allowed ('{v}')")
        if v in PS_VERBS and any(PS_ENCODED.match(t) for t in seg[1:]):
            raise Denied("encoded PowerShell commands are not allowed")

    read_only = is_read_only(segs, redirect)
    cur = cwd
    for si, seg in enumerate(segs):
        v = verb(seg)
        skip = g if (g is not None and si == 0) else -1
        for ti, tok in words_of(seg, skip):
            # arguments of the gate itself are titles and options, not local paths
            plain_gate_arg = skip >= 0 and not re.search(r"[/\\~$%]", tok)
            for p in candidates(tok, cur):
                if rules.secret(p):
                    raise Denied(OFF_LIMITS)
                if plain_gate_arg:
                    continue
                if rules.write_protected(p) and not read_only:
                    raise Denied(READ_ONLY)
                if ti and inside(p, rules.stdlib) and not read_only:
                    raise Denied("the Python installation the guard runs on is read-only for the assistant")
                if v in BULK_VERBS and rules.key_ancestor(p):
                    raise Denied(NARROW)
        if v in GREP_VERBS and not piped[si] and rules.key_ancestor(real(cur or os.getcwd())):
            named = [c for _, t in words_of(seg, 0) for c in candidates(t, cur)[:1]]
            if not any(os.path.exists(c) for c in named):
                raise Denied(NARROW)
        if v in CD_VERBS and len(seg) > 1:
            args = [t for t in seg[1:] if not t.startswith("-")]
            if args:
                c = candidates(args[0], cur)
                if c:
                    cur = c[0]


def check_shell(cmd: str, rules: Rules, cwd: str, tool: str):
    low = " " + fold(re.sub(r"[`\"'\\]", "", cmd)) + " "
    if "disableallhooks" in low:
        raise Denied("changing hook switches is reserved for the user")
    m = next((m for m in (re.search(p, low) for p in OBFUSCATION) if m), None)
    if m:
        raise Denied(f"obfuscated shell commands are not allowed ('{m.group(0).strip()}')")
    text = HARMLESS_REDIRECT.sub(" ", cmd)
    # Bash on Windows still gets Windows paths, so check every command both ways.
    modes = [True, False] if tool != "PowerShell" else [False]
    for posix in modes:
        segs, piped, redirect = lex(text, posix)
        check_lexed(segs, piped, redirect, rules, cwd, low)


# ---------------------------------------------------------------- other tools

def tool_paths(tin: dict):
    """Paths named by a tool input: the usual path fields, list fields such as "paths", and the
    file headers of an apply_patch style patch."""
    out = []
    for field in PATH_FIELDS + ("paths", "files", "file_paths"):
        val = tin.get(field)
        if isinstance(val, str) and val:
            out.append(val)
        elif isinstance(val, list):
            out += [v for v in val if isinstance(v, str) and v]
    for val in tin.values():
        if isinstance(val, str) and "*** " in val:
            out += [a or b for a, b in PATCH_FILE.findall(val)]
    return out


def check_paths(tool: str, tin: dict, rules: Rules, cwd: str):
    name = tool.casefold().rsplit("__", 1)[-1]          # mcp__server__tool -> tool
    writes = name in WRITE_TOOLS or bool(WRITE_HINT.search(name))
    searches = bool(SEARCH_HINT.search(name))
    paths = tool_paths(tin)
    for val in paths:
        found = candidates(val, cwd)
        if not found:
            continue
        p = found[0]
        if rules.secret(p):
            raise Denied(OFF_LIMITS)
        if writes and (rules.write_protected(p) or inside(p, rules.stdlib)):
            raise Denied(READ_ONLY)
        if searches and rules.key_ancestor(p):
            raise Denied(NARROW)
    if searches and not paths and rules.key_ancestor(real(cwd or os.getcwd())):
        raise Denied(NARROW)

    if writes:
        path = str(tin.get("file_path") or tin.get("notebook_path") or tin.get("path") or "")
        if path.casefold().endswith(SCRIPT_EXT):
            body = fold(json.dumps({k: v for k, v in tin.items() if k not in PATH_FIELDS}, ensure_ascii=False))
            hit = next((w for w in rules.text_deny if w and w in body), None)
            if hit:
                raise Denied(f"a script that uses vault tooling or files ('{hit}'); use the gate instead")


# ---------------------------------------------------------------- main

def log_denial(tool, reason):
    try:
        home = common.vault_home()
        home.mkdir(parents=True, exist_ok=True)
        log = home / "guard.log"
        if log.exists() and log.stat().st_size > LOG_LIMIT:
            os.replace(log, home / "guard.log.1")
        with log.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": datetime.datetime.now().isoformat(timespec="seconds"),
                                "tool": tool, "reason": reason}) + "\n")
    except Exception:
        pass


def decide(data: dict, home_arg=None):
    """Return None to allow, or the denial reason."""
    if not isinstance(data, dict):
        data = {}
    tool = str(data.get("tool_name") or "")
    tin = data.get("tool_input")
    if not isinstance(tin, dict):
        # flat events (for example a "before shell execution" hook): the event is the input
        tin = {k: v for k, v in data.items() if k != "cwd"} if not tool else {}
        tool = tool or ("Shell" if isinstance(data.get("command"), str) else "Read")
    cwd = str(data.get("cwd") or "")
    try:
        rules = Rules(home_arg)
        if isinstance(tin.get("command"), str):
            check_shell(tin["command"], rules, cwd, tool)
        check_paths(tool, tin, rules, cwd)
    except Denied as d:
        return str(d)
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    home_arg = argv[argv.index("--home") + 1] if "--home" in argv[:-1] else None
    fmt = argv[argv.index("--format") + 1] if "--format" in argv[:-1] else "claude"
    tool = "?"
    try:
        raw = sys.stdin.buffer.read().decode("utf-8-sig", "replace")
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
        tool = str(data.get("tool_name") or "?")
        reason = decide(data, home_arg)
    except Exception as e:  # fail closed
        reason = f"guard internal error ({type(e).__name__}); run guard.py by hand to see why"
    if reason is None:
        return 0
    log_denial(tool, reason)
    message = (f"KeePassAI guard: {reason}. Use the vault gate (vault.ps1 / vault.sh) or ask the user; "
               f"see {common.GATE_DIR / 'README.md'}")
    if fmt == "exit2":
        print(message, file=sys.stderr)
        return 2
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": message,
    }}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
