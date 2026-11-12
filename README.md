# KeePassAI

Let an AI coding assistant **use** the secrets in your KeePass vault (generate them, store
them, feed them to commands) **without seeing them**.

**Which assistants it works with:**
- **The gate** is a plain command-line tool, so any assistant that can run shell commands can
  use it: Claude Code, OpenAI Codex CLI, Gemini CLI, Cursor, GitHub Copilot agent mode, Aider
  and others. Put the rules from [AI-INSTRUCTIONS.md](AI-INSTRUCTIONS.md) into that tool's
  instruction file (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, ...).
- **The guard**, which blocks every other way to the vault, is a pre-tool-call hook. The
  installer sets it up automatically for Claude Code. Any assistant that can run a command
  before each tool call can use it too, with `guard.py --format exit2`. It understands the
  common tool shapes (`Bash`, `run_shell_command`, `read_file`, `write_file`, `apply_patch`,
  ...). See [Using it with other assistants](#using-it-with-other-assistants). Without a
  hook, you get the gate and the rules, but no enforcement.

Works on Windows, macOS and Linux. It uses the standard KeePass `.kdbx` format, so you keep
using KeePassXC (or any KeePass app) as usual.

> Status: early (0.3, unreleased). Used day to day with Claude Code on Windows; macOS, Linux and the
> other assistants' tool shapes are covered by CI tests only.
> Read the [security model](#security-model-what-this-does-and-does-not-protect) before you rely on it.

## The problem

Homelab and dev work is full of secrets: container passwords, API tokens, services reached
over SSH. An assistant that sets those up needs to create and use secrets. But every value it
prints ends up in the chat transcript, in logs and in the model's context.

## How it works

```
 AI assistant ──► vault.ps1 / vault.sh ──► vault.py ──► your .kdbx vault
      │                  (the gate)          │
      │                                      └─ secrets go only to a program's stdin/env,
      │                                         and are masked in that program's output
      └─ every tool call ──► guard.py (pre-tool hook) ──► blocks every other way in
```

1. **The gate** (`vault.py`, run through `vault.ps1` on Windows or `vault.sh` on macOS/Linux)
   is the only way in. It lists names and metadata and generates secrets with Python's
   `secrets` module. When a secret must be used, it pipes it to a program's stdin or puts it
   in an environment variable. **No command prints a secret value.** The entry's secrets, and
   common encodings of them (reversed, base64, base32, hex, URL and JSON escaped), are
   replaced with `<hidden>` in the program's output. Every call is logged without secrets to
   `~/.keepassai/gate.log`.
2. **The guard** (`guard.py`) is a hook that runs before every tool call. It is installed
   automatically for Claude Code (`PreToolUse`) and can be wired into other assistants by
   hand. It works on **resolved paths**: it expands `~` and home variables, Git Bash `/c/`
   paths, wildcards and paths relative to `cd`, and it follows symlinks, junctions and 8.3
   names. It then decides whether a path is inside a protected place:
   - **off limits** (no reading, no writing): the key file, the vault file and the working
     folder `~/.keepassai` (only `gate.log` and `guard.log` may be read), which includes the
     pinned host keys in `known_hosts`;
   - **read-only**: the gate folder; the settings and hook files of Claude Code, Gemini CLI,
     Codex CLI and Cursor (`settings*.json`, `config.toml`, `hooks.json`, `hooks/`, in the
     home folder and in any project); shell profiles; Python start-up files (`sitecustomize.py`, `*.pth`) and the standard
     library the guard runs on.

   It also blocks recursive searches or copies of a folder that contains the key file, the
   KeePass tools and libraries in shell commands, scripts that import them, and shell
   obfuscation (`-EncodedCommand`, `base64 -d`, `iex`, `eval`). If the guard itself fails, it
   **denies** the call (fail closed). Denials are logged to `~/.keepassai/guard.log`.
3. **Safe writes**: every write runs under a lock file and saves atomically (temp file,
   fsync, rename). A backup is taken before and after each change, and a third copy of
   the file on disk right before it is replaced; the newest 50 backup files (about 16 writes)
   are kept.
   With `"allow_open_app": false` in `config.json`, writes are refused while a KeePass app is
   running, unless you pass `--force-gui`. By default they proceed (see [Writing while KeePassXC is open](#writing-while-keepassxc-is-open)).
   Deleting only moves an entry to the Recycle Bin; the gate has no hard delete.

## Commands

- Windows: `& "C:\path\to\KEEPASS-AI\vault.ps1" <command>`
- macOS / Linux: `/path/to/KEEPASS-AI/vault.sh <command>`

Add `--help` after any command to see its options.

| Command | What it does |
|---|---|
| `list` | All entries: full name (`Group/Title`), username, URL (credentials hidden), attribute **names**; entries that are expired or expire within 14 days (KeePass's *Expires* field) are marked `EXPIRED` / `expires YYYY-MM-DD` |
| `show <title>` | Metadata of one entry: whether a password is set, attribute names, dates, expiry date (or `never`) |
| `add <title> [--user U] [--url URL] [--group A/B] [--length 28] [--charset C] [--notes T]` | New entry with a generated password. `add "A/B/title"` puts the entry in group `A/B` |
| `rotate <title> [--field password\|ATTR] [--length 28] [--charset C]` | Regenerate the password or a secret attribute |
| `gen-attr <title> <name> [--length 28] [--charset C] [--overwrite]` | Generate a secret (protected) custom attribute, for example `DB_PASSWORD` |
| `set-attr <title> <name> <value>` | Write a **non-secret** attribute, stored in clear (for example `DB_USER`) |
| `set-user <title> <username>` / `set-url <title> <url>` | Edit those fields |
| `trash <title>` | Move to the Recycle Bin. Refused for an entry whose full name or title appears in a server's `PASSWORD` or `JUMP_HOST` field |
| `pipe [--field F] [--env VAR=F]... [--no-stdin] [--timeout S] <title> [--] <program> [args...]` | Run a program with the secret on stdin and/or in environment variables; its output is masked |
| `ssh [--timeout S] [--as CREDENTIAL] <server> [--] <command...>` | Run a command on a server, logging in with a password from the vault that the assistant never sees; output is masked. See [Servers and `ssh`](#servers-and-ssh) |

- `<title>` is either the entry title or its full name `Group/Sub/Title`; use the full name
  when two entries share a title.
- Field names: `password` is the Password field; anything else is a custom attribute.
- `--charset`: `full` (default, letters, digits and `-_.!@#%+=`), `urlsafe` (letters,
  digits and `-_.~`, safe in URLs and `.env` files) or `alnum`. Length is 12 to 256.
- Writing commands accept `--force-gui` to write while a KeePass app is open. Only use it if
  the app has no unsaved changes.
- Exit codes: `0` ok, `2` bad arguments, `3` gate error. `pipe` and `ssh` return the
  command's own code, or `124` if it hit the timeout (300 s by default).

### Writing while KeePassXC is open

By default (`"allow_open_app": true`) the writing commands also work while **KeePassXC** has the
vault open. The gate still takes the lock, saves atomically and makes backups. This relies on
KeePassXC noticing that the file changed and offering to reload or merge it (on by default).
Accept the merge prompt in KeePassXC; do not save over it.

If **KeePass 2** (`KeePass.exe`) is running, the gate refuses to write, because KeePass 2 may save
over the gate's change; close it first, or pass `--force-gui` if it has no unsaved changes. With
`"allow_open_app": false` the gate refuses whenever any KeePass app runs.

One small race remains: the gate compares the file's modification time before and again right
before it replaces the file, and copies the current file into `backups/` first. A save by
another app in the few milliseconds between that last check and the replace is not detected, but
the copy in `backups/` still holds it.

### Which programs `pipe` runs

A program that runs on your machine and receives the secret could print it in a form the
mask does not know. So by default `pipe` refuses interpreters, shells and text tools such as
`python`, `bash`, `powershell`, `node`, `cat`, `sed`, `base64`, `xxd` and `openssl`. A stricter
allowlist is better: the installer writes `"pipe_allow": ["ssh"]` into `config.json`, and then
only `ssh` may be used. Edit that list yourself (the assistant cannot) to allow `curl`,
`docker`, `psql` and so on.

Programs are given by name, never by path. A name must resolve on `PATH` to a file outside
your home folder and the current folder, because the assistant could plant a fake `ssh` in
those places. To allow a program that lives in your home folder, put its absolute path in
`pipe_allow`.

`pipe` refuses secrets shorter than 8 characters, because they cannot be masked reliably.
`--env` refuses variables that change how programs run (`PATH`, `LD_*`, `PYTHON*` and
similar).

### Servers and `ssh`

`ssh` logs in to a server with a password from the vault and runs one command. The assistant
does not get the password in any output (it is masked), and the host key is pinned. Read the
security note on remote commands under [Security model](#security-model-what-this-does-and-does-not-protect). It uses the `paramiko` library (installed
by `install.py`), not the `ssh` program, so `pipe_allow` does not apply to it.

**Vault convention.** A *server entry* has these custom fields (set them in the KeePass app):

| Field | Meaning |
|---|---|
| `HOSTNAME` | Host name of the server |
| `IP` | Optional. If set, the gate connects to it instead of `HOSTNAME` |
| `PORT` | Optional, default `22` |
| `PASSWORD` | Title or full name (`Group/Title`) of the *credential entry*, or a comma separated list of them. Use full names: a bare title must match exactly one entry, and the gate refuses it if another entry has the same title. This is a reference, not a secret. The credential entry's UserName and Password are used to log in |
| `HOST_KEY` | Optional. The expected host key fingerprint, exactly as the gate prints it on first use (`ssh-ed25519 SHA256:...`); `SHA256:...` or the bare fingerprint also work. It lives in the vault, so it survives a reinstall of this PC |
| `JUMP_HOST` | Reserved for a future jump host feature. **Not supported yet**: a server that has it set is refused |

```
SERVERS/TEST-WEB01   HOSTNAME=web01.example.lan  IP=10.0.0.11  PASSWORD=SSH-ALICE, PASSWORDS/SSH-BOB
PASSWORDS/SSH-ALICE  user alice, password ...
PASSWORDS/SSH-BOB    user bob,   password ...
```

```bash
vault.sh ssh TEST-WEB01 uptime                       # first credential in the PASSWORD list
vault.sh ssh --as PASSWORDS/SSH-BOB TEST-WEB01 -- systemctl status nginx
```

- `--as` must be written exactly as one item of the server's `PASSWORD` list, otherwise the
  gate refuses. Without `--as`, the first item is used.
- Password authentication only: no key files, no agent. `sudo` and jump hosts are **not
  supported yet**. The remote command gets no terminal and no stdin.
- **Host key.** With a `HOST_KEY` field, the gate compares the key the server presents with it
  before any password is sent: a match connects directly, a mismatch or a malformed value is
  refused (exit 3, showing the expected and presented fingerprints). Without `HOST_KEY`, the
  **first run only pins**: it stores the key in `~/.keepassai/known_hosts`, prints its type and
  SHA256 fingerprint on stderr and exits with 3 without sending anything. Check that fingerprint
  against the server, then run the command again; you can also copy the printed line into the
  entry's `HOST_KEY` field. Later runs refuse a different key. If both `HOST_KEY` and a
  `known_hosts` line exist and disagree, the gate refuses. A malformed or duplicate `known_hosts`
  line for a host is an error, never a reason to pin again. If a server was legitimately
  reinstalled, you delete its line from `known_hosts` and update `HOST_KEY` yourself (the guard
  keeps the assistant out of that file). `HOSTNAME` and `IP` may only contain letters, digits and
  `. : _ - %`.
- **Output.** Stdout and stderr are masked like `pipe`: the password and its encodings. The
  server's `HOSTNAME` and `IP` (any letter case) are masked too; set `"mask_hosts": false` in
  `config.json` to turn that off. Errors are masked the same way.
- Exit code: the remote command's, `124` on timeout (`pipe_timeout`, or `--timeout`), `3` if
  the gate itself failed (bad reference, connection or authentication error, host key mismatch).
- **Reserved fields.** The writing commands (`set-attr`, `gen-attr`, `rotate --field`) refuse
  `HOSTNAME`, `IP`, `PORT`, `PASSWORD`, `HOST_KEY` and `JUMP_HOST` in any letter case. Otherwise the
  assistant could point a stored credential at a host it controls. Only you change these fields,
  in the KeePass app.

### Examples

```bash
# a new database container: entry in group "Containers", plus a secret attribute
vault.sh add "Containers/postgres" --user app --url https://db.example.lan
vault.sh gen-attr "Containers/postgres" POSTGRES_PASSWORD --charset urlsafe

# set a service password on a remote server: the secret travels only over ssh stdin
vault.sh pipe "Gitea - alice" ssh -o BatchMode=yes myserver "bash /tmp/apply-password.sh alice"

# a local tool with the secret in an environment variable (needs "psql" in pipe_allow)
vault.sh pipe --no-stdin --env PGPASSWORD=password "Containers/postgres" psql -h db -U app -c "select 1"
```

The receiving side reads the secret from stdin. In bash:
`IFS= read -r PW; PW="${PW%$'\r'}"`. Prefer stdin over command-line arguments, because other
users can see arguments in `ps`.

## Install

**[INSTALL.md](INSTALL.md)** is the full step-by-step guide. It covers KeePassXC, Python,
creating a vault that opens with a key file, `install.py`, enabling the hook, testing it,
updating and uninstalling.

Short version:

```bash
git clone https://github.com/ozuakcelil/KEEPASS-AI.git ~/tools/KEEPASS-AI
python3 ~/tools/KEEPASS-AI/install.py --db ~/Vault/home.kdbx --key ~/.keys/home.keyx --hook
```

`--hook` sets up the guard for Claude Code; leave it out for other assistants and see
[Using it with other assistants](#using-it-with-other-assistants). Then restart the
assistant, and put the contents of [AI-INSTRUCTIONS.md](AI-INSTRUCTIONS.md) into its
instruction file (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, ...) so it knows how to use the gate.

## Using it with other assistants

1. Install as described in INSTALL.md, but skip `--hook` if you do not use Claude Code.
2. Copy the rules from [AI-INSTRUCTIONS.md](AI-INSTRUCTIONS.md) into the assistant's
   instruction file, for example `AGENTS.md` (Codex CLI and others), `GEMINI.md` (Gemini
   CLI), `.cursor/rules/` (Cursor) or `.github/copilot-instructions.md` (Copilot).
3. Without the guard, those rules are a request, not a barrier. If your tool has a
   pre-execution hook or an approval policy, use it:
   - call `guard.py --format exit2` from that hook (INSTALL.md, step 7). It reads the tool
     call as JSON on stdin; when it denies, it exits with code 2 and prints the reason on
     stderr;
   - or at least require your approval for every shell command.
4. The other protections live in the gate itself and work with every assistant: masked
   output, the `pipe_allow` list, backups, locking and no hard delete.

## Files

| File | Role |
|---|---|
| `vault.py` | The gate (needs the `pykeepass` library) |
| `vault.ps1`, `vault.sh` | Wrappers that run the gate with its private venv |
| `guard.py` | Pre-tool-call hook: Claude Code format by default, `--format exit2` for other tools (standard library only) |
| `common.py` | Shared config loading |
| `install.py` | Creates the venv, the config and (optionally) the hook |
| `config.example.json` | Config template |
| `AI-INSTRUCTIONS.md` | Rules to paste into your assistant's instruction file (`CLAUDE.md`, `AGENTS.md`, ...) |
| `tests/` | pytest suite; it uses a throwaway vault in a temp folder |

Working folder (not in the repo): `~/.keepassai/` holds `venv/`, `config.json`, `backups/`,
`gate.log`, `guard.log` and `known_hosts` (pinned SSH host keys). Override it with `KEEPASSAI_HOME`, the config file with
`KEEPASSAI_CONFIG` and the Python interpreter with `KEEPASSAI_PYTHON`.

### config.json

| Key | Default | Meaning |
|---|---|---|
| `db`, `key` | (required) | Vault file and key file |
| `pipe_allow` | `["ssh"]` from the installer | If not empty, the only programs `pipe` may run |
| `keep_backups` | `50` | Backups to keep; `0` keeps all |
| `allow_open_app` | `true` | Writing commands run while KeePassXC is open (KeePass 2 always refuses). `false` refuses for any app unless `--force-gui` |
| `pipe_timeout` | `300` | Seconds before a `pipe` program or an `ssh` command is killed; `0` means no limit |
| `mask_hosts` | `true` | `ssh` masks the server's `HOSTNAME` and `IP` in its output |
| `deny` | `[]` | Extra words the guard blocks in shell commands (4+ characters) |

## Security model: what this does and does not protect

**It does:**
- keep secret values out of the assistant's context, the chat transcript and tool logs
  during normal work;
- make the gate the single, audited path to the vault;
- stop the assistant from editing the gate, the hook or its own settings, and from reading
  the key file, with resolved-path checks;
- protect against honest mistakes like `cat .env` or "let me just print it to check".

**It does not:**
- **encrypt anything against the assistant.** The vault is unlocked by a key file alone, and
  that file sits on a disk the assistant's user account can read. The guard inspects tool
  calls; it cannot see what a program does once it runs. These are known ways around it, and
  they cannot be closed by inspecting commands:
  - code that builds a path or module name at run time (string arithmetic, reading a path
    from a file, walking the home folder);
  - a script written with harmless-looking content and run later, or code downloaded and run;
  - a program on a remote host reached through `pipe`: `ssh host "rev"` sends the secret back
    reversed in a way the mask may not cover, and any program can send it over the network;
  - links created by other processes, and races between the check and the execution.

  Treat it as a strong seatbelt, not a vault door. The real fix is an OS boundary, such as
  running the assistant as a different user that cannot read the key file.
- make `ssh` safe against someone who can edit the vault. The server fields (`HOSTNAME`, `IP`,
  `PORT`, `PASSWORD`, `JUMP_HOST`, `HOST_KEY`) decide where a password is sent; the gate will not write them,
  but anyone who can write the vault (the KeePass app, a sync tool) can.
  Also, `pipe` with an allowed `ssh` program can still send a secret to any host the assistant
  names; keep `pipe_allow` short.
- protect a password from a remote command that runs with enough rights. `ssh` masks what a
  command prints, but the command itself runs on the server with the credential's rights. With
  a root or `NOPASSWD` sudo credential it can hook PAM or `sshd` and capture this and later
  passwords of that server, and send them anywhere. Use non-root credentials for the assistant
  and treat a server's passwords as exposed to whoever can run commands there.
- protect secrets after they leave the gate. If `pipe` sends a password to a server, the
  server has it.
- enforce anything for an assistant that has no hook pointing at the guard. The gate works
  with any assistant; enforcement needs the hook (set up automatically for Claude Code, by
  hand for others), or at least an approval step for shell commands.
- remove old secrets. Backups and the Recycle Bin keep previous values until you delete them
  yourself.
- block the call when the guard cannot start or times out, unless the assistant supports
  that. Claude Code does, with `onFailure: block` in recent versions; check your tool's hook
  docs.

**Keep truly personal secrets elsewhere.** Use this vault only for the machine and service
credentials the assistant manages. Put bank, email and other personal passwords in a second
vault, protected by a master password that the assistant never gets.

Found a hole? See [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install pytest
.venv/bin/pytest -q
```

The guard protects the folder it is installed from. Work on a **separate clone**, not on
the copy your hook points at. The source mentions KeePass file and library names, so an
assistant session with the guard enabled cannot edit `.py` files that use them.

`requirements.txt` pins every dependency, including indirect ones, with hashes (pip then
checks every download, so `pytest` is installed in a separate command). To change a version,
edit `requirements.in` and run `pip-compile --generate-hashes --strip-extras -o requirements.txt
requirements.in` (from `pip-tools`) on the oldest Python you support.

## License

[MIT](LICENSE)
