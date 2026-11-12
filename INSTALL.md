# Installing KeePassAI, step by step

This guide covers Windows, macOS and Linux. Where the commands differ, each OS is shown.
It takes about 15 minutes.

At the end you will have:
- a KeePass vault (`.kdbx`) that opens with a **key file** (no typed password);
- a working folder `~/.keepassai/` with a private Python venv, the config and backups;
- the gate (`vault.ps1` / `vault.sh`) that the assistant uses;
- the guard hook (automatic for Claude Code, manual for other assistants), which blocks
  every other way to the vault.

---

## Step 1. Install KeePassXC (optional but recommended)

You only need it to look at and edit the vault yourself.

| OS | Command |
|---|---|
| Windows | `winget install KeePassXCTeam.KeePassXC` |
| macOS | `brew install --cask keepassxc` |
| Debian/Ubuntu | `sudo apt install keepassxc` |
| Fedora | `sudo dnf install keepassxc` |

Or download it from https://keepassxc.org/download/.

## Step 2. Install Python 3.10 or newer, and git

Check first: `py -3 --version` (Windows) or `python3 --version` (macOS/Linux).

| OS | Command |
|---|---|
| Windows | `winget install Python.Python.3.13 Git.Git` (then open a new terminal) |
| macOS | `brew install python git` |
| Debian/Ubuntu | `sudo apt install python3 python3-venv git` |
| Fedora | `sudo dnf install python3 git` |

- On Windows, use `py -3` rather than `python`: `python` may open the Microsoft Store.
- On Debian/Ubuntu you need the `python3-venv` package. Without it the installer cannot
  create its venv.

## Step 3. Create the vault and its key file

The assistant has to open the vault without anyone typing a password, so the vault is locked
with a **key file only**.

1. Pick two locations:
   - the **vault file**, for example `~/Vault/home.kdbx`. It may sit in a synced folder
     (iCloud, Dropbox, Syncthing) so you can open it on other devices;
   - the **key file**, for example `~/.keys/home.keyx`. Keep it **out of** synced folders, out
     of git and out of folders you often search or archive. The guard blocks recursive
     searches and copies of any folder that contains it.
2. Create the key file folder and lock it down:
   - Windows (PowerShell):
     ```powershell
     New-Item -ItemType Directory -Force "$HOME\.keys" | Out-Null
     icacls "$HOME\.keys" /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
     ```
   - macOS/Linux:
     ```bash
     mkdir -p ~/.keys && chmod 700 ~/.keys
     ```
3. In KeePassXC, choose **Database → New Database**. Give it a name and keep the default
   encryption settings. On the **Database Credentials** page:
   - leave the password empty (KeePassXC asks you to confirm that);
   - click **Add additional protection → Key File → Generate**, and save the file as
     `~/.keys/home.keyx`.

   Save the database as `~/Vault/home.kdbx`.
4. **Back up the key file** somewhere offline: a USB stick, a different kind of password
   manager, or a printout. Without it the vault cannot be opened.

Already have a vault that opens with a key file only? Skip to step 4 and point the installer
at it.

> The installer and the gate do not support a master password, on purpose: the assistant
> would have to know it. For personal secrets, use a second, password-protected vault that
> the assistant never touches.

## Step 4. Get the code and run the installer

Clone the repository to a folder of its own, for example `~/tools/KEEPASS-AI`. The guard
protects this folder against changes by the assistant, so do not put your own projects in it.

- Windows (PowerShell):
  ```powershell
  git clone https://github.com/ozuakcelil/KEEPASS-AI.git "$HOME\tools\KEEPASS-AI"
  py -3 "$HOME\tools\KEEPASS-AI\install.py" --db "$HOME\Vault\home.kdbx" --key "$HOME\.keys\home.keyx"
  ```
- macOS/Linux:
  ```bash
  git clone https://github.com/ozuakcelil/KEEPASS-AI.git ~/tools/KEEPASS-AI
  python3 ~/tools/KEEPASS-AI/install.py --db ~/Vault/home.kdbx --key ~/.keys/home.keyx
  ```

The installer:
- creates `~/.keepassai/` with `venv/`, `backups/` and `config.json`;
- installs the KeePass library into the venv;
- opens the vault once as a self-test. You should see something like:

```
==> self-test: opening the vault through the gate
    (0 entries, Recycle Bin excluded)
```

Options:
- `--home DIR` uses another working folder. Then also set `KEEPASSAI_HOME=DIR` permanently in
  your environment so the wrappers find it.
- `--force` replaces an existing `config.json`.
- `--skip-test` skips the self-test.

Running the installer again is safe.

If you downloaded a ZIP on Windows instead of cloning, unblock the files first:
`Get-ChildItem "$HOME\tools\KEEPASS-AI" -Recurse | Unblock-File`.

## Step 5. Review config.json

Open `~/.keepassai/config.json`:

```json
{
  "db": "C:\\Users\\you\\Vault\\home.kdbx",
  "key": "C:\\Users\\you\\.keys\\home.keyx",
  "deny": [],
  "pipe_allow": ["ssh"],
  "keep_backups": 50,
  "pipe_timeout": 300,
  "mask_hosts": true,
  "allow_open_app": true
}
```

`pipe_allow` lists the only programs the gate's `pipe` command may run. Add the ones you need
(`curl`, `docker`, `psql`, ...). Never add a shell or an interpreter (`bash`, `python`,
`powershell`): with those, the assistant could print the secret in a form the mask does not
catch. Only you edit this file; the guard keeps the assistant out of it.

## Step 6. Try the gate yourself

- Windows: `& "$HOME\tools\KEEPASS-AI\vault.ps1" list`
- macOS/Linux: `~/tools/KEEPASS-AI/vault.sh list`

Add a test entry and check it in KeePassXC:

```bash
vault.sh add "Test/test-entry" --user demo
vault.sh show "Test/test-entry"
vault.sh trash "Test/test-entry"
```

The password is generated and stored, but never printed. If KeePassXC is open, the gate
refuses to write until you lock or close the vault there.

On Windows, if PowerShell refuses to run `.ps1` files, allow local scripts once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## Step 7. Enable the guard

The guard checks every tool call before it runs. How you hook it in depends on your
assistant.

### Claude Code (automatic)

Run the installer once more with `--hook`:

- Windows: `py -3 "$HOME\tools\KEEPASS-AI\install.py" --hook`
- macOS/Linux: `python3 ~/tools/KEEPASS-AI/install.py --hook`

This backs up `~/.claude/settings.json` (or the one in `$CLAUDE_CONFIG_DIR`). It then adds a
`PreToolUse` hook that runs `guard.py` before every tool call. An older KeePassAI hook is
replaced; other hooks are kept. The entry looks like this, with the paths filled in for
your machine:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/home/you/.keepassai/venv/bin/python",
            "args": ["-I", "/home/you/tools/KEEPASS-AI/guard.py"],
            "timeout": 15,
            "onFailure": "block",
            "statusMessage": "KeePassAI guard"
          }
        ]
      }
    ]
  }
}
```

- The guard denies a call itself when it hits an internal error.
- `onFailure: block` also blocks the call if the guard process cannot start or times out.
  This needs a Claude Code version that supports `onFailure`; older versions let the call
  through in that case.
- Claude Code versions without the `args` field: use a single command string instead, for
  example
  `"command": "\"/home/you/.keepassai/venv/bin/python\" -I \"/home/you/tools/KEEPASS-AI/guard.py\""`.

Restart Claude Code, or start a new session, so the hook is loaded.

### Other assistants (manual)

If your assistant can run a command before each tool call (a "pre-tool" or "before shell
execution" hook), point that hook at the guard with the generic output format:

```
<venv python> -I <path>/guard.py --format exit2
```

`<venv python>` is `~/.keepassai/venv/bin/python`, or
`%USERPROFILE%\.keepassai\venv\Scripts\python.exe` on Windows.

- **Input:** the guard reads the tool call as JSON on stdin. It accepts
  `{"tool_name": ..., "tool_input": {...}, "cwd": ...}` (Claude Code, Gemini CLI and
  similar), or a flat event such as `{"command": "...", "cwd": "..."}` or
  `{"file_path": "..."}`.
- **Tool names:** it understands the common ones (`Bash`, `run_shell_command`, `Read`,
  `read_file`, `write_file`, `replace`, `apply_patch`, and so on).
- **Output:** on deny it prints the reason on stderr and exits with code `2`; on allow it
  prints nothing and exits `0`.

Check your tool's hook documentation for where to put the command and whether it expects a
different output. Only the Claude Code setup is tested end to end.

If your assistant has no hooks, turn on its approval step for every shell command. The gate
still never prints secrets, but nothing then stops the assistant from reading the key file
by other means.

## Step 8. Tell the assistant how to use it

Open [AI-INSTRUCTIONS.md](AI-INSTRUCTIONS.md) and replace `<GATE>` with the absolute path of
this folder. Paste it into your assistant's instruction file:

| Assistant | File |
|---|---|
| Claude Code | `~/.claude/CLAUDE.md` (every project) or the project's `CLAUDE.md` |
| Codex CLI and other `AGENTS.md` readers | `~/.codex/AGENTS.md` or the project's `AGENTS.md` |
| Gemini CLI | `~/.gemini/GEMINI.md` or the project's `GEMINI.md` |
| Cursor | a rule file in `.cursor/rules/` |
| GitHub Copilot | `.github/copilot-instructions.md` |

## Step 9. Check that the guard works

Ask the assistant to do each of these. With the guard enabled, all must be **denied** with a
"KeePassAI guard" reason:

1. "Show the contents of my key file." (also try "search my whole home folder for the word
   `KeyFile`")
2. "Read `~/.keepassai/config.json`."
3. "Add a line to your own settings file." (for example `~/.claude/settings.json` or
   `~/.gemini/settings.json`)
4. "Edit `guard.py` in the KeePassAI folder." (also via `cd` into the folder and `sed -i`)
5. "Run `pipe <entry> python -c 'print(input())'`." (the gate itself refuses this one, with
   or without the guard)

These must **work**:
- "Run the vault gate's `list` command."
- "Read `~/.keepassai/gate.log`."
- "Show me the README in the KeePassAI folder."

Denials are logged in `~/.keepassai/guard.log`, and gate calls in `~/.keepassai/gate.log`.

## Updating

1. You, not the assistant (the folder is read-only for it), run `git pull` in the folder,
   or replace its files.
2. Run `install.py` again (with `--hook` if the folder moved and you use Claude Code) to
   update the venv and the hook path. For other assistants, update the path in their hook
   yourself.
3. Start a new assistant session.

Your `config.json` is kept. New settings (`pipe_allow`, `keep_backups`, `pipe_timeout`) are
optional and have defaults.

## Uninstalling

1. Remove the KeePassAI hook from your assistant's settings. For Claude Code that is the
   entry in `hooks.PreToolUse` in `~/.claude/settings.json`; you can also restore the
   `settings.json.bak-*` file the installer made.
2. Delete `~/.keepassai/`. This removes the venv, the logs and the vault backups; keep the
   backups if you want them.
3. Delete this folder. Your vault and your key file are not touched.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `config file not found` | Run `install.py --db ... --key ...` |
| `cannot open vault: CredentialsError` | Wrong key file, or the vault also has a master password |
| `the KeePass library is not installed` | Run `install.py` again; on Debian/Ubuntu install `python3-venv` first |
| `Python not found: .../venv/...` | The venv is missing or broken (for example after a Homebrew Python upgrade). Delete `~/.keepassai/venv` and run `install.py` again |
| `a KeePass app is running` | Save and lock the vault in the app, then retry |
| `the vault changed on disk since it was opened` | Something else saved the vault meanwhile; retry |
| `program ... is not in 'pipe_allow'` | Add it to `pipe_allow` in `config.json` yourself, if it cannot print secrets |
| Every tool call is denied with "guard internal error" or "config problem" | Fix `config.json` (it must be valid JSON), or run the guard by hand: `echo '{}' \| ~/.keepassai/venv/bin/python -I guard.py` |
| A harmless command is denied | It names a protected path, a KeePass tool, or a folder that contains the key file. Use a narrower path, or run it yourself |
| Secret arrives with a stray `\r` on Linux | The receiving script should strip it: `PW="${PW%$'\r'}"` |
| Non-English titles look garbled in Windows PowerShell 5.1 | Use PowerShell 7 (`winget install Microsoft.PowerShell`); the wrapper already sets UTF-8 output |

Gate exit codes: `0` ok, `2` bad arguments, `3` gate error. `pipe` passes through the
program's own exit code, or returns `124` after the timeout.
