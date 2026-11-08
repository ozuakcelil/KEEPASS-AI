# Vault rules for the AI assistant

Paste this section into your assistant's instruction file and replace `<GATE>` with the
absolute path of this folder. That file is `CLAUDE.md` for Claude Code, `AGENTS.md` for Codex
CLI and others, `GEMINI.md` for Gemini CLI, `.cursor/rules/` for Cursor, and
`.github/copilot-instructions.md` for Copilot.

The guard hook mentioned below is installed automatically for Claude Code; other tools need
it set up by hand (INSTALL.md, step 7). Without it these rules are not enforced, so turn on
your tool's approval step for shell commands.

---

## Secrets: use the KeePassAI gate only

- All secrets (service passwords, tokens, container environment values) live in a KeePass
  vault. The **only** way to reach it is the gate:
  - Windows: `& "<GATE>\vault.ps1" <command>`
  - macOS/Linux: `"<GATE>/vault.sh" <command>`
- Never print a secret value. Never read the vault file, the key file, or anything under
  `~/.keepassai/` except `gate.log` and `guard.log`. Never call KeePass tools or libraries
  directly. A guard hook enforces this. If it denies a call, do not try to get around it: use
  the gate or ask the user.
- Never edit the gate folder, `~/.keepassai/`, your own settings or hook files, or shell profiles.
  Those belong to the user.
- To create a secret:
  - a password: `add "<Group>/<title>" --user U --url URL`;
  - an extra secret attribute: `gen-attr <title> <NAME>`.

  Add `--charset urlsafe` when the value goes into a URL or a `.env` file. Non-secret values
  go in with `set-attr`. Never put a secret in `set-attr`, `--notes` or any other command-line
  argument.
- To use a secret: `pipe <title> <program> [args...]` sends the password to the program's
  stdin.
  - `--field NAME` sends an attribute instead.
  - `--env VAR=NAME` puts it in an environment variable.
  - `--no-stdin` sends nothing on stdin.

  The receiving script reads stdin and strips a trailing `\r`. Only programs listed in
  `pipe_allow` are allowed (usually `ssh`). Ask the user to extend the list; never try to echo
  or transform a secret.
- Writes take a backup automatically. `trash` moves an entry to the Recycle Bin; there is no
  hard delete, and you must never empty the Recycle Bin.
- If the gate says a KeePass app is running, ask the user to save and lock the vault. Do not
  use `--force-gui` unless the user says so.
- Run `<wrapper> <command> --help` for options. Call the gate with an absolute path and do not
  chain other commands after it, except read-only filters such as `| head` or
  `| Select-String`.
