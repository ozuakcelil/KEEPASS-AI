# Changelog

## 0.2.0 - 2026-11-08

Security review before the first public release.

### Guard
- Decisions are made on resolved paths instead of raw text. It now handles `~` and home
  variables, Git Bash `/c/` paths, wildcards, `cd` followed by relative paths, quotes,
  PowerShell backticks, symlinks, junctions, 8.3 names and Unicode normalization.
- Fails closed: an internal error, a broken config or bad input JSON denies the call.
  Config values of the wrong type fall back to defaults.
- Fewer false positives. Tool inputs such as agent prompts and documentation edits are no
  longer matched as raw text. The gate folder can be read, but not written. `gate.log` and
  `guard.log` are readable in the shell too.
- New protections:
  - recursive search or copy of a folder that contains the key file;
  - writes to project-level `.claude/settings*.json`, shell profiles, Python start-up files
    and the standard library;
  - scripts that import KeePass libraries;
  - `KEEPASSAI_*` environment overrides;
  - every tool that takes a `command` (not only Bash and PowerShell).
- More path tricks are resolved:
  - bash brace expansion and backslash escapes, and PowerShell `-Param:value`;
  - `\\?\` device paths;
  - hard links to the key or vault file, compared by file identity.
- `gate.log` and `guard.log` can be read but not written or deleted.
- `eval`/`iex` are matched only as commands, and `-ec`/`-enc` only for PowerShell.
  `grep` reading from a pipe is no longer treated as a recursive search.
- `.pth` files are protected only inside `site-packages`.
- A command that calls the gate may only be followed by read-only filters (`| head`).
- `guard.log` rotates at 1 MB. New `--home` option.

### Gate
- `pipe`:
  - also masks the fields it sends, even unprotected ones, plus reversed, base64, base32,
    hex, URL-encoded and JSON-escaped forms of every secret;
  - refuses interpreters, shells and text tools by default (`pipe_allow` in the config);
  - runs programs by name only. A name must resolve outside the home folder and the current
    folder, unless the user lists its absolute path in `pipe_allow`;
  - refuses secrets shorter than 8 characters and dangerous `--env` names;
  - has a timeout, gives no stdin with `--no-stdin`, finds `.cmd` programs on Windows and
    accepts `--`.
- Writes:
  - run under a lock file and save atomically;
  - check that the vault did not change on disk since it was opened;
  - take a backup before and after the change, with retention (`keep_backups`);
  - are refused while a KeePass app is running unless `--force-gui` is given;
  - no longer take a backup when validation fails.
- Entries can be named `Group/Title`, and `add "Group/Title"` creates the entry in that group.
- `list` and `show` hide credentials and query values in URLs.
- New `--charset full|urlsafe|alnum` option; length is limited to 12-256.
- Exit code `3` for gate errors. No tracebacks.
- Fixed: the Recycle Bin group itself was not recognized as trash.

### Installer and wrappers
- Settings files with a BOM or invalid content no longer crash the installer. Only the
  KeePassAI hook is replaced, and the settings are written atomically. `CLAUDE_CONFIG_DIR`
  is respected. `--home` is passed to the hook.
- A failed venv creation is cleaned up and a hint is shown.
- `vault.ps1` sets UTF-8 output. `vault.sh` is safe with `CDPATH`.

### Other assistants
- The gate and the rules work with any assistant that runs shell commands. The docs now
  cover Codex CLI, Gemini CLI, Cursor and Copilot as well as Claude Code.
- The guard understands other tool shapes: Gemini-style names and fields (`run_shell_command`,
  `read_file`, `absolute_path`, ...), Codex `apply_patch` patches, list-valued paths and flat
  `{"command": ...}` events.
- `guard.py --format exit2`: prints the reason on stderr and exits with code 2, the common
  hook convention.
- The settings and hook files of Gemini CLI, Codex CLI and Cursor are protected too.

### Project
- Python 3.10 or newer is required (3.9 is out of support).
- On macOS and Linux, a backslash in a PowerShell command is treated as a path separator.
- Added a pytest suite, GitHub Actions CI (Windows, macOS, Linux), MIT license, SECURITY.md
  and `.gitattributes`.

## 0.1.0 - 2026-11-08

First version.
