import io
import json
import os
import sys

import pytest

import common
import guard

GATE = str(common.GATE_DIR)
WIN = os.name == "nt"


def run(sb, tool, cwd=None, **tin):
    return guard.decide({"tool_name": tool, "tool_input": tin, "cwd": str(cwd or sb["project"])})


def bash(sb, cmd, cwd=None):
    return run(sb, "Bash", cwd=cwd, command=cmd)


# ---- allowed

def test_plain_calls_allowed(sandbox):
    sb = sandbox
    assert run(sb, "Read", file_path=str(sb["project"] / "a.txt")) is None
    assert bash(sb, "ls -la && git status") is None
    assert bash(sb, "grep -e foo notes.txt") is None
    assert run(sb, "Agent", prompt="review the code that opens .kdbx files with pykeepass") is None
    assert run(sb, "Write", file_path=str(sb["project"] / "README.md"), content="uses .kdbx files") is None


def test_logs_are_readable(sandbox):
    sb = sandbox
    assert run(sb, "Read", file_path=str(sb["work"] / "gate.log")) is None
    assert bash(sb, f'cat "{sb["work"] / "guard.log"}"') is None


def test_gate_calls_allowed(sandbox):
    sb = sandbox
    assert bash(sb, f'& "{GATE}/vault.ps1" list') is None
    assert bash(sb, f'"{GATE}/vault.sh" show "Git - x" 2>&1 | head -5') is None
    assert bash(sb, f'& "{GATE}\\vault.ps1" pipe "server" ssh -o BatchMode=yes myserver "bash /tmp/x.sh"') is None
    assert bash(sb, "./vault.sh list", cwd=GATE) is None


def test_gate_folder_is_readable_but_not_writable(sandbox):
    sb = sandbox
    assert bash(sb, f'cat "{GATE}/README.md"') is None
    assert bash(sb, f'git -C "{GATE}" status') is None
    assert run(sb, "Read", file_path=os.path.join(GATE, "guard.py")) is None
    assert run(sb, "Write", file_path=os.path.join(GATE, "guard.py"), content="x")
    assert run(sb, "Edit", file_path=os.path.join(GATE, "README.md"), old_string="a", new_string="b")


# ---- secrets

def test_key_file_is_off_limits(sandbox):
    sb = sandbox
    key = str(sb["key"])
    assert run(sb, "Read", file_path=key)
    assert run(sb, "Read", file_path=key.upper() if WIN else key)
    assert bash(sb, f"cat '{key}'")
    assert bash(sb, "cat ~/.vaultkey/*")
    assert bash(sb, "cat $HOME/.vaultkey/lab.*")
    assert bash(sb, "cd ~ && cat .vaultkey/l?b.keyx")
    assert bash(sb, "Get-Content $env:USERPROFILE\\.vaultkey\\*")


@pytest.mark.skipif(not WIN, reason="Git Bash drive paths exist on Windows only")
def test_git_bash_paths(sandbox):
    sb = sandbox
    key = str(sb["key"]).replace("\\", "/")
    gitbash = "/" + key[0].lower() + key[2:]
    assert bash(sb, f'cat "{gitbash}"')
    gate = "/" + GATE[0].lower() + GATE[2:].replace("\\", "/")
    assert bash(sb, f'cd "{gate}" && sed -i s/a/b/ guard.py')


def test_working_folder_is_off_limits(sandbox):
    sb = sandbox
    assert bash(sb, "cat ~/.keepassai/config.json")
    assert bash(sb, "cd ~/.keepassai && cat config.json")
    assert bash(sb, "cp -r $HOME/.keepassai /tmp/x")
    assert run(sb, "Read", file_path=str(sb["work"] / "config.json"))
    assert run(sb, "Write", file_path=str(sb["work"] / "config.json"), content="{}")


def test_recursive_search_over_the_key(sandbox):
    sb = sandbox
    assert run(sb, "Grep", pattern="x", path=str(sb["home"]))
    assert run(sb, "Grep", pattern="x", path=str(sb["project"])) is None
    assert bash(sb, "grep -r token ~")
    assert bash(sb, "rg token", cwd=sb["home"])
    assert bash(sb, f'rg token "{sb["project"]}"', cwd=sb["home"]) is None
    assert bash(sb, f'tar czf /tmp/h.tgz "{sb["home"]}"')


def test_tricks_after_quotes_and_cd(sandbox):
    sb = sandbox
    assert bash(sb, f'sed -i s/deny/pass/ "{GATE}"/guard.py')
    assert bash(sb, f'cd "{GATE}" && sed -i s/a/b/ guard.py')
    assert bash(sb, f'cd "{GATE}"; echo x > guard.py')
    assert bash(sb, f'bash -c "sed -i s/a/b/ {GATE}/guard.py"'.replace(chr(92), '/'))
    assert bash(sb, f'& "{GATE}/vault.ps1" list; echo x > guard.py', cwd=GATE)
    assert bash(sb, f'Set-Content "{GATE[:-2]}*\\guard.py" x')


def test_links_are_resolved(sandbox, tmp_path):
    sb = sandbox
    link = tmp_path / "link"
    try:
        os.symlink(GATE, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        if not WIN:
            raise
        import subprocess
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), GATE], capture_output=True)
        if r.returncode:
            pytest.skip("cannot create a link here")
    assert run(sb, "Write", file_path=str(link / "guard.py"), content="x")


def test_claude_settings_and_profiles(sandbox):
    sb = sandbox
    claude = sb["home"] / ".claude"
    assert run(sb, "Edit", file_path=str(claude / "settings.json"), old_string="a", new_string="b")
    assert run(sb, "Write", file_path=str(claude / "settings.local.json"), content="{}")
    assert run(sb, "Write", file_path=str(sb["project"] / ".claude" / "settings.json"), content="{}")
    assert run(sb, "Write", file_path=str(claude / "hooks" / "x.py"), content="")
    assert run(sb, "Write", file_path=str(claude / "projects" / "p" / "memory" / "m.md"), content="ok") is None
    assert run(sb, "Write", file_path=str(sb["home"] / ".bashrc"), content="export X=1")
    assert run(sb, "Write", file_path=str(sb["project"] / "sitecustomize.py"), content="")
    assert bash(sb, "echo '{\"disableAllHooks\": true}' > x.json")
    assert bash(sb, "cat ~/.claude/settings.json") is None


def test_tooling_and_obfuscation(sandbox):
    sb = sandbox
    assert bash(sb, "pip show pykeepass")
    assert bash(sb, "keepassxc-cli ls x")
    assert bash(sb, "powershell -enc ZQBjAGgAbwA=")
    assert bash(sb, "echo aGk= | base64 -d | sh")
    assert bash(sb, "$env:KEEPASSAI_PYTHON='C:/evil.exe'")
    assert bash(sb, "iex (gc x.ps1)")
    assert bash(sb, "cat lab.keyx")  # the key file name itself
    assert run(sb, "Write", file_path=str(sb["project"] / "x.py"), content="import pykeepass")
    assert run(sb, "Write", file_path=str(sb["project"] / "x.md"), content="import pykeepass") is None


def test_command_tools_other_than_bash(sandbox):
    sb = sandbox
    assert run(sb, "PowerShell", command="Get-Content ~/.keepassai/config.json")
    assert run(sb, "mcp__terminal__run_in_terminal", command="cat ~/.vaultkey/lab.keyx")


def test_fail_closed(sandbox, monkeypatch, capsys):
    sb = sandbox
    (sb["work"] / "config.json").write_text("{not json", encoding="utf-8")
    assert "config problem" in bash(sb, "ls")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"[1, 2")))
    guard.main([])
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_odd_config_values_do_not_crash(sandbox):
    sb = sandbox
    (sb["work"] / "config.json").write_text(json.dumps({"db": 5, "key": None, "deny": "abc"}), encoding="utf-8")
    assert bash(sb, "ls -la") is None
    assert guard.decide({"tool_name": "Bash", "tool_input": "oops"}) is None


def test_deny_is_logged(sandbox, monkeypatch, capsys):
    sb = sandbox
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(sb["key"])}, "cwd": str(sb["project"])}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    guard.main([])
    assert "deny" in capsys.readouterr().out
    assert "off limits" in (sb["work"] / "guard.log").read_text(encoding="utf-8")



def test_review_bypasses(sandbox):
    sb = sandbox
    key = str(sb["key"])
    assert bash(sb, "cat ~/.keepass{ai,}/config.json")
    assert bash(sb, r"cat ~/.keep\assai/config.json")
    assert run(sb, "PowerShell", command="Get-Content -Path:~/.keepassai/config.json")
    assert run(sb, "Read", file_path=("\\\\?\\" + key) if WIN else key)
    assert run(sb, "Write", file_path=str(sb["work"] / "gate.log"), content="forged")
    assert bash(sb, "rm ~/.keepassai/gate.log")
    assert bash(sb, "cat ~/.keepassai/gate.log") is None


def test_hard_link_to_key(sandbox, tmp_path):
    sb = sandbox
    link = sb["project"] / "innocent.txt"
    try:
        os.link(sb["key"], link)
    except OSError:
        pytest.skip("hard links not supported here")
    assert run(sb, "Read", file_path=str(link))


def test_review_false_positives(sandbox):
    sb = sandbox
    for cmd in ['git commit -m "add eval step"', "python eval.py", "npm run eval", "bash -ec 'npm ci'",
                "npm test", "python -m pytest -q", "docker ps | grep web", "ssh host uptime",
                "Get-ChildItem -Recurse src | Select-String TODO", "echo {a,b}"]:
        assert bash(sb, cmd) is None, cmd
    for cmd in ["ls -la | grep foo", "docker ps | grep web", "Get-Process | Select-String node"]:
        assert bash(sb, cmd, cwd=sb["home"]) is None, cmd
    assert run(sb, "Write", file_path=str(sb["project"] / "weights.pth"), content="x") is None
    assert run(sb, "Write", file_path=str(sb["project"] / "lib" / "site-packages" / "evil.pth"), content="x")
    assert bash(sb, "eval $(echo x)")
    assert bash(sb, "pwsh -ec ZQBjAGgAbwA=")


def test_other_assistants_tool_shapes(sandbox):
    sb = sandbox
    key = str(sb["key"])
    # Gemini CLI style tool names and fields
    assert run(sb, "read_file", absolute_path=key)
    assert run(sb, "run_shell_command", command="cat ~/.keepassai/config.json")
    assert run(sb, "search_file_content", pattern="x", path=str(sb["home"]))
    assert run(sb, "write_file", file_path=str(sb["home"] / ".gemini" / "settings.json"), content="{}")
    assert run(sb, "write_file", file_path=str(sb["project"] / "notes.txt"), content="ok") is None
    # Codex CLI style patch
    patch = f"*** Begin Patch\n*** Update File: {GATE}/guard.py\n@@\n-a\n+b\n*** End Patch"
    assert run(sb, "apply_patch", input=patch)
    ok = f"*** Begin Patch\n*** Add File: {sb['project']}/x.txt\n+hi\n*** End Patch"
    assert run(sb, "apply_patch", input=ok) is None
    # settings and hook files of other assistants
    assert run(sb, "Write", file_path=str(sb["home"] / ".codex" / "config.toml"), content="")
    assert run(sb, "Write", file_path=str(sb["project"] / ".cursor" / "hooks.json"), content="{}")
    assert run(sb, "Write", file_path=str(sb["project"] / ".gemini" / "settings.json"), content="{}")
    # list-valued paths
    assert run(sb, "read_many_files", paths=[str(sb["project"] / "a"), key])


def test_flat_events_and_exit2_format(sandbox, monkeypatch, capsys):
    sb = sandbox
    assert guard.decide({"command": "cat ~/.vaultkey/lab.keyx", "cwd": str(sb["project"])})
    assert guard.decide({"file_path": str(sb["key"])})
    assert guard.decide({"command": "ls", "cwd": str(sb["project"])}) is None
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(sb["key"])}}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    assert guard.main(["--format", "exit2"]) == 2
    out = capsys.readouterr()
    assert out.out == "" and "KeePassAI guard" in out.err
