# KeePassAI vault gate - Windows wrapper (PowerShell 5.1+ or pwsh). Usage: & "C:\path\to\vault.ps1" <command> ...
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$vaultHome = if ($env:KEEPASSAI_HOME) { $env:KEEPASSAI_HOME } else { Join-Path $HOME '.keepassai' }
$py = if ($env:KEEPASSAI_PYTHON) { $env:KEEPASSAI_PYTHON } else { Join-Path $vaultHome 'venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $py)) { [Console]::Error.WriteLine("ERROR: Python not found: $py (see INSTALL.md)"); exit 3 }
& $py -I (Join-Path $PSScriptRoot 'vault.py') @args
exit $LASTEXITCODE
