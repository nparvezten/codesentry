# codesentry - one-time installer for Windows
# Run this once per Windows laptop, in PowerShell: .\install-windows.ps1
# Then use scan.sh via Git Bash (installed automatically with Git for Windows).

Write-Host "Installing prerequisites via winget..."
winget install --id Python.Python.3.12 -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Git.Git -e
winget install --id Microsoft.DotNet.SDK.8 -e
winget install --id semgrep.semgrep -e
winget install --id gitleaks.gitleaks -e

Write-Host "Installing bandit (Python SAST)..."
pip install bandit

Write-Host "Installing ESLint + plugins into the toolkit (not global, not per-project)..."
Set-Location $PSScriptRoot
npm install

Write-Host ""
Write-Host "Done. Open Git Bash (not PowerShell) to run scans, since scan.sh is a bash script:"
Write-Host "  bash ./scan.sh /path/to/any/project"
