# codesentry

A local, free, open-source SAST + code review toolkit for reviewing code you,
your team, or AI assistants generate — before it merges. Runs entirely on
your machine; nothing is sent to a third-party service.

Covers: Angular / TypeScript, .NET Core (API + MVC), Syncfusion usage
patterns, Python services, and MS SQL / Entity Framework Core query patterns.

## What's inside

| Tool | Layer | Language coverage |
|---|---|---|
| [Semgrep](https://semgrep.dev) + `configs/semgrep-rules.yml` | SAST | C#, TypeScript, JavaScript, Python |
| [Security Code Scan](https://security-code-scan.github.io) | SAST | .NET (add per-project, see below) |
| ESLint + `configs/.eslintrc.json` | SAST | Angular, TypeScript |
| [Bandit](https://bandit.readthedocs.io) + `configs/bandit.yaml` | SAST | Python |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets scan | All files |
| `npm audit` | SCA (dependencies) | npm packages |
| `dotnet list package --vulnerable` | SCA (dependencies) | NuGet packages |

## One-time setup (per laptop)

**macOS:**
```bash
git clone <your-repo-url> codesentry
cd codesentry
bash install-mac.sh
```

**Windows:**
```powershell
git clone <your-repo-url> codesentry
cd codesentry
.\install-windows.ps1
```
Windows note: `scan.sh` is a bash script. Run it from **Git Bash**
(installed automatically with Git for Windows), not PowerShell/cmd.

## Running a scan (any project, any time after setup)

You never need to add anything to the target project's repo. Point the
scanner at any project folder from anywhere:

```bash
bash /path/to/codesentry/scan.sh /path/to/some-project
```

Or from inside the target project:
```bash
bash /path/to/codesentry/scan.sh .
```

Reports are written to `codesentry/reports/<project-name>-<timestamp>/`,
never into the target project.

### Make it a one-word command

Add to `~/.zshrc` (Mac) or `~/.bashrc` (Windows Git Bash):
```bash
alias codescan="bash /path/to/codesentry/scan.sh"
```
Then from any project folder, anywhere:
```bash
codescan .
```

## Adding Security Code Scan to a .NET project (one-time, per .NET project)

Security Code Scan runs as a build-time Roslyn analyzer, so it needs to be
added inside the target .NET project itself (this is the one exception to
"never touch the target repo" — it's a NuGet dev-dependency, not a source
file, and doesn't affect what ships):
```bash
cd your-dotnet-project
dotnet add package SecurityCodeScan.VS2019
dotnet build
```
Warnings show up in the normal build output.

## What each report file means

- `gitleaks.json` — hardcoded secrets, API keys, connection strings found in files/history.
- `semgrep.txt` — cross-language SAST findings, including the custom EF Core / Syncfusion rules in `configs/semgrep-rules.yml`.
- `eslint.txt` — Angular/TypeScript issues, including unsafe `bypassSecurityTrust*` and `innerHTML` usage.
- `bandit.txt` — Python security issues (weak crypto, insecure deserialization, SQL string building, etc.).
- `npm-audit.txt` — known CVEs in npm dependencies.
- `dotnet-vulnerable.txt` — known CVEs in NuGet dependencies.

## Roadmap (not in this repo yet)

- SonarQube CE via Docker, for a persistent dashboard (Mac only — needs ~3-5GB).
- OWASP ZAP for DAST against a running staging instance.
- OWASP Dependency-Check as a deeper SCA alternative to `npm audit`/`dotnet list`.

## Tuning for less noise

Edit the files in `configs/` directly:
- `configs/bandit.yaml` → `skips:` list, `exclude_dirs:`
- `configs/.eslintrc.json` → `rules:` section, set any rule to `"off"`
- `configs/semgrep-rules.yml` → remove or edit individual rule blocks

Commit changes to this repo so the whole team's scans stay in sync.
