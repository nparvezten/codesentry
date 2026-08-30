#!/usr/bin/env python3
"""
codesentry report generator (v2 - baseline aware)
Reads JSON tool output where available for reliable fingerprinting, filters
out findings already accepted in <target>/.codesentry-baseline.json (copied
into the report dir as baseline.json by scan.sh), and renders one
self-contained report.html.

Usage: python3 generate_report.py <report_dir> <project_name>
"""
import sys
import os
import re
import json
import html
from datetime import datetime

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(text):
    return ANSI_RE.sub('', text)

def read_file(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r', errors='ignore') as f:
        return strip_ansi(f.read())

def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read().strip()
        if not content:
            return None
        return json.loads(content)
    except Exception:
        return None

def esc(s):
    return html.escape(str(s)) if s is not None else ""

def load_baseline(report_dir):
    data = load_json(os.path.join(report_dir, "baseline.json"))
    if not data:
        return set()
    return set(data.get("accepted", []))

def sev_badge(sev):
    sev = (sev or "").upper()
    if sev in ("HIGH", "ERROR", "CRITICAL"):
        return "badge-high"
    if sev in ("MEDIUM", "WARNING"):
        return "badge-med"
    return "badge-low"

def suppressed_note(n):
    if n <= 0:
        return ""
    return f"<p class='muted'>{n} finding(s) suppressed (already accepted in project baseline)</p>"

def build_gitleaks_section(report_dir, baseline):
    data = load_json(os.path.join(report_dir, "gitleaks.json"))
    if data is None:
        return 0, "<p class='ok'>No secrets found.</p>"

    shown, suppressed = [], 0
    for f in data:
        fp = f"gitleaks:{f.get('Fingerprint','')}"
        if fp in baseline:
            suppressed += 1
            continue
        shown.append(f)

    if not shown:
        return 0, "<p class='ok'>No secrets found.</p>" + suppressed_note(suppressed)

    rows = []
    for f in shown:
        secret = f.get("Secret", "")
        masked = secret[:6] + "..." + secret[-4:] if len(secret) > 12 else "***"
        rows.append(f"""
        <tr>
          <td><span class="badge badge-high">SECRET</span></td>
          <td>{esc(f.get('RuleID',''))}</td>
          <td><code>{esc(f.get('File',''))}</code>:{f.get('StartLine','?')}</td>
          <td><code>{esc(masked)}</code></td>
          <td>{esc(f.get('Author',''))}</td>
        </tr>""")
    table = f"""
    <table>
      <thead><tr><th>Type</th><th>Rule</th><th>Location</th><th>Value (masked)</th><th>Author</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    <p class="warn">Secrets found in git history remain there even after deleting the file.
    Revoke/rotate the credential first, then consider history-scrubbing tools if needed.</p>
    """ + suppressed_note(suppressed)
    return len(shown), table

def build_bandit_section(report_dir, baseline):
    data = load_json(os.path.join(report_dir, "bandit.json"))
    if data is None:
        text = read_file(os.path.join(report_dir, "bandit.txt"))
        if text is None:
            return 0, "<p class='muted'>No bandit output found.</p>"
        return 0, f"<p class='muted'>bandit.json not available; showing raw output.</p><pre>{esc(text)}</pre>"

    shown, suppressed = [], 0
    for r in data.get("results", []):
        fp = f"bandit:{r.get('test_id')}:{r.get('filename')}:{r.get('line_number')}"
        if fp in baseline:
            suppressed += 1
            continue
        shown.append(r)

    if not shown:
        return 0, "<p class='ok'>No issues found.</p>" + suppressed_note(suppressed)

    rows = []
    for r in shown:
        rows.append(f"""
        <tr>
          <td><span class="badge {sev_badge(r.get('issue_severity'))}">{esc(r.get('issue_severity'))}</span></td>
          <td>{esc(r.get('test_id'))} {esc(r.get('test_name'))}</td>
          <td><code>{esc(r.get('filename'))}</code>:{r.get('line_number')}</td>
          <td>{esc(r.get('issue_text'))}</td>
        </tr>""")
    table = f"""<table><thead><tr><th>Severity</th><th>Check</th><th>Location</th><th>Detail</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>""" + suppressed_note(suppressed)
    return len(shown), table

def build_semgrep_section(report_dir, baseline):
    data = load_json(os.path.join(report_dir, "semgrep.json"))
    if data is None:
        text = read_file(os.path.join(report_dir, "semgrep.txt"))
        if text is None:
            return 0, "<p class='muted'>No semgrep output found.</p>"
        return 0, f"<p class='muted'>semgrep.json not available; showing raw output.</p><pre>{esc(text)}</pre>"

    shown, suppressed = [], 0
    for r in data.get("results", []):
        line = r.get("start", {}).get("line")
        fp = f"semgrep:{r.get('check_id')}:{r.get('path')}:{line}"
        if fp in baseline:
            suppressed += 1
            continue
        shown.append(r)

    if not shown:
        return 0, "<p class='ok'>No findings.</p>" + suppressed_note(suppressed)

    rows = []
    for r in shown:
        sev = r.get("extra", {}).get("severity", "")
        msg = r.get("extra", {}).get("message", "")
        line = r.get("start", {}).get("line")
        rows.append(f"""
        <tr>
          <td><span class="badge {sev_badge(sev)}">{esc(sev)}</span></td>
          <td>{esc(r.get('check_id'))}</td>
          <td><code>{esc(r.get('path'))}</code>:{line}</td>
          <td>{esc(msg)}</td>
        </tr>""")
    table = f"""<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>""" + suppressed_note(suppressed)
    return len(shown), table

def build_eslint_section(report_dir, baseline):
    raw_text = read_file(os.path.join(report_dir, "eslint.txt"))
    if raw_text and ("Oops! Something went wrong" in raw_text or "TypeError" in raw_text):
        return -1, f"<p class='warn'>ESLint crashed during this scan (tooling issue, not a code finding). Fix the toolkit setup and re-scan.</p><pre>{esc(raw_text[:2000])}</pre>"

    data = load_json(os.path.join(report_dir, "eslint.json"))
    if data is None:
        if raw_text is None:
            return 0, "<p class='muted'>No eslint output found.</p>"
        return 0, f"<p class='muted'>eslint.json not available; showing raw output.</p><pre>{esc(raw_text)}</pre>"

    shown, suppressed = [], 0
    for file_result in data:
        for m in file_result.get("messages", []):
            fp = f"eslint:{m.get('ruleId')}:{file_result.get('filePath')}:{m.get('line')}"
            if fp in baseline:
                suppressed += 1
                continue
            shown.append((file_result.get("filePath"), m))

    if not shown:
        return 0, "<p class='ok'>No issues found.</p>" + suppressed_note(suppressed)

    rows = []
    for filepath, m in shown:
        sev = "ERROR" if m.get("severity") == 2 else "WARNING"
        rows.append(f"""
        <tr>
          <td><span class="badge {sev_badge(sev)}">{sev}</span></td>
          <td>{esc(m.get('ruleId'))}</td>
          <td><code>{esc(filepath)}</code>:{m.get('line')}</td>
          <td>{esc(m.get('message'))}</td>
        </tr>""")
    table = f"""<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>""" + suppressed_note(suppressed)
    return len(shown), table

def build_npm_audit_section(report_dir):
    text = read_file(os.path.join(report_dir, "npm-audit.txt"))
    if text is None:
        return 0, "<p class='muted'>No npm-audit.txt found (no package.json in target).</p>"
    if "found 0 vulnerabilities" in text:
        return 0, "<p class='ok'>No known vulnerabilities.</p>"
    return 1, f"<pre>{esc(text)}</pre>"

def build_dotnet_section(report_dir):
    text = read_file(os.path.join(report_dir, "dotnet-vulnerable.txt"))
    if text is None:
        return 0, "<p class='muted'>No dotnet-vulnerable.txt found (no .NET project in target).</p>"
    vuln_count = len(re.findall(r'^\s*>\s+\S+', text, re.MULTILINE))
    if vuln_count == 0:
        return 0, "<p class='ok'>No vulnerable NuGet packages found.</p>"
    summary = f"<p><span class='badge badge-high'>{vuln_count} vulnerable package(s)</span></p>"
    return vuln_count, summary + f"<pre>{esc(text)}</pre>"

def main():
    if len(sys.argv) < 3:
        print("Usage: generate_report.py <report_dir> <project_name>")
        sys.exit(1)

    report_dir = sys.argv[1]
    project_name = sys.argv[2]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    baseline = load_baseline(report_dir)

    secrets_count, secrets_html = build_gitleaks_section(report_dir, baseline)
    bandit_count, bandit_html = build_bandit_section(report_dir, baseline)
    semgrep_count, semgrep_html = build_semgrep_section(report_dir, baseline)
    eslint_count, eslint_html = build_eslint_section(report_dir, baseline)
    npm_count, npm_html = build_npm_audit_section(report_dir)
    dotnet_count, dotnet_html = build_dotnet_section(report_dir)

    total_findings = sum(c for c in [secrets_count, bandit_count, semgrep_count,
                                      max(eslint_count, 0), npm_count, dotnet_count])

    baseline_note = f"<p class='muted' style='margin-top:-8px'>Baseline active: {len(baseline)} previously accepted finding(s) suppressed from this report.</p>" if baseline else ""

    sections = [
        ("Secrets (gitleaks)", secrets_count, secrets_html),
        ("Python (bandit)", bandit_count, bandit_html),
        ("Cross-language SAST (semgrep)", semgrep_count, semgrep_html),
        ("Angular / TypeScript (eslint)", eslint_count, eslint_html),
        ("npm dependencies", npm_count, npm_html),
        ("NuGet dependencies", dotnet_count, dotnet_html),
    ]

    nav_items = "".join(
        f'<li><a href="#{i}">{esc(title)} <span class="count">{c if c >= 0 else "!"}</span></a></li>'
        for i, (title, c, _) in enumerate(sections)
    )

    body_sections = "".join(f"""
    <section id="{i}">
      <h2>{esc(title)}</h2>
      {body}
    </section>
    """ for i, (title, c, body) in enumerate(sections))

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>codesentry report - {esc(project_name)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#f6f7f9; color:#1a1a1a; margin:0; }}
  header {{ background:#1e2433; color:white; padding:24px 32px; }}
  header h1 {{ margin:0; font-size:22px; }}
  header p {{ margin:6px 0 0; color:#a9b1c3; font-size:14px; }}
  .layout {{ display:flex; }}
  nav {{ width:280px; background:white; border-right:1px solid #e2e5ea; min-height:100vh; padding:16px; box-sizing:border-box; }}
  nav ul {{ list-style:none; padding:0; margin:0; }}
  nav li a {{ display:flex; justify-content:space-between; padding:10px 12px; border-radius:6px; text-decoration:none; color:#1a1a1a; font-size:14px; margin-bottom:4px; }}
  nav li a:hover {{ background:#f0f2f5; }}
  .count {{ background:#e2e5ea; border-radius:10px; padding:1px 8px; font-size:12px; color:#444; }}
  main {{ flex:1; padding:32px; max-width:1100px; }}
  section {{ background:white; border:1px solid #e2e5ea; border-radius:8px; padding:20px 24px; margin-bottom:24px; }}
  section h2 {{ margin-top:0; font-size:18px; }}
  pre {{ background:#0f1117; color:#d6deeb; padding:16px; border-radius:6px; overflow-x:auto; font-size:12.5px; line-height:1.5; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #eee; vertical-align:top; }}
  th {{ color:#666; font-weight:600; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; margin-right:4px; white-space:nowrap; }}
  .badge-high {{ background:#fde2e1; color:#c0292c; }}
  .badge-med  {{ background:#fef3d6; color:#9a6b00; }}
  .badge-low  {{ background:#e4f0ff; color:#1a5fb4; }}
  .ok {{ color:#1a7f37; font-weight:600; }}
  .warn {{ color:#9a6b00; background:#fef8e8; padding:10px 12px; border-radius:6px; }}
  .muted {{ color:#888; font-size:13px; }}
  .summary-cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }}
  .card {{ background:white; border:1px solid #e2e5ea; border-radius:8px; padding:16px 20px; min-width:150px; }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .label {{ font-size:12px; color:#666; margin-top:4px; }}
</style>
</head>
<body>
<header>
  <h1>codesentry scan report</h1>
  <p>Project: {esc(project_name)} &nbsp;&middot;&nbsp; Generated: {esc(timestamp)}</p>
</header>
<div class="layout">
  <nav>
    <ul>{nav_items}</ul>
  </nav>
  <main>
    <div class="summary-cards">
      <div class="card"><div class="num">{total_findings}</div><div class="label">Total findings</div></div>
      <div class="card"><div class="num">{secrets_count}</div><div class="label">Secrets</div></div>
      <div class="card"><div class="num">{bandit_count + semgrep_count}</div><div class="label">SAST issues</div></div>
      <div class="card"><div class="num">{npm_count + dotnet_count}</div><div class="label">Vulnerable deps</div></div>
    </div>
    {baseline_note}
    {body_sections}
  </main>
</div>
</body>
</html>"""

    out_path = os.path.join(report_dir, "report.html")
    with open(out_path, 'w') as f:
        f.write(html_out)
    print(f"Report written to: {out_path}")

if __name__ == "__main__":
    main()
