#!/usr/bin/env python3
"""
codesentry - accept_baseline.py
Snapshots all findings from the most recent scan into the target project's
.codesentry-baseline.json, so future scans only surface NEW findings.

Usage: python3 accept_baseline.py <report_dir> <target_dir>
"""
import sys
import os
import json
from datetime import datetime

def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', errors='ignore') as f:
            return json.load(f)
    except Exception:
        return None

def fingerprints_from_gitleaks(report_dir):
    data = load_json(os.path.join(report_dir, "gitleaks.json"))
    if not data:
        return []
    return [f"gitleaks:{item.get('Fingerprint','')}" for item in data]

def fingerprints_from_bandit(report_dir):
    data = load_json(os.path.join(report_dir, "bandit.json"))
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        out.append(f"bandit:{r.get('test_id')}:{r.get('filename')}:{r.get('line_number')}")
    return out

def fingerprints_from_semgrep(report_dir):
    data = load_json(os.path.join(report_dir, "semgrep.json"))
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        line = r.get("start", {}).get("line")
        out.append(f"semgrep:{r.get('check_id')}:{r.get('path')}:{line}")
    return out

def fingerprints_from_eslint(report_dir):
    data = load_json(os.path.join(report_dir, "eslint.json"))
    if not data:
        return []
    out = []
    for file_result in data:
        for m in file_result.get("messages", []):
            out.append(f"eslint:{m.get('ruleId')}:{file_result.get('filePath')}:{m.get('line')}")
    return out

def main():
    if len(sys.argv) < 3:
        print("Usage: accept_baseline.py <report_dir> <target_dir>")
        sys.exit(1)

    report_dir = sys.argv[1]
    target_dir = sys.argv[2]

    all_fps = set()
    all_fps.update(fingerprints_from_gitleaks(report_dir))
    all_fps.update(fingerprints_from_bandit(report_dir))
    all_fps.update(fingerprints_from_semgrep(report_dir))
    all_fps.update(fingerprints_from_eslint(report_dir))

    baseline_path = os.path.join(target_dir, ".codesentry-baseline.json")

    existing = []
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, 'r') as f:
                existing = json.load(f).get("accepted", [])
        except Exception:
            existing = []

    merged = sorted(set(existing) | all_fps)

    baseline = {
        "generated": datetime.now().isoformat(),
        "note": "Fingerprints of findings reviewed and accepted as known/acceptable risk. codescan will not show these again unless removed from this list.",
        "accepted": merged
    }

    with open(baseline_path, 'w') as f:
        json.dump(baseline, f, indent=2)

    print(f"Baseline written: {baseline_path}")
    print(f"  {len(all_fps)} findings from this scan added/confirmed")
    print(f"  {len(merged)} total findings now in baseline")
    print("Commit this file to the project's own repo so the whole team shares it.")

if __name__ == "__main__":
    main()
