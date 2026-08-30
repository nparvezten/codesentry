#!/bin/bash
# codesentry - local SAST + code review scanner
# Usage: ./scan.sh /path/to/target-project
#        ./scan.sh .                (scans current directory)

set -e

TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "Error: '$TARGET_DIR' is not a directory."
  exit 1
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
PROJECT_NAME="$(basename "$TARGET_DIR")"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="$TOOLKIT_DIR/reports/${PROJECT_NAME}-${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

echo "=========================================="
echo " codesentry scan"
echo " Target : $TARGET_DIR"
echo " Reports: $REPORT_DIR"
echo "=========================================="

# --- Secrets scan ---
echo ""
echo "== [1/6] Secrets scan (gitleaks) =="
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$TARGET_DIR" -v --report-path "$REPORT_DIR/gitleaks.json" || true
else
  echo "gitleaks not installed, skipping."
fi

# --- Semgrep: cross-language SAST + custom EF Core / Syncfusion rules ---
echo ""
echo "== [2/6] Semgrep (cross-language SAST) =="
if command -v semgrep >/dev/null 2>&1; then
  semgrep --config "$TOOLKIT_DIR/configs/semgrep-rules.yml" \
          --config auto \
          "$TARGET_DIR" \
          --output "$REPORT_DIR/semgrep.txt" || true
  semgrep --config "$TOOLKIT_DIR/configs/semgrep-rules.yml" \
          --config auto \
          "$TARGET_DIR" \
          --json --output "$REPORT_DIR/semgrep.json" || true
  echo "  -> saved to $REPORT_DIR/semgrep.txt"
else
  echo "semgrep not installed, skipping."
fi

# --- ESLint: Angular / TypeScript ---
echo ""
echo "== [3/6] ESLint (Angular/TypeScript) =="
ESLINT_BIN="$TOOLKIT_DIR/node_modules/.bin/eslint"
if [ -f "$ESLINT_BIN" ]; then
  "$ESLINT_BIN" --config "$TOOLKIT_DIR/configs/.eslintrc.json" \
      --resolve-plugins-relative-to "$TOOLKIT_DIR" \
      --ext .ts,.html \
      --no-error-on-unmatched-pattern \
      "$TARGET_DIR" > "$REPORT_DIR/eslint.txt" 2>&1 || true
  "$ESLINT_BIN" --config "$TOOLKIT_DIR/configs/.eslintrc.json" \
      --resolve-plugins-relative-to "$TOOLKIT_DIR" \
      --ext .ts,.html \
      --no-error-on-unmatched-pattern \
      --format json \
      "$TARGET_DIR" > "$REPORT_DIR/eslint.json" 2>/dev/null || true
  echo "  -> saved to $REPORT_DIR/eslint.txt"
else
  echo "ESLint not set up in toolkit yet. Run: cd $TOOLKIT_DIR && npm install"
fi

# --- Bandit: Python ---
echo ""
echo "== [4/6] Bandit (Python) =="
if command -v bandit >/dev/null 2>&1; then
  bandit -r "$TARGET_DIR" -c "$TOOLKIT_DIR/configs/bandit.yaml" -f txt -o "$REPORT_DIR/bandit.txt" || true
  bandit -r "$TARGET_DIR" -c "$TOOLKIT_DIR/configs/bandit.yaml" -f json -o "$REPORT_DIR/bandit.json" || true
  echo "  -> saved to $REPORT_DIR/bandit.txt"
else
  echo "bandit not installed, skipping."
fi

# --- npm audit: JS/TS dependency vulnerabilities ---
echo ""
echo "== [5/6] npm audit (dependency check) =="
if [ -f "$TARGET_DIR/package.json" ]; then
  npm audit --prefix "$TARGET_DIR" > "$REPORT_DIR/npm-audit.txt" 2>&1 || true
  echo "  -> saved to $REPORT_DIR/npm-audit.txt"
else
  echo "No package.json found in target, skipping."
fi

# --- dotnet vulnerable packages ---
echo ""
echo "== [6/6] dotnet vulnerable packages check =="
if command -v dotnet >/dev/null 2>&1; then
  ( cd "$TARGET_DIR" && dotnet list package --vulnerable --include-transitive > "$REPORT_DIR/dotnet-vulnerable.txt" 2>&1 ) || true
  echo "  -> saved to $REPORT_DIR/dotnet-vulnerable.txt"
else
  echo "dotnet not installed, skipping."
fi

# --- Pick up baseline (accepted findings) from target project, if present ---
if [ -f "$TARGET_DIR/.codesentry-baseline.json" ]; then
  cp "$TARGET_DIR/.codesentry-baseline.json" "$REPORT_DIR/baseline.json"
  echo ""
  echo "Baseline found in target project — accepted findings will be suppressed in the report."
fi

# --- Build HTML report for developer handoff ---
echo ""
echo "== Generating HTML report =="
if command -v python3 >/dev/null 2>&1; then
  python3 "$TOOLKIT_DIR/generate_report.py" "$REPORT_DIR" "$PROJECT_NAME" || true
fi

echo ""
echo "=========================================="
echo " Scan complete."
echo " All reports saved in:"
echo " $REPORT_DIR"
if [ -f "$REPORT_DIR/report.html" ]; then
  echo ""
  echo " Open the report:"
  echo " open \"$REPORT_DIR/report.html\""
fi
if [ ! -f "$TARGET_DIR/.codesentry-baseline.json" ]; then
  echo ""
  echo " First time scanning this project? Accept current findings as baseline so"
  echo " future scans only show NEW issues:"
  echo " python3 \"$TOOLKIT_DIR/accept_baseline.py\" \"$REPORT_DIR\" \"$TARGET_DIR\""
fi
echo "=========================================="
