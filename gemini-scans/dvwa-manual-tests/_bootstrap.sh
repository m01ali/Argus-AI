#!/usr/bin/env bash
# DVWA headless bootstrap: initialise the DB, log in as admin/password,
# set the security level to low, and capture an authenticated session cookie.
# Prints a SUCCESS line plus the exact --cookie string sqlmap needs.
set -euo pipefail
TARGET="http://target-w"
CJ="/tmp/dvwa.cookies"
rm -f "$CJ"

# DVWA puts an anti-CSRF user_token in a hidden field on every form.
tok() { grep -oP -m1 "name='user_token' value='\K[0-9a-f]+"; }

# 1) fresh anonymous session + the setup-page token
T=$(curl -s -c "$CJ" "$TARGET/setup.php" | tok)
# 2) create / reset the database
curl -s -b "$CJ" -c "$CJ" \
     --data-urlencode "create_db=Create / Reset Database" \
     --data "user_token=$T" "$TARGET/setup.php" -o /dev/null
# 3) log in as admin/password
LT=$(curl -s -b "$CJ" -c "$CJ" "$TARGET/login.php" | tok)
curl -s -b "$CJ" -c "$CJ" \
     --data "username=admin&password=password&Login=Login&user_token=$LT" \
     "$TARGET/login.php" -o /dev/null
# 4) set the security level to low
ST=$(curl -s -b "$CJ" -c "$CJ" "$TARGET/security.php" | tok)
curl -s -b "$CJ" -c "$CJ" \
     --data "security=low&seclev_submit=Submit&user_token=$ST" \
     "$TARGET/security.php" -o /dev/null

# 5) verify we can reach the SQLi page while authenticated
BODY=$(curl -s -b "$CJ" "$TARGET/vulnerabilities/sqli/")
PHPSESSID=$(grep -i PHPSESSID "$CJ" | awk '{print $7}')
if echo "$BODY" | grep -qi "User ID"; then
  echo "SUCCESS: DB initialised, logged in as admin, security=low."
  echo "SQLMAP_COOKIE=PHPSESSID=$PHPSESSID; security=low"
  cp "$CJ" /opt/argus-ai/gemini-scans/dvwa/.dvwa-cookies
  printf 'PHPSESSID=%s; security=low\n' "$PHPSESSID" \
     > /opt/argus-ai/gemini-scans/dvwa/.dvwa-sqlmap-cookie
else
  echo "FAIL: could not reach the SQLi page authenticated. First 20 lines:"
  echo "$BODY" | head -20
fi
