# metasploitable — Assessment Summary

*Target `target-m` · model `llama3:8b` · 2026-09-07 14:26 · 3 scans.*

## Executive Summary

The authorized lab assessment of target-m reveals several vulnerabilities and weaknesses that pose a moderate to high risk to the system's security. The most severe finding is an unauthenticated root shell accessible via TCP port 1524, which allows unauthorized access with elevated privileges. Additionally, the Samba username map script RCE vulnerability (CVE-2007-2447) can be exploited for remote code execution. To mitigate these risks, it is recommended to restrict access to port 1524 and update or remove the vulnerable map users script.

## Severity-Ranked Findings

| Severity | Finding | Port/Service | Impact |
| --- | --- | --- | --- |
| Critical | Unauthenticated Root Shell (TCP 1524) | TCP 1524 | Unauthorized access with elevated privileges |
| High | Samba RCE via username map script (CVE-2007-2447) | N/A | Remote code execution |
| Medium | Anonymous FTP Login Allowed (FTP) | 21/tcp | Unauthorized access to sensitive files or data |
| Medium | SSLv2 Supported (SMTP) | 25/tcp | Interception of sensitive information or injection of malicious data |

## Top Remediation Priorities

1. Restrict access to port 1524 by configuring the firewall rules or disabling the service that listens on this port.
2. Update or remove the vulnerable map users script in Samba.
3. Disable anonymous FTP login and upgrade vsftpd to a version that no longer supports SSLv2.
4. Investigate and potentially disable or block access to the unrecognized services (Exec? and Ingreslock?).
