# metasploitable — TCP 1524 ingreslock — unauthenticated root shell

*Target `target-m` · analysed by `llama3:8b` via local Ollama.*

## Open Ports / Services

No open ports or services are reported in this scan output.

## Vulnerabilities & Weaknesses

### Finding 1: Unauthenticated Root Shell

**Severity**: Critical
**CVE**: None (not applicable)
**What it is**: The system has an unauthenticated root shell accessible via TCP port 1524.
**Why it matters**: This allows an attacker to gain unauthorized access to the system with elevated privileges, potentially leading to data theft, modification, or destruction.

## Remediation

### Fix: Restrict Access to Port 1524

To remediate this issue, restrict access to port 1524 by configuring the firewall rules or disabling the service that listens on this port. This can be achieved by running the following command:
```bash
ufw deny 1524
```
Alternatively, you can disable the ingreslock service if it is not required:
```bash
service ingreslock stop
service ingreslock disable
```
Note: The exact remediation steps may vary depending on the specific system and configuration.
