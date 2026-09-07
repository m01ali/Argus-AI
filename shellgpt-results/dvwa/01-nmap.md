# dvwa — Nmap service/version scan

*Target `target-w` · analysed by ShellGPT (`sgpt`) via local Ollama/llama.*

## Open Ports / Services
| Port | Service | Version | Notes |
| --- | --- | --- | --- |
| 80/tcp | http | Apache httpd 2.4.25 (Debian) | |

## Vulnerabilities & Weaknesses
### Finding 1: Unsecured HTTP Cookie Flag

**Severity**: Medium
**What it is**: The PHPSESSID cookie flag is not set to `httponly`, allowing JavaScript code to access the session ID.
**Why it matters**: This weakness allows an attacker to steal the session ID, potentially leading to unauthorized access to the application.

### Finding 2: Outdated Apache HTTP Server

**Severity**: Medium
**What it is**: The Apache HTTP Server version is outdated (2.4.25).
**Why it matters**: Older versions of Apache may contain known vulnerabilities that can be exploited by attackers.

## Remediation
```
sudo apt-get update && sudo apt-get install -y apache2
```

Note: To fix the unsecured cookie flag, consider setting `httponly` for PHPSESSID in the application's configuration files.
