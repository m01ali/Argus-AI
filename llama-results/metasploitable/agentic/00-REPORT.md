# metasploitable — Agentic Assessment (Llama-driven)

*Target `target-m` · model `llama3:8b` drove the scanning AND the analysis · 2026-09-07 14:26 · 6 commands run.*

## Open Ports / Services

| Port | State | Service |
| --- | --- | --- |
| 21/tcp | open | ftp |
| 22/tcp | open | ssh |
| 23/tcp | open | telnet |
| 25/tcp | open | smtp |
| 80/tcp | open | http |
| 111/tcp | open | rpcbind |
| 139/tcp | open | netbios-ssn |
| 445/tcp | open | microsoft-ds |
| 512/tcp | open | exec |
| 513/tcp | open | login |
| 514/tcp | open | shell |
| 1099/tcp | open | rmiregistry |
| 1524/tcp | open | ingreslock |
| 2121/tcp | open | ccproxy-ftp |
| 3306/tcp | open | mysql |
| 3632/tcp | open | distccd |
| 5432/tcp | open | postgresql |
| 6667/tcp | open | irc |
| 6697/tcp | open | ircs-u |
| 8787/tcp | open | msgsrvr |
| 34523/tcp | open | unknown |

## Vulnerabilities & Weaknesses

### Finding 1
**Severity:** Medium
**CVE:** N/A
**What it is:** The system has multiple open ports, including FTP (21), SSH (22), and Telnet (23).
**Why it matters:** These open ports can be used by attackers to gain unauthorized access to the system or exploit vulnerabilities in the services running on these ports.

### Finding 2
**Severity:** Low
**CVE:** N/A
**What it is:** The Apache web server (80) is running with a default configuration, which may expose the system to common web-based attacks.
**Why it matters:** A default-configured Apache web server can be vulnerable to common web-based attacks, such as SQL injection and cross-site scripting.

### Finding 3
**Severity:** Medium
**CVE:** N/A
**What it is:** The IRC (6667) service is running with no apparent authentication or encryption.
**Why it matters:** An unauthenticated and unencrypted IRC service can be used by attackers to gain unauthorized access to the system or exploit vulnerabilities in the IRC service.

## Remediation

* Close unnecessary open ports using firewall rules or disabling services that are not being used.
* Configure Apache web server with secure settings, such as enabling SSL/TLS encryption and configuring authentication mechanisms.
* Implement authentication and encryption for the IRC service, if it is necessary to keep running.
