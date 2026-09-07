# metasploitable — Nmap service/version scan

*Target `target-m` · analysed by ShellGPT (`sgpt`) via local Ollama/llama.*

## Open Ports / Services
| Port | Service | Version | Notes |
| --- | --- | --- | --- |
| 21/tcp | ftp | vsftpd 2.3.4 | Anonymous FTP login allowed (FTP code 230) |
| 22/tcp | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) | RSA and DSA host keys available |
| 23/tcp | telnet | Linux telnetd | |
| 25/tcp | smtp | Postfix smtpd | SSLv2 supported, ciphers: SSL2_RC4_128_EXPORT40_WITH_MD5, etc. |
| 80/tcp | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | HTTP server header: Apache/2.2.8 (Ubuntu) DAV/2 |
| 111/tcp | rpcbind | 2 (RPC #100000) | RPC services available, including NFS and mountd |
| 139/tcp | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | NetBIOS session service available |
| 445/tcp | netbios-ssn | Samba smbd 3.0.20-Debian (workgroup: WORKGROUP) | NetBIOS session service available |

## Vulnerabilities & Weaknesses
### Finding 1: Unsecured FTP Server
**Severity**: Medium
**What it is**: The vsftpd server on port 21/tcp allows anonymous login, which can be exploited by an attacker to gain unauthorized access.
**Why it matters**: An unsecured FTP server can lead to data breaches and unauthorized access to sensitive files.

### Finding 2: Outdated SSH Server
**Severity**: Medium
**What it is**: The OpenSSH server on port 22/tcp has a version (4.7p1) that is outdated and potentially vulnerable to exploits.
**Why it matters**: An outdated SSH server can be exploited by an attacker to gain unauthorized access or execute malicious code.

### Finding 3: SSLv2 Support in SMTP Server
**Severity**: Low
**What it is**: The Postfix smtpd server on port 25/tcp supports SSLv2, which is an outdated and insecure protocol.
**Why it matters**: Using SSLv2 can lead to data breaches and unauthorized access to sensitive information.

### Finding 4: Unsecured HTTP Server
**Severity**: Low
**What it is**: The Apache httpd server on port 80/tcp does not have any security measures in place, making it vulnerable to attacks.
**Why it matters**: An unsecured HTTP server can lead to data breaches and unauthorized access to sensitive information.

### Finding 5: RPC Services Available
**Severity**: Medium
**What it is**: The rpcbind service on port 111/tcp provides access to various RPC services, including NFS and mountd.
**Why it matters**: Unsecured RPC services can be exploited by an attacker to gain unauthorized access or execute malicious code.

### Finding 6: NetBIOS Session Service Available
**Severity**: Medium
**What it is**: The Samba smbd service on ports 139/tcp and 445/tcp provides NetBIOS session services.
**Why it matters**: Unsecured NetBIOS session services can be exploited by an attacker to gain unauthorized access or execute malicious code.

## Remediation

### Secure FTP Server
* Update vsftpd to a secure version (e.g., vsftpd 3.5.4)
* Disable anonymous login and require authentication for all users

### Upgrade SSH Server
* Update OpenSSH to a secure version (e.g., OpenSSH 8.2p1)

### Secure SMTP Server
* Disable SSLv2 support in Postfix smtpd
* Configure TLS/SSL encryption for email transmission

### Secure HTTP Server
* Install and configure a web application firewall (WAF) to protect against attacks
* Update Apache httpd to a secure version (e.g., Apache httpd 2.4.38)

### Secure RPC Services
* Disable unnecessary RPC services
* Configure firewalls to block incoming RPC requests

### Secure NetBIOS Session Service
* Disable unnecessary NetBIOS session services
* Configure firewalls to block incoming NetBIOS session requests
