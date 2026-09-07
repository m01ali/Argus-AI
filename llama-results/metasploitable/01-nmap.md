# metasploitable — Nmap service/version scan

*Target `target-m` · analysed by `llama3:8b` via local Ollama.*

## Open Ports / Services

| Port | Service | Version | Notes |
| --- | --- | --- | --- |
| 21/tcp | ftp | vsftpd 2.3.4 | Anonymous FTP login allowed |
| 22/tcp | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) | RSA and DSA host keys available |
| 23/tcp | telnet | Linux telnetd | |
| 25/tcp | smtp | Postfix smtpd | SSLv2 supported, ciphers listed |
| 80/tcp | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | HTTP server header and title available |
| 111/tcp | rpcbind | 2 (RPC #100000) | RPC services listed |
| 139/tcp | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | SMB/CIFS file sharing available |
| 445/tcp | netbios-ssn | Samba smbd 3.0.20-Debian (workgroup: WORKGROUP) | SMB/CIFS file sharing available |
| 512/tcp | exec? | | Unrecognized service |
| 513/tcp | login | | |
| 514/tcp | tcpwrapped | | |
| 1099/tcp | java-rmi | GNU Classpath grmiregistry | |
| 1524/tcp | ingreslock? | | Unrecognized service |

## Vulnerabilities & Weaknesses

### Finding 1: Anonymous FTP Login Allowed (FTP)

**Severity:** Medium
**CVE:** None
**What it is:** The vsftpd FTP server allows anonymous login, which may allow unauthorized access to the system.
**Why it matters:** This vulnerability can be exploited by an attacker to gain access to sensitive files or data.

### Finding 2: SSLv2 Supported (SMTP)

**Severity:** Medium
**CVE:** None
**What it is:** The Postfix SMTP server supports SSLv2, which is considered insecure and vulnerable to attacks.
**Why it matters:** This vulnerability can be exploited by an attacker to intercept sensitive information or inject malicious data.

### Finding 3: Unrecognized Service (Exec?)

**Severity:** Low
**CVE:** None
**What it is:** The exec? service is not recognized, which may indicate a custom or proprietary service.
**Why it matters:** This finding does not pose a significant security risk, but further investigation may be necessary to determine the purpose and potential vulnerabilities of this service.

### Finding 4: Unrecognized Service (Ingreslock?)

**Severity:** Low
**CVE:** None
**What it is:** The ingreslock? service is not recognized, which may indicate a custom or proprietary service.
**Why it matters:** This finding does not pose a significant security risk, but further investigation may be necessary to determine the purpose and potential vulnerabilities of this service.

## Remediation

### Fix 1: Disable Anonymous FTP Login (FTP)

* Edit the vsftpd configuration file (/etc/vsftpd.conf) to disable anonymous login.
* Restart the vsftpd service to apply the changes.

### Fix 2: Upgrade or Disable SSLv2 Support (SMTP)

* Upgrade Postfix to a version that no longer supports SSLv2.
* Alternatively, disable SSLv2 support in the Postfix configuration file (/etc/postfix/main.cf).

### Fix 3: Investigate Unrecognized Services (Exec? and Ingreslock?)

* Further investigate the purpose and potential vulnerabilities of these services using additional tools or techniques.
* Consider disabling or blocking access to these services if they are not necessary for system functionality.
