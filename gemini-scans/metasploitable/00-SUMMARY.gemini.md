# Metasploitable - Assessment Summary

### Executive Summary
The security assessment of the Metasploitable host reveals a critically compromised security posture. The host is currently running dozens of obsolete, end-of-life, backdoored, and misconfigured services that present multiple independent, unauthenticated paths to root-level command execution. Unrestricted administrative access is directly obtainable via active backdoors, unauthenticated remote method invocation registries, and input validation failures in network-exposed legacy services. With key administrative and file transfer utilities transmitting sessions in cleartext and vital database services exposed without authentication, this host is highly vulnerable to complete compromise and lateral movement.

---

### Severity-Ranked Findings Table

| Severity | Finding | Port or Service | Impact |
| :--- | :--- | :--- | :--- |
| **Critical** | Unauthenticated Bind Shell Backdoor | Port 1524 (ingreslock) | **Complete Host Takeover:** Allows any remote attacker to connect directly and instantly execute arbitrary commands as the `root` superuser without authentication. |
| **Critical** | Samba Username Map Script RCE (CVE-2007-2447) | Ports 139/445 (Samba smbd 3.0.20-Debian) | **Remote Root Command Execution:** Attackers can run arbitrary shell commands with root privileges by sending shell metacharacters in the username field during MS-RPC logon transactions. |
| **Critical** | vsftpd Backdoor RCE (CVE-2011-2523) | Port 21 (vsftpd 2.3.4) | **Remote Root Command Execution:** Spawns an unauthenticated shell on port 6200 when a user attempts connection with a username ending in `:)`. |
| **Critical** | UnrealIRCd Trojan Backdoor (CVE-2010-2075) | Ports 6667/6697 (UnrealIRCd) | **Remote Command Execution:** Allows remote attackers to execute arbitrary system commands with IRC daemon privileges by sending a command starting with the characters "AB". |
| **Critical** | distcc Daemon Command Execution (CVE-2004-2687) | Port 3632 (distccd v1) | **Remote Command Execution:** Allows remote attackers to execute arbitrary commands as the `distcc` user by embedding shell arguments in compilation tasks. |
| **Critical** | Unauthenticated Distributed Ruby RMI | Port 8787 (Ruby DRb) | **Remote Command Execution:** Lacks authentication, allowing remote attackers to invoke arbitrary Ruby methods to execute system-level commands. |
| **Critical** | Unsecured Java RMI Registry | Ports 1099/37867 (Java-RMI / GNU Classpath) | **Remote Command Execution:** Unsecured registries allow remote class registration and lookup, exposing the host to Java deserialization attacks (e.g., via ysoserial). |
| **High** | Cleartext Transmission & Host Trust (r-services) | Ports 512, 513, 514 (exec, login, shell) | **Credential Sniffing & Hijacking:** Legacy protocols transmit administrative data in cleartext and bypass authentication using spoofable IP-based host trust files. |
| **High** | Insecure Network File System Exports | Port 2049/111 (NFS & rpcbind) | **Unauthorized File Access & Privilege Escalation:** Loose export configurations (e.g., `no_root_squash`) allow remote clients to mount directories, modify system files, or inject SSH keys. |
| **High** | Telnet Cleartext Session Exposure | Port 23 (Linux telnetd) | **Administrative Credential Theft:** Transmits interactive administrative logins and session payloads over the network in cleartext, enabling credential sniffing. |
| **High** | Obsolete Database Network Exposure | Port 3306 (MySQL 5.0.51a) & Port 5432 (PostgreSQL 8.3) | **Data Exfiltration & Secondary RCE:** Obsolete, unhardened database engines exposed to the network are vulnerable to remote exploits, SQL injections, and brute-forcing. |
| **Medium** | Outdated Apache HTTP Server & WebDAV | Port 80 (Apache httpd 2.2.8) | **Information Disclosure & File Tampering:** Outdated server containing public CVEs; active WebDAV modules expose internal directory configurations. |
| **Medium** | Outdated OpenSSH Server | Port 22 (OpenSSH 4.7p1) | **User Enumeration & Cryptographic Cracking:** Exposed to user enumeration and supports deprecated, weak cryptographic algorithms (e.g., RC4, 3DES). |
| **Medium** | Legacy FTP Server Implementation | Port 2121 (ProFTPD 1.3.1) | **File System Compromise:** Vulnerable to legacy buffer overflows; transmits all credentials and file transfers in cleartext. |
| **Medium** | Postfix SMTP Legacy SSLv2 & Expired Certificate | Port 25 (Postfix smtpd) | **MITM & Cryptographic Downgrade:** SSLv2 support is vulnerable to downgrade attacks (DROWN), and the expired certificate (since 2010) facilitates MITM attacks. |

---

### Top Remediation Priorities

1. **Kill the Backdoors:** Terminate the listening processes running backdoors on port 1524 (`ingreslock`), port 3632 (`distccd`), and ports 6667/6697 (`UnrealIRCd`). Disable and comment out any associated persistent super-server configurations in `/etc/inetd.conf` and `/etc/xinetd.d/`.
2. **Remove R-Services, Telnet, and FTP:** Disable and uninstall legacy, unencrypted remote access utilities—specifically `rlogin`/`rsh`/`rexec` (ports 512–514), `telnetd` (port 23), and all plaintext FTP services (ports 21 and 2121). Force all administrative actions and file transfers over secure SSH/SFTP connections.
3. **Apply a Default-Deny Host Firewall:** Implement a local packet filter (e.g., `iptables` or `ufw`) configured with a strict default-deny inbound policy. Drop all incoming traffic by default, and only explicitly permit incoming SSH connections from a designated, highly restricted administrative subnet.
4. **Patch or Replace End-of-Life Services:** Upgrade remaining required services to modern, supported versions. Apply defensive hardening: disable the `username map script` and enforce mandatory message signing in Samba; bind MySQL and PostgreSQL strictly to the local loopback interface (`127.0.0.1`); and configure OpenSSH to require key-based authentication while disabling deprecated ciphers.

---

### Systemic Issue
The overarching systemic issue is that this host is running a fundamentally obsolete, end-of-life operating system distribution compiled with deprecated libraries. Because the operating system is entirely EOL, per-service hardening configurations and local firewalls are merely temporary stopgaps that cannot protect the host against unpatched kernel vulnerabilities or memory-safety exploits. The only true remediation is to completely **decommission** this legacy host, securely back up the necessary application data, and rebuild/redeploy the services onto a modern, actively supported, and hardened enterprise operating system featuring automated, continuous security patching.
