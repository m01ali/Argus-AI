# Metasploitable - service hardening report

## 1. Running Services Inventory

The following inventory details the active network-facing services detected during the port and service version scan. 

| Port | Service | Version | Concern |
| :--- | :--- | :--- | :--- |
| **21/tcp** | ftp | vsftpd 2.3.4 | Critical backdoor vulnerability (CVE-2011-2523); cleartext transmission; anonymous access allowed. |
| **22/tcp** | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) | Outdated SSH daemon; vulnerable to user enumeration; supports weak/deprecated cryptography. |
| **23/tcp** | telnet | Linux telnetd | Highly insecure; transmits administrative sessions and credentials in cleartext. |
| **25/tcp** | smtp | Postfix smtpd | Cryptographically broken SSLv2 protocol supported; TLS certificate has been expired since 2010. |
| **80/tcp** | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | Legacy web server; prone to multiple public CVEs; WebDAV exposes server files and directory configuration. |
| **111/tcp** | rpcbind | 2 (RPC #100000) | Information disclosure of registered RPC services; maps internal remote procedure ports. |
| **139/tcp** | netbios-ssn | Samba smbd 3.X - 4.X | Direct path for Samba reconnaissance; works alongside port 445. |
| **445/tcp** | netbios-ssn | Samba smbd 3.0.20-Debian | Critical remote root command execution (CVE-2007-2447); SMB signing disabled; guest access allowed. |
| **512/tcp** | exec | rexec (r-services) | Outdated remote execution utility; transmits passwords in cleartext; relies on insecure host verification. |
| **513/tcp** | login | rlogin (r-services) | Outdated remote login utility; transmits passwords in cleartext; vulnerable to IP address spoofing. |
| **514/tcp** | tcpwrapped | rsh (r-services) | Outdated remote shell utility; lacks encryption and strong authentication; highly susceptible to session hijacking. |
| **1099/tcp** | java-rmi | GNU Classpath grmiregistry | Unsecured Java Remote Method Invocation registry; susceptible to unauthenticated remote code execution. |
| **1524/tcp** | ingreslock | Root shell backdoor | **Most Severe:** An unauthenticated, interactive bash shell running as `root` is bound directly to this port. |
| **2121/tcp** | ftp | ProFTPD 1.3.1 | Legacy FTP server; multiple known vulnerabilities (buffer overflows, SQL injection); transmits credentials in cleartext. |
| **3306/tcp** | mysql | MySQL 5.0.51a-3ubuntu5 | Outdated database server exposed to the network; vulnerable to brute-forcing, SQL attacks, and privilege escalation. |
| **3632/tcp** | distccd | distccd v1 | Critical remote command execution via compilation tasks (CVE-2004-2687). |
| **5432/tcp** | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 | Legacy database exposed to the network with expired certificate; prone to SQL injection and RCE. |
| **6667/tcp** | irc | UnrealIRCd | Backdoored IRC daemon allowing direct remote command execution (CVE-2010-2075). |
| **6697/tcp** | irc | UnrealIRCd (SSL) | Backdoored IRC daemon over SSL; same vulnerability profile as port 6667 (CVE-2010-2075). |
| **8787/tcp** | drb | Ruby DRb RMI (Ruby 1.8) | Unauthenticated Distributed Ruby registry; allows arbitrary Ruby method invocation and shell command execution. |
| **2049/tcp** | nfs | NFS (v2, v3, v4) | Raw network file system access; insecure client host exports without transport encryption. |
| **37867/tcp**| java-rmi | GNU Classpath grmiregistry | Secondary unsecured Java RMI registry; prone to unauthenticated remote code execution. |

---

## 2. Risk-Ranked Issues List

| Severity | Affected Service & Version | CVE / Weakness | Security Impact |
| :--- | :--- | :--- | :--- |
| **Critical** | ingreslock (Port 1524) | Unauthenticated Bind Shell Backdoor | **Complete Host Takeover:** Anyone connecting to port 1524 is immediately granted an interactive root shell prompt (`root@214dcb0131f9:/#`) without needing credentials, facilitating full host compromise. |
| **Critical** | Samba smbd 3.0.20-Debian (Port 139/445) | CVE-2007-2447 (MS-RPC Username Map Script RCE) | **Remote Root Code Execution:** Unauthenticated remote attackers can execute arbitrary shell commands with root privileges by supplying shell metacharacters in the username field during MS-RPC logon transactions. |
| **Critical** | UnrealIRCd (Port 6667/6697) | CVE-2010-2075 (UnrealIRCd Trojan Backdoor) | **Remote Code Execution:** A trojaned distribution of UnrealIRCd contains a backdoor that allows remote users to execute arbitrary system commands with the privileges of the IRC daemon by sending a command starting with "AB". |
| **Critical** | distccd v1 (Port 3632) | CVE-2004-2687 (distcc Daemon Command Execution) | **Remote Code Execution:** The compiler daemon processes compilation jobs without restricting arguments. Remote attackers can pass arbitrary shell commands within build requests to run code as the `distcc` user. |
| **Critical** | vsftpd 2.3.4 (Port 21) | CVE-2011-2523 (vsftpd Backdoor RCE) | **Remote Root Code Execution:** A compromised vsftpd distribution spawns a shell on port 6200 when a user authenticates with a username ending with `:)`. Attackers can connect to port 6200 to execute system commands as root. |
| **Critical** | Ruby DRb (Port 8787) | Unauthenticated Distributed Ruby RMI | **Remote Code Execution:** The Distributed Ruby protocol lacks built-in authentication. Attackers can connect to port 8787 and invoke arbitrary Ruby methods to execute system-level commands in the context of the Ruby process. |
| **Critical** | Java RMI / GNU Classpath (Port 1099/37867) | Java Deserialization / Unsecured RMI | **Remote Code Execution:** Unsecured Java RMI registries allow remote attackers to register, look up, and execute arbitrary classes, making them highly vulnerable to Java deserialization attacks (e.g., using ysoserial payloads) to run arbitrary system commands. |
| **High** | r-services: exec/login/tcpwrapped (Port 512/513/514) | Cleartext Transmission & IP-Based Authentication | **Credential Sniffing & Hijacking:** Legacy utilities transmit session data in cleartext. They also utilize host-based trust (`/etc/hosts.equiv` or `~/.rhosts`), allowing attackers to spoof IP addresses and bypass authentication to spawn remote shells. |
| **High** | Network File System (NFS) (Port 2049/111) | Insecure NFS Export Options (e.g., `no_root_squash`) | **Unauthorized File Access & Privilege Escalation:** Unencrypted NFS exports allow remote clients to mount system directories. Attackers can manipulate system files, write SSH keys, or read confidential configuration files, leading to full local root access. |
| **High** | Linux telnetd (Port 23) | Cleartext Transmission of Session Data | **Administrative Credential Theft:** Administrative credentials and sessions are transmitted over the network in cleartext. Anyone positioned along the network path can easily sniff administrative credentials or hijack sessions. |
| **High** | MySQL 5.0.51a (Port 3306) & PostgreSQL 8.3 (Port 5432) | Obsolete Database Engine Exposure | **Database Compromise & Remote Exploitation:** Highly outdated databases exposed to the network are vulnerable to remote exploits, credential brute-forcing, and SQL injection attacks, leading to sensitive data leaks or secondary RCE. |
| **Medium** | Apache httpd 2.2.8 (Port 80) | Outdated HTTP Web Server & WebDAV | **Information Disclosure, DoS, and File Tampering:** This EOL server contains multiple public CVEs. Active WebDAV modules allow directory traversal, configuration exposure, and potential unauthorized file manipulation. |
| **Medium** | OpenSSH 4.7p1 (Port 22) | Outdated OpenSSH Server | **User Enumeration & Cryptographic Cracking:** OpenSSH 4.7p1 is susceptible to user enumeration attacks and supports deprecated cryptographic algorithms (e.g., RC4, Blowfish, 3DES ciphers) vulnerable to cryptographic interception. |
| **Medium** | ProFTPD 1.3.1 (Port 2121) | Legacy FTP Server Implementation | **File System Compromise & Credential Sniffing:** Prone to legacy buffer overflow and SQL injection vulnerabilities; transmits all usernames, passwords, and file contents in cleartext. |
| **Medium** | Postfix smtpd (Port 25) | Legacy SSLv2 Support & Expired Certificate | **Cryptographic Downgrade & MITM:** SSLv2 support exposes SMTP-over-SSL connections to cryptographic downgrade attacks (e.g., DROWN). The expired SSL certificate allows attackers to perform Man-In-The-Middle (MITM) attacks. |
| **Low** | rpcbind (Port 111) | RPC Portmapper Information Disclosure | **Reconnaissance Information Disclosure:** Allows remote attackers to list all registered RPC services on the host and map their associated high-range ports (e.g., mountd, nlockmgr), facilitating targeted attacks. |
| **Low** | Samba smbd 3.0.20-Debian (Port 445) | SMB Signing Disabled | **Man-In-The-Middle (MITM) Relay Attacks:** Because SMB signing is not enforced, an attacker on the same local network can capture authentication requests and relay them to other machines on the network, leading to lateral movement. |

---

## 3. Prioritized Remediation Plan

To defend and harden this legacy host, the server owner must apply the following specific, technical remediation steps immediately.

### Step 1: Immediate Service Shutdown (Kill Immediately)
Certain services represent extreme, active backdoor exposures or have zero legitimate business use cases on a modern network. They must be terminated and disabled immediately.

1. **Stop and Disable Backdoors, IRC, and Compilation Services:**
   - **Ingreslock Backdoor (Port 1524):** Immediately terminate the process bound to port 1524. Check `/etc/inetd.conf` and `/etc/xinetd.d/` for any legacy entries mapping `ingreslock` or spawn shells, and comment them out.
   - **distccd (Port 3632):** Stop the `distcc` service and remove its startup scripts.
   - **UnrealIRCd (Port 6667/6697):** Stop the IRC daemon process and delete the backdoored binary to prevent execution.
2. **Decommission Cleartext Legacy Remote Administration Services:**
   - **R-Services (Port 512, 513, 514):** Terminate `rexec`, `rlogin`, and `rsh` services. Disable and remove their respective configuration files from `/etc/xinetd.d/` and delete any global trust configurations (`/etc/hosts.equiv` or user-specific `~/.rhosts`).
   - **Telnet (Port 23):** Stop the `telnetd` service and disable it within `/etc/xinetd.d/`. All remote administrative access must be routed through SSH.
   - **FTP (Port 21, 2121):** Stop the `vsftpd` and `proftpd` services. FTP transmits passwords in cleartext and vsftpd 2.3.4 contains a root shell backdoor. All file transfers must be replaced with SFTP.
3. **Stop and Disable Developer & Object Registry Services:**
   - **Java RMI (Port 1099, 37867) & Ruby DRb (Port 8787):** Terminate the processes running Java RMI and Ruby DRb registries. Ensure they do not automatically execute at startup, as they represent immediate remote execution vectors.

### Step 2: Patch, Replace, or Reconfigure (Defensive Application Hardening)
For services that must remain running, secure configurations and cryptographic hardening must be enforced.

1. **Samba (SMB) Hardening (Ports 139, 445):**
   - **Upgrade:** Compile or install a supported, patched version of Samba that is not vulnerable to CVE-2007-2447.
   - **Configure `smb.conf`:** Apply the following options in the `[global]` section of `/etc/samba/smb.conf`:
     ```ini
     [global]
     # Enforce mandatory SMB signing to block MITM relay attacks
     server signing = mandatory
     
     # Disable unauthenticated guest access
     map to guest = Never
     
     # Restrict SMB access strictly to the local loopback or a trusted management VLAN
     hosts allow = 127.0.0.1 192.168.56.0/24
     ```
   - Restart the Samba service to apply changes.

2. **SSH Server Hardening (Port 22):**
   - **Upgrade:** Upgrade OpenSSH to a modern, supported version.
   - **Configure `sshd_config`:** Edit `/etc/ssh/sshd_config` to enforce modern, secure ciphers, restrict administrative login, and transition to key-based authentication:
     ```text
     # Disable old SSH protocol versions
     Protocol 2

     # Enforce strong key exchange algorithms (KEX)
     KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

     # Enforce strong cryptographic ciphers (disable RC4, Blowfish, 3DES)
     Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

     # Enforce strong Message Authentication Codes (MACs)
     MACs hmac-sha2-512-etm@openssh.com

     # Disable password-based root login
     PermitRootLogin prohibit-password

     # Enforce cryptographic key-based authentication and disable passwords
     PasswordAuthentication no
     PubkeyAuthentication yes
     ```
   - Reload the SSH configuration: `sudo service ssh restart` (or equivalent).

3. **Database Security Hardening (MySQL Port 3306, PostgreSQL Port 5432):**
   - **Upgrade:** Upgrade both database systems to modern, stable releases.
   - **Restrict Bindings:** Force database engines to listen exclusively on local loopback interfaces. Database management should only occur locally or via SSH port forwarding.
     - **MySQL (`my.cnf`):**
       ```ini
       [mysqld]
       bind-address = 127.0.0.1
       ```
     - **PostgreSQL (`postgresql.conf`):**
       ```ini
       listen_addresses = 'localhost'
       ```
     - Restart the database services.

4. **Postfix SMTP Hardening (Port 25):**
   - **Disable Broken Cryptography:** Edit `/etc/postfix/main.cf` to explicitly deny deprecated SSL/TLS protocols:
     ```text
     smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
     smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
     ```
   - **Certificate Replacement:** Generate a modern, secure TLS certificate from a trusted public Certificate Authority (e.g., Let's Encrypt) or a secured internal Enterprise PKI, replacing the expired 2010 certificate.

5. **Apache Web Server Hardening (Port 80):**
   - **Upgrade:** Upgrade Apache httpd to a modern, actively supported version.
   - **Disable WebDAV:** Disable WebDAV modules if not required by commenting out lines loading `mod_dav` and `mod_dav_fs` in Apache configurations.
   - **Enforce TLS:** Implement TLS on port 443. Set up HTTP-to-HTTPS redirection on port 80 and enable HSTS headers.

### Step 3: Network Firewalls and Segmentation
Prevent unauthorized network discovery and exploitation by blocking exposed ports at the network boundary and the host layer.

1. **Host-Based Firewall (UFW / iptables):**
   - Implement a strict **Default-Deny** inbound firewall policy:
     ```bash
     sudo ufw default deny incoming
     sudo ufw default allow outgoing
     ```
   - Explicitly permit incoming SSH connections only from authorized management workstations or a secure VPN range:
     ```bash
     sudo ufw allow from 192.168.56.100 to any port 22 proto tcp
     ```
   - Enable the firewall and logging:
     ```bash
     sudo ufw enable
     ```
2. **Network Segmentation:**
   - Place this host in a dedicated, isolated VLAN or private network segment (DMZ) with no direct ingress paths from the public Internet.
   - Apply strict Network Security Group (NSG) rules or border firewall ACLs to drop any traffic heading to legacy ports (such as RPC, Samba, database services, and NFS) from outside the local subnet.

### Step 4: Enforce Encryption and Authentication in Transit
1. **Mandate Cryptographic Communication:**
   - Ban any interactive administrative sessions or file transfers using plaintext protocols (Telnet, FTP, R-services).
   - Enforce the use of TLS 1.2 or TLS 1.3 across all active network endpoints (HTTPS, SMTPS, secure databases).
2. **Multi-Factor / Cryptographic Authentication:**
   - Migrate administrative SSH endpoints to require SSH Public-Key Cryptographic Authentication.
   - Implement strong passphrase requirements and lock down any legacy local database accounts with complex, non-default passwords.

### Step 5: Core Recommendation (Decommission and Rebuild)
While individual service hardening and host-based firewalls will mitigate immediate risks, they are temporary band-aid solutions. 

The underlying operating system (indicated by the outdated service versions, Debian base, and the expired 2010 SSL certificate) is a severely legacy, completely End-of-Life (EOL) distribution. Applying secure configurations to obsolete software compiled against outdated system libraries (such as glibc) will not protect the host from kernel exploits or memory safety vulnerabilities.

**Critical Action:** The server owner must prioritize **decommissioning** this legacy server. The legacy software applications and database schemas must be audited, backed up, and redeployed onto a modern, actively supported, and hardened enterprise operating system (e.g., Ubuntu 24.04 LTS, Debian 12, or Rocky Linux 9). Continuous vulnerability monitoring and automated security patching must be established on the replacement host from day one.
