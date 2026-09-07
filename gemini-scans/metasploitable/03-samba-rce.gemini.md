# Metasploitable - Samba username map script RCE (CVE-2007-2447)

### Summary
Samba versions 3.0.0 through 3.0.25rc3 (including 3.0.20) configured with the `username map script` directive are vulnerable to unauthenticated remote command execution (RCE) as root. This vulnerability is rated **Critical**. Vulnerability presence on this host is confirmed by the service version coupled with the vulnerable configuration directive in `smb.conf`. 

Due to client-side validation, modern SMB clients (such as the Samba 4.x smbclient) sanitize usernames and refuse to transmit shell metacharacters such as backticks in SMB session setups. Live exploitation therefore requires crafting raw SMB1 session-setup packets, which is the canonical technique implemented by Metasploit's `exploit/multi/samba/usermap_script` module. Independent confirmation of full host compromise was already established via the unauthenticated root shell running as a backdoor on the ingreslock service (TCP port 1524).

### Root Cause
The vulnerability exists because Samba fails to sanitize the client-supplied username before constructing and executing a shell command. When the `username map script` directive is enabled, Samba builds a shell command dynamically using the template:
`/bin/sh -c "<script_path> <username>"`
and executes it. Because the input is not sanitized, shell metacharacters (such as backticks) embedded within the SMB username are evaluated directly by `/bin/sh` and run with root privileges.

Additionally, the service is weakened by having SMB message signing disabled (allowing potential packet manipulation) and permitting unauthenticated guest access.

### Evidence
- **Samba Version:** `Samba smbd 3.0.20-Debian` (detected on open ports 139/tcp and 445/tcp, confirmed via `smbd -V`).
- **Vulnerable Configuration:** Line 107 of `/etc/samba/smb.conf` contains:
  ```ini
  username map script = /etc/samba/scripts/mapusers.sh
  ```
- **SMB Security Mode Weaknesses:**
  - `message_signing = disabled`
  - `account_used = guest` (anonymous/guest access allowed)
- **Anonymously Reachable Shares (via SMB1):**
  - `print$`
  - `tmp` ("oh noes!")
  - `opt`
  - `IPC$`
  - `ADMIN$`

### Remediation
To fully secure the host, implement the following remediation measures:
1. **Upgrade Samba:** Install a patched version of Samba (Samba 3.0.25rc4 or later, or migrate to a currently supported release).
2. **Disable the Map Script:** Remove or comment out the `username map script` directive in `/etc/samba/smb.conf`, or rewrite the script and ensure input validation is strictly handled prior to execution.
3. **Enforce Message Signing:** Require SMB signing in `smb.conf` to prevent interception and relay attacks:
  ```ini
  server signing = mandatory
  ```
4. **Restrict Guest/Anonymous Access:** Secure anonymous access by modifying `smb.conf` settings:
  ```ini
  map to guest = Never
  restrict anonymous = 2
  ```
5. **Network Segmentation:** Use a firewall (such as `iptables` or a host-based firewall) to restrict access to ports 139/tcp and 445/tcp so that only trusted management hosts are permitted to connect.
6. **Operating System Upgrade:** Because this legacy host is running an end-of-life OS and is fundamentally insecure, it should be decommissioned and rebuilt on a modern, actively supported operating system.
