# DVWA - nmap analysis

## 1. Open Ports and Detected Services

| Port | State | Service | Version | Additional Information / Banner |
| :--- | :--- | :--- | :--- | :--- |
| **80/tcp** | Open | http | Apache httpd 2.4.25 ((Debian)) | `robots.txt` found, `PHPSESSID` cookie missing HttpOnly, verbose Server header |

---

## 2. Vulnerabilities and Weaknesses

### Finding 1: Outdated and Vulnerable Apache Web Server
* **Severity:** Medium
* **What it is:** The target host runs Apache HTTP Server version `2.4.25`.
* **Why it matters:** This version is outdated and affected by several known vulnerabilities (including request smuggling, path traversal/file disclosure if certain modules are enabled, and denial of service). Attackers can target these known CVEs to compromise the server's availability or integrity.

### Finding 2: Session Cookie Missing `HttpOnly` Flag
* **Severity:** Medium
* **What it is:** The application's session identifier cookie (`PHPSESSID`) is set without the `HttpOnly` flag.
* **Why it matters:** Without the `HttpOnly` flag, scripts executing within the browser (such as those injected via Cross-Site Scripting/XSS) can access the session cookie via `document.cookie`. This dramatically increases the risk of successful session hijacking attacks.

### Finding 3: Cleartext Communication (Missing TLS/HTTPS Hardening Gap)
* **Severity:** Medium
* **What it is:** The web application is accessible over plaintext HTTP (port 80) with no redirection to HTTPS.
* **Why it matters:** All data in transitΓÇöincluding authentication credentials, session identifiers, and sensitive application contentΓÇöis sent unencrypted. Anyone positioned on the local network path can intercept, sniff, or alter this traffic using Man-in-the-Middle (MitM) techniques.

### Finding 4: Verbose Server Banner and Application Title Disclosure
* **Severity:** Low
* **What it is:** The server exposes the exact web server version and OS platform (`Apache/2.4.25 (Debian)`) in the HTTP response headers, and the web page title (`Login :: Damn Vulnerable Web Application (DVWA) v1.10...`) explicitly leaks the application name and version.
* **Why it matters:** Detailed information disclosure simplifies reconnaissance. Attackers do not need to guess or probe; they can immediately look up exploits tailored specifically to Apache 2.4.25 on Debian and DVWA v1.10.

### Finding 5: Broad Disallowed Directory in `robots.txt`
* **Severity:** Low
* **What it is:** The `robots.txt` file contains a disallowed entry for the root directory (`/`).
* **Why it matters:** While intended to guide web crawlers, attackers actively inspect `robots.txt` to find paths that administrators are trying to hide. Disallowing `/` signals that the entire root contains restricted content, highlighting it as a high-value target for manual brute-forcing or mapping.

---

## 3. Remediation

### Action 1: Upgrade Apache Web Server
* **Fix:** Update the web server packages to the latest stable release provided by the distribution repository.
* **Implementation:**
  ```bash
  apt-get update && apt-get install --only-upgrade apache2
  ```

### Action 2: Secure Session Cookies
* **Fix:** Configure PHP to enforce the `HttpOnly` (and `Secure`) attributes on session cookies.
* **Implementation:**
  In `/etc/php/7.x/apache2/php.ini` (or the relevant active configuration file), ensure the following directives are configured:
  ```ini
  session.cookie_httponly = On
  session.cookie_secure = On
  ```

### Action 3: Enable HTTPS / TLS Encryption
* **Fix:** Deploy a TLS certificate (using Let's Encrypt or an internal CA) and redirect all HTTP traffic to HTTPS.
* **Implementation:**
  1. Configure a VirtualHost on port 443 with TLS certificates enabled.
  2. Implement an automatic redirect in the port 80 configuration:
     ```apache
     <VirtualHost *:80>
         ServerName 172.20.0.2
         Redirect permanent / https://172.20.0.2/
     </VirtualHost>
     ```
  3. Set the HTTP Strict Transport Security (HSTS) header on the secure host:
     ```apache
     Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
     ```

### Action 4: Suppress Verbose Banners
* **Fix:** Disable verbose server tokens in the Apache security configuration.
* **Implementation:**
  Modify `/etc/apache2/conf-enabled/security.conf` (or the main configuration file) to include:
  ```apache
  ServerTokens ProductOnly
  ServerSignature Off
  ```
  *(Also, customize or genericize the HTML `<title>` tag within the login.php application source code to avoid exposing the application version).*

### Action 5: Re-evaluate or Remove `robots.txt`
* **Fix:** Remove the wildcard disallowance from `robots.txt` and instead use robust authentication, authorization mechanisms, or `<meta name="robots" content="noindex">` tags directly on private pages to prevent search indexing without leaking the existence of restricted assets.
