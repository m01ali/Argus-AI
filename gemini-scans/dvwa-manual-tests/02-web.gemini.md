# DVWA - web scan analysis (whatweb + nikto)

## 1. Technology Fingerprint

Based on the provided `whatweb` and `nikto` scan outputs, the target application environment has been fingerprinted with the following technical stack details:

*   **Operating System:** Debian Linux (reported by Apache server signature)
*   **Web Server:** Apache 2.4.25 (Outdated Debian package release)
*   **Application / Framework:** Damn Vulnerable Web Application (DVWA) v1.10 *Development*
*   **Backend Runtime:** PHP (indicated by `login.php` entry points and PHP sessions)
*   **Active Session/Cookie Headers:** `PHPSESSID`, `security`
*   **Internal Container IP:** `172.20.0.2:80` (mapped to hostname `target-w`)

---

## 2. Vulnerabilities and Weaknesses

The scan results reveal several high-risk misconfigurations and outdated components. These have been analyzed, classified by severity, and prioritized below:

### 2.1 Remotely Available Configuration Information
*   **Severity:** High
*   **Description:** Nikto flagged that sensitive configuration files may be remotely accessible in `/config/`. This directory typically holds database credentials, security keys, database connection drivers, and environment variables.
*   **Impact:** If configuration files (e.g., `.inc`, `.conf`, or backup config files) are readable, an attacker can extract plaintext database credentials, encryption salts, and internal API keys, resulting in complete database and platform compromise.

### 2.2 Directory Indexing Enabled on `/config/` and `/docs/` (CWE-548)
*   **Severity:** Medium
*   **Description:** The web server is configured with directory listings enabled for `/config/` and `/docs/`. When no default index page (e.g., `index.php` or `index.html`) is found, Apache returns a list of files within that directory.
*   **Impact:** Exposes the complete folder structures to attackers, allowing direct reconnaissance, identification of target scripts, discovery of legacy files, or access to sensitive documentation files.

### 2.3 Outdated Apache HTTP Server v2.4.25 (CWE-937)
*   **Severity:** Medium
*   **Description:** The target is running Apache HTTP Server version 2.4.25. This legacy release contains known, unpatched public vulnerabilities (such as HTTP Request Smuggling, Denial of Service, and buffer overflows).
*   **Impact:** Exploitation of known CVEs against the outdated server daemon could lead to service disruption, privilege escalation, or arbitrary code execution.

### 2.4 Exposed Version Control Metadata File (`/.gitignore`)
*   **Severity:** Low
*   **Description:** The `.gitignore` file is publicly readable at the web root.
*   **Impact:** Exposes the project's internal directory structure, third-party module locations, and names of skipped files (e.g., `.env`, keys, logs), facilitating targeted path-traversal or vulnerability mapping.

### 2.5 Exposed Administrative Login Page (`/login.php`)
*   **Severity:** Low
*   **Description:** The DVWA administrator and user authentication portal is fully exposed to the public internet without network-level restrictions.
*   **Impact:** Increases risk of automated brute-force attacks, credential stuffing, and session hijacking.

### 2.6 Missing Critical Security Headers
*   **Severity:** Low
*   **Description:** The web server fails to emit modern HTTP response security headers:
    *   `Content-Security-Policy` (CSP)
    *   `Strict-Transport-Security` (HSTS)
    *   `X-Content-Type-Options`
    *   `Referrer-Policy`
    *   `Permissions-Policy`
*   **Impact:** 
    *   *Missing CSP:* Significantly increases susceptibility to cross-site scripting (XSS) and clickjacking.
    *   *Missing HSTS:* Leaves traffic vulnerable to SSL stripping/MITM attacks during initial connections.
    *   *Missing X-Content-Type-Options:* Allows browser-side MIME-sniffing, facilitating script-injection attacks using non-executable extensions.
    *   *Missing Referrer-Policy:* May leak sensitive query parameter data to external links.
    *   *Missing Permissions-Policy:* Fails to restrict device hardware capability usage (e.g., camera, microphone) under XSS scenarios.

---

## 3. Remediation

To secure the environment and mitigate the identified risks, implement the following technical solutions using concrete Apache configuration directives and deployment workflows:

### 3.1 Disable Directory Indexing and Deny Web Access to `/config/`
1. Turn off directory listings globally by setting the `Options` directive.
2. Completely restrict access to `/config/` within the Apache site configuration (e.g., in `/etc/apache2/sites-available/000-default.conf` or inside the directory's `.htaccess` file).

```apache
# Disable global directory listings
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Block all direct web access to the config directory
<Directory "/var/www/html/config">
    Require all denied
</Directory>
```

### 3.2 Block and Remove `.gitignore` and Other Version Control Files
Ensure that sensitive hidden files (like `.git`, `.gitignore`, `.env`) are blocked from public access in the web root.

```apache
# Deny access to hidden dotfiles
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Specifically redirect or block .gitignore
Redirect 404 /.gitignore
```
*Best Practice:* Update the build pipeline to omit development metadata files (like `.gitignore`) from the final production directory.

### 3.3 Configure Missing Security Headers
Enable Apache's `mod_headers` module (`a2enmod headers`) and apply the following hardening headers within your VirtualHost block:

```apache
<IfModule mod_headers.c>
    # 1. Content-Security-Policy (Restricts source domains for scripts, styles, frames)
    Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"

    # 2. Strict-Transport-Security (Enforces HTTPS connection for 2 years)
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    # 3. X-Content-Type-Options (Prevents MIME-sniffing)
    Header set X-Content-Type-Options "nosniff"

    # 4. Referrer-Policy (Prevents leakage of query strings to foreign sites)
    Header set Referrer-Policy "strict-origin-when-cross-origin"

    # 5. Permissions-Policy (Disables browser hardware permissions)
    Header set Permissions-Policy "geolocation=(), camera=(), microphone=()"
</IfModule>
```

### 3.4 Upgrade the Apache Web Server
To patch vulnerabilities associated with version 2.4.25, upgrade the Apache package to the latest stable Debian/Ubuntu LTS release.

```bash
# Update local package index and upgrade Apache2 package
sudo apt-get update
sudo apt-get install --only-upgrade apache2
```
*Docker Deployments:* If running inside a container, update your `Dockerfile` base image to use a supported, updated standard image:
```dockerfile
FROM php:8.2-apache
```

### 3.5 Restrict Access to `/login.php`
Enforce network boundaries to protect the application's entry page from brute-force attempts.

```apache
<Files "login.php">
    # Permit access only from corporate subnet or administrative VPN
    Require ip 10.0.0.0/8 192.168.0.0/16 127.0.0.1
</Files>
```
