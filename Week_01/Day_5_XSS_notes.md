# Cross-Site Scripting (XSS) Notes

Based on [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting).

## 1. Introduction to XSS
Cross-site scripting (XSS) is a web security vulnerability that allows an attacker to compromise the interactions users have with a vulnerable application. 

### Key Characteristics:
* **Same-Origin Policy (SOP) Circumvention**: XSS allows attackers to bypass the SOP, which is designed to segregate different websites from each other.
* **Malicious JavaScript**: It works by manipulating a vulnerable site to return malicious JavaScript to users.
* **Context**: Once the script runs in the victim's browser, the attacker can act as the user, access their data, and perform actions on their behalf.

---

## 2. Main Types of XSS

### A. Reflected XSS
Reflected XSS arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.
* **Mechanism**: The script is "reflected" off the web server to the victim's browser.
* **Example**: A search parameter displayed on a page:
    * URL: `https://insecure-website.com/search?term=item`
    * Response: `<p>You searched for: item</p>`
    * Payload: `https://insecure-website.com/search?term=<script>alert(1)</script>`

### B. Stored XSS (Persistent XSS)
Stored XSS occurs when an application receives data from an untrusted source and includes it in its later HTTP responses in an unsafe way.
* **Mechanism**: The script is permanently stored on the target server (e.g., in a database, in a comment field, user profile).
* **Impact**: Every user who views the affected page will execute the script.
* **Example**: A comment section where the payload `<script>...</script>` is saved to the database and rendered on the post page for all visitors.

### C. DOM-based XSS
DOM-based XSS arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the Document Object Model (DOM).
* **Taint Flow**:
    * **Source**: A JavaScript property that accepts attacker-controlled data (e.g., `location.search`, `document.cookie`).
    * **Sink**: A dangerous function or DOM object that can execute JavaScript or render HTML (e.g., `eval()`, `innerHTML`).
* **Key Difference**: In DOM XSS, the entire vulnerability exists in the client-side code; the server might not even see the payload if it's in the URL fragment (`#`).

---

## 3. Impact of XSS Vulnerabilities
A successful XSS attack can have devastating consequences:
* **Impersonation**: Stealing session cookies to hijack a user's session.
* **Data Theft**: Accessing sensitive information displayed to the user.
* **Account Takeover**: Performing actions as the user (changing passwords, emails).
* **Credential Capture**: Injecting a fake login form to capture usernames and passwords.
* **Malware Distribution**: Injecting trojan functionality or redirecting users to malicious sites.

---

## 4. How to Find and Test for XSS
1.  **Submit Simple Input**: Use unique alphanumeric strings to identify where input is reflected in the response.
2.  **Determine Context**: Check if the input is reflected inside HTML tags, attributes, or JavaScript strings.
3.  **Proof of Concept (PoC)**:
    * Use `alert(1)` or `print()` to confirm script execution.
    * *Note*: Modern browsers may block `alert()`, so `console.log()` or `print()` are good alternatives.
4.  **DOM Invader**: A Burp Suite tool specifically designed to find DOM-based XSS by tracking sources and sinks.

---

## 5. Prevention Strategies

### Input Filtering
* Filter input as strictly as possible on arrival.
* Use whitelists (e.g., allow only alphanumeric characters) rather than blacklists.

### Output Encoding
* Encode data immediately before it is written to the page.
* Use context-specific encoding:
    * **HTML Encoding**: Convert `<` to `&lt;`, `>` to `&gt;`.
    * **Attribute Encoding**: For data inside `href` or `src`.
    * **JavaScript Encoding**: For data inside script blocks.

### Content Security Policy (CSP)
* A browser-level security layer that restricts the sources from which scripts and other resources can be loaded.
* Can prevent scripts from being executed even if an injection vulnerability exists.

### Secure Headers
* `X-Content-Type-Options: nosniff`: Prevents browsers from trying to "guess" the content type (MIME-sniffing).
* `Content-Type`: Ensure it is set correctly (e.g., `text/html; charset=utf-8`).

---

## 6. XSS vs. CSRF
* **XSS**: Allows an attacker to execute arbitrary JavaScript. It is "two-way" (can read responses).
* **CSRF**: Allows an attacker to induce a victim to perform unintended actions. It is "one-way" (cannot read responses).
* *Note*: A successful XSS attack can be used to bypass CSRF protections by reading the CSRF token from the page.

---
*Created as a summary of the PortSwigger Web Security Academy - Cross-Site Scripting Module.*
