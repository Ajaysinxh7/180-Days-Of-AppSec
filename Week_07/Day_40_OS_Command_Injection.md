# Day 40 Notes — OS Command Injection (Blind & Out-of-Band)

  
**Platform:** PortSwigger Web Security Academy  
**Focus:** Foundation-first understanding of OS Command Injection with visible and blind exploitation techniques.

> **Note on omitted payloads:** The specific injection strings and raw HTTP requests from these labs are intentionally excluded from this document. Antivirus and endpoint detection tools flag files containing active shell exploitation syntax as malicious threats, which causes issues during GitHub commits and repository pushes. The complete conceptual methodology, step-by-step approach, and mechanical understanding are fully documented here — sufficient to understand, reproduce, and explain every technique covered.

---

## 1. What We Did Today Overview

Three labs completed on PortSwigger Web Security Academy:

| Lab | Type | Detection Method |
|-----|------|------------------|
| **Lab 1** | OS command injection, simple case | Visible output in HTTP response |
| **Lab 2** | Blind OS command injection with time delays | Side-channel confirmation only (response timing) |
| **Lab 3** | Blind OS command injection with output redirection | File-based exfiltration to web-accessible directory |

Two additional labs are documented in Section 10 (not completed — require Burp Professional).

---

## 2. The Foundation (Deep Dive)

### 2.1 What This Technology Is Actually For

Web applications often need to interact with the underlying operating system. Legitimate use cases include:

- Checking product stock by running a backend shell script
- Converting images using tools like ImageMagick
- Sending emails via the system mail command
- Running network diagnostics such as ping or nslookup
- Generating reports or performing backups

Developers implement these features by calling OS commands from application code — standard engineering practice when the application must leverage existing system utilities rather than reimplementing them.

### 2.2 The Exact Developer Assumption That Breaks

The developer assumes that any data supplied by the user will be **simple, safe values** such as a numeric ID, and will **never contain characters that have special meaning to the shell**. They treat user input as passive data rather than as text that will be parsed and executed by a command interpreter.

This is called the **data-as-code assumption** — the developer writes code that builds a command string from user input, assuming the input will always remain "data." But the shell has no concept of the developer's intention. It parses the **entire string** — developer-written parts and user-supplied parts — using the same syntax rules. If the user's input contains shell syntax characters, the shell obeys them.

> **Key Insight:** The vulnerability does not exist because the developer "forgot" to validate input. It exists because the developer chose an architecture where user-supplied data and executable instructions **occupy the same string** with no enforced boundary between them.

### 2.3 The Mechanical Explanation — How the Shell Parses the Attack

Most vulnerable code follows this pattern:

```python
command = f"check_stock.sh {product_id} {store_id}"
subprocess.run(command, shell=True)
```

When `shell=True` is used (or equivalent functions like `system()`, `exec()`, `shell_exec()` in other languages), the entire string is passed to `/bin/sh` for parsing.

#### What Happens Inside the Shell — Step by Step

```
Developer intends:    check_stock.sh  42  1
                      ↑ program       ↑ arg1  ↑ arg2
                      (all treated as one command)

Attacker sends:       product_id = "42; whoami"

Shell receives:       check_stock.sh 42; whoami 1

Shell parses:         Command 1: check_stock.sh 42
                      Separator: ;
                      Command 2: whoami 1

Shell executes:       → check_stock.sh 42  (runs, may fail due to missing arg)
                      → whoami 1           (runs, prints username)
```

The shell has its own syntax rules. Certain characters act as command separators, redirectors, and operators. When an attacker embeds any of these characters in user input, the shell treats everything after them as a new, separate command to execute.

The operating system has no concept of the developer's original intention. It executes whatever the shell decides to run after parsing the full string.

#### Common Shell Metacharacters Used in Injection

| Character | Shell Meaning | Injection Effect |
|-----------|--------------|------------------|
| `;` | Command separator | Ends current command, starts a new one |
| `&` | Background execution | Runs injected command in background |
| `&&` | Logical AND | Runs injected command if first succeeds |
| `\|\|` | Logical OR | Runs injected command if first fails |
| `\|` | Pipe | Pipes output of first command into injected command |
| `` ` `` | Command substitution | Executes enclosed command, substitutes output |
| `$()` | Command substitution | Same as backticks, modern syntax |
| `>` | Output redirection | Writes command output to a file |
| `#` | Comment | Ignores everything after this on the line |

### 2.4 Real Life Analogy

Imagine a hotel concierge who reads every guest request exactly as written to the kitchen staff. A normal guest writes "one large pizza" and the kitchen prepares it.

An attacker writes: "one large pizza; also unlock room 402 and bring me the cash from the drawer." The concierge has no mechanism to distinguish where the legitimate order ends and the malicious instruction begins. The kitchen executes everything. The system fails because there is no enforced boundary between data and instructions.

**Why the analogy works precisely:** The concierge is the shell interpreter. The written note is the concatenated command string. The semicolon is the shell metacharacter. The kitchen staff is the OS kernel executing whatever it is told. The "no mechanism to distinguish" is the absence of parameterized command execution.

### 2.5 Three Required Conditions for Exploitation

For OS command injection to be exploitable, **all three** conditions must be true:

| # | Condition | What It Means | How to Verify |
|---|-----------|---------------|---------------|
| 1 | **User input reaches an OS command** | The application constructs and executes an OS command that includes user-controlled input | Identify parameters that trigger backend operations (stock checks, email sending, file processing) |
| 2 | **The command is passed to a shell interpreter** | The full command string is passed to `/bin/sh` or equivalent for parsing (e.g., `shell=True`, `system()`, `exec()`) | Inject a benign shell metacharacter and observe if behavior changes |
| 3 | **No filtering or escaping of metacharacters** | Shell metacharacters in the user input reach the shell without being stripped, escaped, or blocked | Test with known separators (`;`, `&`, `|`) and observe for evidence of execution |

> **Important:** If any one of these conditions is missing, command injection cannot be exploited. For example, if the developer passes arguments as a list instead of a string (`shell=False`), condition 2 is eliminated, and metacharacters have no effect.

### 2.6 What It Can and Cannot Achieve

**Can achieve:**
- Run arbitrary commands with the privileges of the web server process
- Read sensitive files accessible to the web server user (passwords, configs, keys)
- Write files including persistent backdoors (webshells) to writable directories
- Establish reverse shells for interactive access
- Perform internal network reconnaissance from the server's network position

**Cannot achieve:**
- Escalate beyond the OS privileges of the web server process without a separate vulnerability
- Directly compromise the visitor's browser (this is a server-side vulnerability)
- Bypass strong containerization or mandatory access controls without additional flaws

### 2.7 One Real World Case

**Shellshock (CVE-2014-6271)** was a command injection vulnerability in the Bash shell itself. Attackers could execute arbitrary commands by embedding them in environment variables sent to CGI scripts. It affected millions of servers worldwide and was actively exploited within hours of public disclosure. On bug bounty platforms, confirmed RCE via command injection is almost universally rated **Critical** with the highest payout tier.

### 2.8 The Three Scenarios of Command Injection

Understanding the three output scenarios is critical because the detection and exfiltration method changes entirely depending on what the attacker can observe:

```
Scenario 1: VISIBLE OUTPUT
  Attacker sends injection → Server executes → Output returned in HTTP response
  Detection: Trivial (read the response)
  Data retrieval: Direct

Scenario 2: BLIND (No Output)
  Attacker sends injection → Server executes → Response contains NO output
  Detection: Time-based (inject sleep, measure delay)
  Data retrieval: File redirection OR out-of-band

Scenario 3: FULLY BLIND (No Output, No Timing, No Write Access)
  Attacker sends injection → Server executes → No observable difference
  Detection: Out-of-band (DNS/HTTP callback)
  Data retrieval: Out-of-band (encode data in DNS subdomain)
```

> **Key Insight:** Most real-world command injection is blind. Developers rarely display raw command output in HTTP responses. The ability to confirm and exfiltrate without visible output is what separates theoretical knowledge from practical exploitation skill.

---

## 3. Labs Completed

### Lab 1: OS command injection, simple case

**Goal:** Execute a command and observe its output directly in the HTTP response.

#### Identifying the injection point

1. Opened the shop application and browsed to any product page.
2. Clicked "Check stock" — this sends a POST request to `/product/stock`.
3. Intercepted the request in Burp Suite. The request body contains two parameters: `productId` and `storeId`.
4. Both values are passed by the backend directly into a shell script as command-line arguments, with no validation or sanitization applied.

#### Exploiting the injection

5. Modified the `productId` value: kept a valid numeric value, then appended a shell command separator character (semicolon), then appended the `whoami` command which prints the username of the process currently executing.
6. Left `storeId` at a valid value so the HTTP request remained structurally intact.
7. Forwarded the modified request.

#### Observing the result

8. The HTTP response contained two things simultaneously:
   - Error messages from the original shell script, whose argument structure our injection had disrupted
   - The output of the injected `whoami` command — the username under which the web server was running

**Why this worked:** The backend concatenated our input directly into a command string and passed the full string to the shell. The semicolon separator caused the shell to treat everything after it as an entirely new command. Because the application captured and returned all shell output, we could see the injected command result directly in the response body.

**Key insight from the error messages:** The response included Bash errors about an "unbound variable." Rather than concealing the injection, these were useful confirmation — they showed that our input had disrupted the intended command flow and that the shell had processed our injected command as a separate execution.

---

### Lab 2: Blind OS command injection with time delays

**Goal:** Confirm command execution when the application returns no output, using response time as the only observable signal.

#### Identifying the injection point

1. Navigated to the feedback submission form.
2. Intercepted the POST request in Burp Suite. Parameters in the body: `csrf`, `name`, `email`, `subject`, `message`.
3. The `email` field is passed by the backend through an OS command.

#### Exploiting the injection

4. Modified the `email` field: appended a shell command separator (ampersand), then the `sleep 10` command which instructs the OS to pause the current process for 10 seconds, then a shell comment character to neutralize any trailing input the backend might append after our injection.
5. Forwarded the modified request and began timing the response.

#### Observing the result

6. The response arrived after approximately **10 seconds** — far longer than the normal sub-second response time.
7. The response body was an empty JSON object — completely uninformative on its own.
8. The timing delay was the only confirmation signal, and it was definitive.

#### Why Each Decision Mattered

| Decision | Reasoning |
|----------|-----------|
| **Why `sleep 10` specifically?** | 10 seconds is long enough to distinguish from normal latency but short enough to not trigger server timeouts. A 1-second sleep might be mistaken for network lag. |
| **Why the comment character at the end?** | The backend may append additional characters after our injection point. The shell comment character causes the shell to ignore everything that follows it on the same line, preventing syntax errors that could stop our injected command from executing. |
| **Why ampersand as the separator?** | Different separators work in different contexts. The ampersand runs the preceding command in the background, but the critical behavior is that it **terminates** the first command and lets the shell parse what follows as new instructions. |

**What this proved and what it did not:** A 10-second response delay confirmed with certainty that the injected sleep command reached the shell and was executed. This proved the injection point is real and functional. It did **not** yet give us any ability to retrieve actual data from the server.

---

### Lab 3: Blind OS command injection with output redirection

**Goal:** Retrieve actual data from a blind injection point by writing command output to a web-accessible file, then fetching that file over HTTP.

#### Identifying the injection point and output location

1. Same feedback form as Lab 2. Injection point: the `email` field.
2. The application serves static image files from the directory `/var/www/images/` via the endpoint `/image?filename=`.
3. This directory is writable by the web server process and accessible via HTTP — making it the ideal location to write exfiltrated data.

#### Exploiting the injection

4. Modified the `email` field: injected a logical-OR command separator, then the `whoami` command, then an output redirection operator pointing to `/var/www/images/output.txt`, then a trailing separator to cleanly end the injection and prevent parse errors from any backend-appended characters.
5. Forwarded the request. The application returned a normal response with no visible indication of what occurred on the server.

#### Retrieving the exfiltrated data

6. Sent a separate GET request to `/image?filename=output.txt`.
7. The server returned the file contents: `peter-pD7Ftb` — the username of the running web server process.

#### Why Each Decision Mattered

| Decision | Reasoning |
|----------|-----------|
| **Why logical-OR (`\|\|`) over a semicolon?** | The logical-OR operator executes the second command even if the preceding command fails. Since our injection disrupts the original command's argument structure causing it to fail, logical-OR ensures our injected command still runs reliably regardless. |
| **Why `/var/www/images/`?** | This directory satisfies two critical requirements: (1) writable by the web server process, and (2) accessible over HTTP via the `/image?filename=` endpoint. Redirecting output to a non-web-accessible path writes the file successfully but leaves it unreadable via HTTP. |
| **Why a two-step attack?** | Step 1 writes the data to disk. Step 2 retrieves it. This is necessary because blind injection gives us no way to see the output directly — we must store it somewhere we can access independently. |

**Why this is fundamentally more powerful than Lab 2:** Lab 2 could only confirm that injection occurred. Lab 3 retrieves actual data by redirecting command output to a location we can subsequently read over HTTP. This is the transition from **injection confirmation** to **full data exfiltration**.

**What this proved:** The username appeared in the HTTP response, confirming that complete data exfiltration is achievable in a blind injection scenario whenever a writable web-accessible directory is available.

---

## 4. Vulnerable Source Code — Analysis

Representative vulnerable pattern matching the behavior observed in these labs:

```python
import subprocess

def check_stock(product_id, store_id):
    command = f"check_stock.sh {product_id} {store_id}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
```

**Line-by-line breakdown:**

`command = f"check_stock.sh {product_id} {store_id}"`
- **What it does:** Concatenates user-supplied values directly into a shell command string using Python f-string formatting.
- **Why it is dangerous:** Any shell metacharacters embedded in the input will be interpreted as instructions by the shell parser, not treated as literal argument text. The user's input becomes part of the **code**, not just the **data**.

`subprocess.run(command, shell=True, ...)`
- **What it does:** Passes the entire concatenated string to `/bin/sh` for parsing and execution.
- **Why it is the root cause:** The `shell=True` flag is the single decision that enables command injection. It tells Python to spawn a shell process and hand it the command string for interpretation. Removing it and passing arguments as a list invokes the program directly via `execve()`, bypassing the shell entirely.

> **Foundation Principle:** The vulnerability is architecturally identical to SQL injection — in both cases, untrusted input is concatenated into a string that is subsequently parsed by an interpreter (shell or SQL engine). The fix is also identical in principle: **use parameterized execution** that separates data from instructions.

---

## 5. What Failed and Why

| What Failed | Why It Failed | What Fixed It |
|-------------|--------------|---------------|
| Tested injection in the wrong parameters | Not all parameters are passed to OS commands — only specific ones reach the shell | Systematically tested each field in the request body to identify the vulnerable one |
| Lab 2 inconsistent without comment character | Backend appended trailing characters that broke shell syntax after our injection | Adding the trailing comment character (`#`) neutralized any backend-appended characters |
| Lab 3 initially considered wrong output directory | Not all directories are both writable AND web-accessible | Identified `/var/www/images/` as satisfying both requirements |

---

## 6. Chain Thinking

```
Stage 1 — Confirm injection (Labs 1 & 2)
    │   Prove that user-controlled input reaches the shell and is executed.
    │   Visible output or timing delays provide this confirmation.
    ▼
Stage 2 — Retrieve data (Lab 3)
    │   Write command output to a web-accessible location and retrieve it
    │   via HTTP. Gives read access to anything the web process user can
    │   access on the filesystem.
    ▼
Stage 3 — Write a persistent backdoor
    │   Use the injection to write a webshell to a web-accessible directory.
    │   A webshell is a small server-side script that accepts HTTP requests
    │   and executes OS commands, providing ongoing interactive access without
    │   needing to re-exploit the original injection point each time.
    ▼
Stage 4 — Read configuration files
    │   Use file read access to extract database credentials, API keys, and
    │   environment variables from application configuration files. These are
    │   frequently stored as plaintext and readable by the web server process.
    ▼
Stage 5 — Lateral movement
        Use harvested credentials to connect to databases, internal APIs, or
        other infrastructure reachable from the compromised server's network
        position.
```

---

## 7. Real World Context

OS Command Injection directly grants code execution on the server — equivalent to logging in as the web server user. On bug bounty platforms, confirmed RCE via command injection is almost universally **Critical** with the highest payout tier. **Shellshock (CVE-2014-6271)** is the canonical real-world example: a Bash vulnerability exploitable via environment variables in CGI scripts that affected millions of servers and was exploited at mass scale within hours of public disclosure.

---

## 8. The Fix — Full Technical Breakdown

### Vulnerable pattern:

```python
command = f"check_stock.sh {product_id} {store_id}"
subprocess.run(command, shell=True)
```

### Secure pattern:

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

### Why the fix works — line by line:

1. **Input validation (`isdigit()`)** — Whitelist validation ensures only expected characters reach the command. Even if the next layer fails, this stops metacharacters at the door.

2. **Arguments as a list (`["check_stock.sh", product_id, store_id]`)** — Each element is passed as a separate argument directly to the program via `execve()`. No shell process is spawned, no shell parsing occurs, and metacharacters embedded in arguments have absolutely no effect — they are passed as literal strings to the program.

3. **`shell=False`** — Explicitly disables shell interpretation. Python calls the program directly via the OS `execve()` system call, which takes a list of arguments and passes them to the target program without any intermediate parsing.

> **Foundation Principle:** This is the same principle as parameterized SQL queries. In SQL injection, you fix it with prepared statements that separate SQL code from data. In command injection, you fix it by passing arguments as a list (separating the command structure from the data).

### Defense in depth:

| Layer | Defense | What It Prevents |
|-------|---------|------------------|
| **Input validation** | Whitelist-validate all input used in any OS command before it is used | Metacharacters reaching the command at all |
| **Parameterized execution** | Pass arguments as a list with `shell=False` — never concatenate into a string | Shell interpretation of metacharacters |
| **Least privilege** | Run the web application with the minimum OS permissions it needs | Limits damage if injection occurs despite other defenses |
| **Library alternatives** | Prefer language library alternatives to shell commands wherever possible | Eliminates the need for OS command execution entirely |
| **WAF** | Use WAFs as a secondary detection layer, never as a primary defense | Catches known attack patterns as a safety net |

---

## 9. Key Concepts Summary

| Concept | Description | Why It Matters |
|---------|-------------|----------------|
| **Visible vs Blind** | Direct output vs side-channel confirmation required | Most real-world cases are blind — the skill gap is in blind detection |
| **Time-based detection** | Injecting a sleep instruction for a measurable delay | Only confirmation method when no output and no write access |
| **Output redirection** | Writing command output to a web-accessible file | Converts blind injection to full data exfiltration |
| **`shell=True`** | Passes command string to a shell interpreter for parsing | The root cause that enables metacharacter interpretation |
| **Shell metacharacters** | Characters with special meaning to the shell (`;`, `&`, `|`, etc.) | The attack vector — these transform data into instructions |
| **Out-of-band exfiltration** | DNS or HTTP callbacks to an attacker-controlled server | Works in fully blind, no-write-access scenarios |
| **Data-as-code confusion** | User input occupying the same string as executable instructions | The fundamental architectural flaw behind all injection vulnerabilities |

---

## 10. Related Labs (Not Completed This Session)

### Lab 4: Blind OS command injection with out-of-band interaction

**What makes this scenario different:**
No response-timing side-channel exists because the application processes the feedback submission asynchronously. There is also no writable web-accessible directory available. The only way to confirm injection is through an out-of-band channel — typically a DNS callback to an external server the tester controls.

**Tool required:** Burp Suite Professional (Burp Collaborator). Not available in Community Edition.

**Step-by-step approach:**

1. Open Burp Suite Professional and navigate to the Burp Collaborator client tab.
2. Click "Copy to clipboard" to generate a unique Collaborator payload — a unique subdomain under a domain that Burp actively monitors for incoming DNS and HTTP interactions.
3. Navigate to the feedback submission form and intercept the POST request in Burp.
4. Modify the `email` parameter: inject a command separator followed by a DNS lookup command (nslookup) targeting the Collaborator subdomain generated in step 2.
5. Forward the request. The application returns a normal response with no visible indication of what occurred.
6. Switch back to the Collaborator client tab and click "Poll now" to check for incoming interactions.
7. A DNS interaction originating from the target server's IP address confirms that the injected command executed on the server.

**Why DNS over HTTP for out-of-band detection:**
Outbound DNS traffic is permitted in virtually every server environment because DNS is required for all normal server operation. Outbound HTTP is frequently blocked or restricted by egress firewall rules. DNS-based detection is therefore the most reliable out-of-band technique across diverse environments.

**What this proves:** Injection is confirmed even with no visible output and no filesystem write access available.

---

### Lab 5: Blind OS command injection with out-of-band data exfiltration

**What makes this different from Lab 4:**
Lab 4 only proves that injection is possible. Lab 5 demonstrates actually recovering data — the server's running username — by encoding the command output directly into the DNS subdomain of the out-of-band request.

**Tool required:** Burp Suite Professional (Burp Collaborator).

**Step-by-step approach:**

1. Generate a Collaborator payload as in Lab 4.
2. Navigate to the feedback submission form and intercept the POST request.
3. Modify the `email` parameter: inject a command separator, then a chained command that first runs `whoami` to get the username, and uses command substitution to embed its output as a subdomain prefix in an nslookup call to the Collaborator domain. The DNS request arriving at Collaborator will have the format `<command-output>.<collaborator-domain>`.
4. Forward the request. The application returns a normal response.
5. Poll the Collaborator client for interactions.
6. Inspect the subdomain of the incoming DNS request — it contains the output of the `whoami` command, which is the username of the web server process.

**Why this is the most powerful exfiltration technique:**
This method works even when the server:
- Returns no output in the HTTP response (fully blind)
- Has no response-time variation to exploit (no timing side-channel)
- Has no writable web-accessible directory (no file redirection possible)
- Has all outbound HTTP blocked by firewall rules

As long as outbound DNS is permitted — which it is in almost every environment — data can be successfully exfiltrated through the DNS channel.

**Alternative for Community Edition users:**
Burp Collaborator requires Professional. The open-source tool `interactsh` by ProjectDiscovery provides similar out-of-band interaction detection and is free to use. Suitable for learning and practicing the OOB technique in lab environments.

---

## 11. Foundation Checklist

### Conceptual Understanding
- [ ] Can you explain why `shell=True` is dangerous even when the input value appears to be a simple integer?
- [ ] What is the "data-as-code confusion" and how does it relate to both SQL injection and command injection?
- [ ] If a developer validates that input "contains only digits," can you identify an edge case in a different context where digit-only input could still be dangerous?
- [ ] What is the fundamental difference between passing OS command arguments as a list versus as a single concatenated string?

### Technical Understanding
- [ ] Why does writing output to a file sometimes succeed as an exfiltration method when timing-based detection is unreliable?
- [ ] If you observe a 10-second response delay after injecting a 10-second sleep instruction, what exactly have you proven — and what have you NOT yet proven?
- [ ] Why is out-of-band exfiltration via DNS more reliable than HTTP in restricted network environments?
- [ ] What is the role of the shell comment character at the end of an injection, and what specific problem does it solve?

### Practical Understanding
- [ ] Name the three required conditions for OS command injection to be exploitable.
- [ ] Explain why logical-OR (`||`) is sometimes preferred over semicolon (`;`) as a command separator during injection.
- [ ] How do you transition from blind injection confirmation (time delay) to actual data exfiltration?
- [ ] Why is the fix for command injection architecturally identical to the fix for SQL injection?

---
