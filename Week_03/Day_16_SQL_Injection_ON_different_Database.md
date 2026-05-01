# Day 16 — PortSwigger SQLi: Database Fingerprinting + Contents Listing

**Date:** April 29, 2026
**Platform:** PortSwigger Web Security Academy  
**Topic:** Database version detection, information_schema enumeration, single column extraction  
**Labs Completed:** 4 (Lab 6, 7, 8, 9)  

---

## Foundation — Why This Matters

Until Day 15, you already knew the database name, table structure, or had hints. On a real target you get nothing. You don't know if it's MySQL, Oracle, or PostgreSQL. You don't know any table names. You don't know any column names.

Tonight you learned how to go from **zero knowledge to full admin access** using only SQL injection — by making the database tell you its own structure.

This is the real attack chain. Everything from Day 8 onwards was building toward this.

---

## Core Concept 1 — Databases Speak Different Dialects

SQL is a standard but every database implements it differently. A payload that works perfectly on MySQL will throw an error on Oracle. Before you can exploit anything you need to know what database you are talking to.

### Syntax differences that matter for SQLi

| What you want | Oracle | MySQL | PostgreSQL |
|---|---|---|---|
| Database version | `SELECT banner FROM v$version` | `SELECT @@version` | `SELECT version()` |
| String concatenation | `'a'||'b'` | `CONCAT('a','b')` | `'a'||'b'` |
| Dummy table | `FROM dual` (mandatory) | not needed | not needed |
| Comment character | `--` | `#` or `-- ` (space after) | `--` |

### Why Oracle needs FROM dual

In Oracle, every single SELECT statement must have a FROM clause. This is not optional — it is a core rule of Oracle SQL syntax.

`dual` is a special built-in dummy table in Oracle. It has one row and one column. It exists purely to satisfy this FROM requirement when you do not actually need data from a real table.

So on Oracle you cannot write:
```sql
SELECT NULL
```
You must write:
```sql
SELECT NULL FROM dual
```

On MySQL and PostgreSQL this rule does not exist. `SELECT NULL` works fine.

---

## Core Concept 2 — What is information_schema

`information_schema` is a built-in database that exists inside every MySQL, PostgreSQL, and Microsoft SQL Server installation. It is a complete map of the entire database system.

Think of it as the database's own documentation — it lists every database, every table, every column, every data type. It was designed for administrators to inspect their database structure. As an attacker you use it to enumerate everything without guessing.

**Oracle does not have information_schema.** Oracle uses `all_tables` and `all_columns` instead.

### Two tables you use in every attack

**information_schema.tables**  
Lists every table in the database.  
The column you want: `table_name`

```sql
SELECT table_name FROM information_schema.tables
```

**information_schema.columns**  
Lists every column in every table.  
The columns you want: `table_name`, `column_name`

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='target_table'
```

You always query `tables` first to find the table name, then `columns` to find the column names inside that table. You need the table name first because `information_schema.columns` holds columns from every table — without filtering by `table_name` you get thousands of rows of noise.

---

## Core Concept 3 — Single Column Concatenation

Sometimes the vulnerable query only displays one column on the page. You need to extract two values — username and password — but you only have one slot.

The solution is to concatenate both values into a single string with a separator character between them.

**PostgreSQL and Oracle syntax:**
```sql
username||'~'||password
```

**MySQL syntax:**
```sql
CONCAT(username,'~',password)
```

The `~` is just a separator you choose. It should be a character unlikely to appear in usernames or passwords so you can split cleanly. Output will look like:

```
administrator~s3cur3password
```

Left of `~` is username. Right of `~` is password.

---

## Lab 6 — Database Version Detection on Oracle

**Goal:** Identify that the database is Oracle and extract its version string by making it appear in the product listing.

---

### Step 1 — Confirm the injection point

```
'
```

**What this does:** A single quote closes the string that the application opens around your input. If the database receives an unbalanced quote it throws a syntax error. An error or changed behavior confirms the parameter is injectable.

**What to look for:** An error message, a blank page, or different output compared to normal.

---

### Step 2 — Count the columns

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

**What ORDER BY does:** It tells the database to sort results by a column number. Column 1 means sort by the first column, column 2 means sort by the second column.

**Why you use it to count columns:** If you say `ORDER BY 3` and the query only has 2 columns, the database throws an error — you cannot sort by a column that does not exist. So you increment the number until you get an error. Error on 3 means you have 2 columns.

**Why this works better than UNION NULL at this stage:** ORDER BY does not require you to match data types. It just sorts. So it gives you a clean column count before you start building UNION payloads.

---

### Step 3 — Find which column displays text

```sql
' UNION SELECT 'a',NULL FROM dual--
' UNION SELECT NULL,'a' FROM dual--
```

**What this does:** UNION appends a second result set to the original query. You put the string `'a'` in one position and NULL in the other. Whichever position shows `a` on the page is the column that accepts and displays text.

**Why FROM dual is here:** Oracle requires it. Without `FROM dual` Oracle throws an error and the payload fails completely.

**Why NULL in the other position:** NULL is compatible with any data type. If the other column expects a number and you put a string there the query errors. NULL avoids that.

---

### Step 4 — Extract the Oracle version

```sql
' UNION SELECT banner,NULL FROM v$version--
```

**Breaking this down piece by piece:**

- `'` — closes the original string in the query
- `UNION SELECT` — appends your own SELECT statement to the original query
- `banner` — the column inside `v$version` that holds the version string
- `NULL` — placeholder for the second column, type-safe
- `FROM v$version` — Oracle's built-in view that stores version information
- `--` — comments out the rest of the original query so it does not cause errors

**Result:** The Oracle version string appeared in the product listing instead of a product name.

---

## Lab 7 — Database Version Detection on MySQL

**Goal:** Same as Lab 6 but the database is MySQL. Different syntax required.

---

### Step 1 — Count columns

```sql
' ORDER BY 2#
```

**Why `#` instead of `--`:** MySQL accepts both `#` and `-- ` (with space) as comment characters. On PortSwigger labs `#` is more reliable for MySQL because `-- ` sometimes needs URL encoding. Oracle and PostgreSQL do not recognize `#` as a comment — using it on the wrong database breaks your payload silently.

---

### Step 2 — Extract the version

```sql
' UNION SELECT @@version,NULL#
```

**Breaking this down:**

- `@@version` — a global system variable in MySQL and Microsoft SQL Server that holds the database version. It is not a column from a table — it is a variable that MySQL maintains internally
- Because it is a global variable and not a table column, it works in any column position — MySQL does not care where you place it
- `NULL` — placeholder for second column
- `#` — MySQL comment character, discards the rest of the original query

**Key finding from this lab:** `@@version` worked in both column positions. This is because global variables in MySQL are not bound to a specific column or table — they resolve to a value anywhere in a SELECT list.

**Result:** Lab marked complete. MySQL version string returned successfully.

---

## Lab 8 — Listing Database Contents on Non-Oracle

**Goal:** Extract admin credentials with zero prior knowledge. No table names given, no column names given. Start from nothing.

This is the most important lab of Day 16. This is the real attack chain.

---

### Step 1 — Count columns

```sql
' ORDER BY 2--
```

Same process as previous labs. Error on 3 means 2 columns.

---

### Step 2 — Dump all table names

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**Breaking this down:**

- `table_name` — the column inside `information_schema.tables` that holds each table's name
- `NULL` — placeholder for second column
- `FROM information_schema.tables` — querying the metadata table that lists every table in the database

**What happens:** Every table name in the entire database appears in the product listing. You scroll through looking for anything that sounds like it stores users — words like `users`, `accounts`, `members`, `admin`, `credentials`.

**What you found:** `users_qchamx` — randomized name, but the `users` prefix makes it identifiable.

PortSwigger randomizes table and column names on purpose. On a real target names might be obvious or completely cryptic. You always enumerate — never assume.

---

### Step 3 — Dump column names for the target table

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_qchamx'--
```

**Breaking this down:**

- `column_name` — the column inside `information_schema.columns` that holds each column's name
- `FROM information_schema.columns` — the metadata table listing every column in every table
- `WHERE table_name='users_qchamx'` — filtering to only show columns belonging to your target table. Without this filter you get every column from every table — thousands of rows of noise

**What you found:** `username_iuwsvu`, `password_wnjocc` — both randomized, both clearly identifiable by meaning.

---

### Step 4 — Extract credentials

```sql
' UNION SELECT username_iuwsvu,password_wnjocc FROM users_qchamx--
```

**Breaking this down:**

- `username_iuwsvu` — the actual column name you discovered in Step 3
- `password_wnjocc` — the actual column name you discovered in Step 3
- `FROM users_qchamx` — the actual table name you discovered in Step 2

**Result:** `administrator:fnf0fpo6xw5kku3d1go1`

**What this demonstrated:** Zero knowledge to full admin access in 4 payloads. No guessing, no prior information needed. `information_schema` handed you the entire database structure.

---

## Lab 9 — Multiple Values in a Single Column

**Goal:** Only one column displays text. Extract both username and password through that single column using concatenation.

---

### Step 1 — Count columns

```sql
' ORDER BY 2--
```

2 columns confirmed.

---

### Step 2 — Identify text column

Tried both positions. Column 2 accepted text.

---

### Step 3 — Dump table names

```sql
' UNION SELECT NULL,table_name FROM information_schema.tables--
```

NULL in position 1 because column 1 does not display text. `table_name` in position 2 because that is the text column.

**What you found:** Table named `users`.

---

### Step 4 — Dump column names

```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
```

**What you found:** `email`, `username`, `password`

Three columns returned. You only needed two. On a real target column dumps return many results — identify what is relevant and ignore the rest. `email` is not useful for login. `username` and `password` are.

---

### Step 5 — Concatenate two values into one column

```sql
' UNION SELECT NULL,username||'~'||password FROM users--
```

**Breaking this down:**

- `username` — first value you want
- `||` — concatenation operator in PostgreSQL and Oracle. Joins strings together
- `'~'` — your separator character. Chosen because it is unlikely to appear in a username or password
- `||` — second concatenation
- `password` — second value you want
- `FROM users` — the table containing both columns

**Why this works:** The database joins all three parts into a single string before returning it. The application sees one value per row and displays it in the one text column available.

**Result:** `administrator~83kwdryr9fkkscbwqpva`

Split on `~`:
- Username: `administrator`
- Password: `83kwdryr9fkkscbwqpva`

---

## Vulnerable Code — Why All of This Works

A typical vulnerable backend looks like this:

```php
$category = $_GET['category'];
$query = "SELECT name, description FROM products WHERE category = '" . $category . "'";
$result = mysqli_query($conn, $query);
```

No sanitization. Your input goes directly into the SQL query as a string.

When you inject `' UNION SELECT username,password FROM users--` the database receives:

```sql
SELECT name, description FROM products WHERE category = '' 
UNION SELECT username, password FROM users--'
```

The original query returns zero results because category is empty string. Your UNION appends the full users table. The application displays both result sets — your injected data appears exactly where product names normally appear.

The application has no idea it is displaying database credentials instead of product names. It just runs the query and renders whatever comes back.

---

## Chain Thinking

**Scenario:** You land on a real target. There is SQLi in a search parameter. You know nothing — no database type, no table names, no column names. Walk through every step.

**Step 1 — Confirm injection**  
Add `'` to the parameter. Look for an error, blank page, or behavior change. If the page breaks — you have injection.

**Step 2 — Count columns**  
`ORDER BY 1`, `ORDER BY 2`, increment until error. Error on N means N-1 columns.

**Step 3 — Find text column**  
`UNION SELECT 'a',NULL`, then `UNION SELECT NULL,'a'`. Whichever shows `a` on the page is your text column.

**Step 4 — Fingerprint the database**  
Try `@@version` for MySQL, `banner FROM v$version` for Oracle, `version()` for PostgreSQL. Whichever works tells you the database. Now you know which syntax to use for everything that follows.

**Step 5 — Dump table names**  
`UNION SELECT table_name,NULL FROM information_schema.tables` on MySQL/PostgreSQL. Look for user-related table names.

**Step 6 — Dump column names**  
`UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='target'`. Identify username and password columns.

**Step 7 — Extract credentials**  
`UNION SELECT username,password FROM target`. Read admin credentials from the page.

**Step 8 — Log in as admin**  
Use extracted credentials to access the admin panel.

**Step 9 — What next**  
Admin access opens further attack paths. If the application has file upload — chain with webshell for RCE. If it has password reset — chain with account takeover. If it runs on a server with other applications — pivot.

**Combined impact:** SQLi → credential extraction → admin login → potential RCE if chained with file upload

---

## Foundation Checklist

**1. Why does Oracle need FROM dual?**  
Oracle syntax requires every SELECT statement to have a FROM clause. `dual` is a built-in dummy table with one row that satisfies this requirement without pulling real data. No other major database enforces this rule.

**2. What is information_schema and which databases have it?**  
A built-in metadata database listing every table and column in the system. Available in MySQL, PostgreSQL, and Microsoft SQL Server. Oracle does not have it — Oracle uses `all_tables` and `all_columns` instead.

**3. What is the difference between @@version and version()?**  
`@@version` is a global system variable in MySQL and Microsoft SQL Server. `version()` is a function in PostgreSQL. Both return the database version string but they only work on their respective databases — using the wrong one on the wrong database returns nothing or errors.

**4. Why do you dump table names before column names?**  
`information_schema.columns` contains every column from every table in the database. Without filtering by `table_name` you get thousands of rows from system tables and your target mixed together. You need the exact table name first so you can filter the column dump to only the table you care about.

**5. How do you extract two values from one column?**  
Concatenate them with a separator using `||'~'||` on PostgreSQL and Oracle, or `CONCAT(a,'~',b)` on MySQL. The database joins them into one string. You split on the separator character when reading the output to separate the two values.

**6. What comment syntax does MySQL use vs Oracle?**  
MySQL uses `#` or `-- ` with a mandatory space after the dashes. Oracle uses `--`. Using the wrong comment syntax means the rest of the original query is not commented out — it gets appended to yours and causes a syntax error. This breaks payloads silently which makes it hard to debug.

---

## Real World Context

`information_schema` enumeration is exactly what sqlmap runs under the hood. When you ran `sqlmap --dump` on Day 10 — this is the query chain it was executing automatically. Today you ran it manually.

Understanding the manual process matters because:
- sqlmap gets blocked by WAFs (Web Application Firewalls) — manual payloads can be crafted to bypass them
- sqlmap leaves noisy logs — manual injection can be done more carefully
- In a bug bounty report you need to explain the exact payload chain — you cannot just say "sqlmap found it"
- In a job interview you will be asked to walk through this manually

Randomized table and column names like `users_qchamx` appear on real targets too. Applications sometimes use non-obvious naming conventions, ORM-generated names, or deliberately obfuscated schemas. Always enumerate. Never assume you know the table name.

---

