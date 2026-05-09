# Day 21 — IDOR + Access Control
**Date:** May 9, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 9 Apprentice Labs
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was entirely focused on IDOR (Insecure Direct Object Reference) and Access Control vulnerabilities. We completed all 9 Apprentice-level PortSwigger labs covering every major pattern of IDOR — from unprotected admin panels to GUID-based user IDs, cookie manipulation, JSON parameter injection, redirect data leakage, password disclosure, and direct file access. Every lab was solved manually using the browser and Burp Suite with zero automated tools.

---

## 2. The Foundation — Why IDOR Exists

### Root Cause

Developers build applications where users own data — their profile, their orders, their invoices. When a user requests their data, the application retrieves it using an identifier — a user ID, an order number, a filename. The developer writes code that says *"fetch the record with this ID"* and returns it to whoever asked.

The mistake: the developer validates **who you are** (authentication — your session, your cookie) but forgets to validate **whether the object you are requesting belongs to you** (authorization). They assume the client will only ever send their own ID. They never enforce it on the server.

So when you change the ID in the request to someone else's ID — the server fetches their data and hands it to you. No error. No warning. Because as far as the server is concerned — you are logged in, you made a valid request, here is the data.

### Real World Analogy

Imagine a hotel where each guest gets a key card programmed to open Room 204. The front desk verified your identity when you checked in — that is authentication. But the locks on every door only check "is this a valid hotel key card?" — not "is this key card programmed for THIS room?"

So you walk up to Room 205, swipe your Room 204 key card — and the door opens. The lock checked that you are a hotel guest. It never checked if you are Room 205's guest. IDOR is exactly this.

### Three Conditions for IDOR to Exist

1. The application uses a user-controlled identifier to retrieve an object (ID in URL, parameter, body, cookie)
2. The server retrieves the object based on that identifier without checking ownership
3. The object belongs to a different user — meaning access should be denied but is not

### Authentication vs Authorization — The Key Distinction

| Aspect | Authentication | Authorization |
|--------|---------------|---------------|
| Question | Who are you? | What are you allowed to do? |
| What it checks | Your identity (session, cookie, password) | Your permissions (do you own this object?) |
| Failure mode | Logging in as someone else | Accessing someone else's data while logged in as yourself |
| IDOR relates to | ❌ Not authentication | ✅ Authorization |

IDOR happens when authentication is done correctly but authorization is completely missing.

### Horizontal vs Vertical Privilege Escalation

**Horizontal:** Same privilege level — regular user accessing another regular user's data.
Example: wiener accessing carlos's profile.

**Vertical:** Lower privilege gaining higher privilege access.
Example: regular user accessing the admin panel.

Both can be achieved through IDOR. Tonight we exploited both.

### What IDOR Can and Cannot Do

**Can do:**
- Read other users' private data (profiles, messages, invoices, API keys)
- Modify other users' data (email, password, address)
- Delete other users' data or resources
- Escalate to admin privileges when admin functions use predictable IDs

**Cannot do:**
- Bypass authentication on its own — you still need a valid session
- Execute code on the server — that is a different class (RCE)
- Work if the ID is truly unpredictable AND never leaked anywhere

### Real World Example

A researcher on HackerOne found that changing a numeric user ID in a request parameter exposed other users' full account details including email addresses and account settings. The endpoint checked the session cookie (authentication) but never validated that the requested user ID matched the session owner (authorization). Payout: **$950**. Facebook had IDOR on their ads platform exposing advertiser billing information — estimated Critical severity. Bug bounty payouts for IDOR range from **$500 to $30,000** depending on data sensitivity.

---

## 3. Lab Walkthroughs

---

### Lab 1 — Unprotected Admin Functionality ✅

**Vulnerability type:** Vertical privilege escalation — unprotected admin route

**What this lab proves:** An admin panel with no authentication check is directly accessible to any user who discovers the URL. Hiding a URL from search engines is not access control.

**How it was solved:**

Navigated to `/robots.txt` on the lab domain. The `robots.txt` file revealed a disallowed path — the admin panel URL the developer tried to hide from search engines. Navigated directly to that path without any authentication. The admin panel loaded with no login required. Deleted user carlos to solve the lab.

**Why it worked:**

The developer added the admin panel URL to `robots.txt` to prevent Google from indexing it. But `robots.txt` is a public file — anyone can read it. Hiding a URL is not the same as protecting it. The route had no server-side authentication check. Any user who reads `robots.txt` gets the URL and full admin access.

**The vulnerable pattern:**
```
/robots.txt reveals:
Disallow: /administrator-panel

GET /administrator-panel
→ Server returns admin panel to anyone — no session check, no role check
```

---

### Lab 2 — Unprotected Admin Functionality With Unpredictable URL ✅

**Vulnerability type:** Vertical privilege escalation — admin URL leaked in client-side JavaScript

**What this lab proves:** Even when a URL is randomized and not in robots.txt, if it appears in JavaScript sent to the browser — any user can find it by reading page source.

**How it was solved:**

`robots.txt` did not help here — the admin URL was randomized. Opened page source (right-click → View Page Source). Searched for `admin` in the source. Found a JavaScript block that conditionally shows the admin link — the randomized admin URL was hardcoded in that JavaScript. Navigated directly to that URL. Deleted carlos to solve the lab.

**Why it worked:**

The developer randomized the URL thinking it was unguessable — which it is by brute force. But they embedded it in JavaScript that is sent to every user's browser. JavaScript runs client-side. Every user who loads the page receives it. Reading page source costs zero effort and zero privileges.

**Key lesson:** Security through obscurity fails when the secret is sent to the client.

---

### Lab 3 — User Role Controlled by Request Parameter ✅

**Vulnerability type:** Vertical privilege escalation — admin status controlled by user-controlled cookie

**What this lab proves:** When the application trusts a client-controlled cookie to determine admin status — any user can forge that cookie and gain admin access.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. Checked the HTTP response in Burp HTTP History — found a cookie being set with the value `Admin=false`. This means the server is reading the `Admin` cookie from the request to decide authorization level. Opened Firefox DevTools → Storage tab → Cookies → found the `Admin` cookie → changed the value from `false` to `true`. Navigated to `/admin` — the admin panel loaded. Deleted carlos.

**Why it worked:**

The server read the `Admin` cookie value directly from the browser request and trusted it without checking anything server-side. The cookie lives in the browser — the user controls it completely. By changing `Admin=false` to `Admin=true` we told the server "I am an admin" and the server believed us. Authorization was decided by data the attacker controls.

**The vulnerable pattern:**
```
Request:  Cookie: Admin=false; session=abc123
Response: Regular user view

Modified: Cookie: Admin=true; session=abc123  
Response: Admin panel — full access
```

---

### Lab 4 — User Role Can Be Modified in User Profile ✅

**Vulnerability type:** Vertical privilege escalation — mass assignment via JSON parameter injection

**What this lab proves:** When an API endpoint accepts and blindly applies all fields in a JSON request body — an attacker can send unauthorized fields to elevate their own privileges.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. Found the Update Email function in the account settings. Turned Burp Intercept ON and submitted an email update. The request body was JSON:
```json
{"email":"test@test.com"}
```
Added a `roleid` field to the JSON body:
```json
{"email":"test@test.com","roleid":2}
```
Forwarded the modified request. The response showed the updated profile with `roleid: 2` — confirming the server accepted and applied the unauthorized field. Navigated to `/admin` — full admin access granted. Deleted carlos.

**Why it worked:**

The API endpoint deserializes the entire JSON body and applies all fields to the user object — including `roleid` which should only be set by the server, never by the user. The developer failed to whitelist which fields the user is allowed to update. This is called mass assignment — blindly mapping all request parameters to a database object.

**The vulnerable pattern:**
```
Intended:  {"email":"test@test.com"}         → updates email only
Injected:  {"email":"test@test.com","roleid":2} → updates email AND role
Server accepted both — no field whitelist existed
```

---

### Lab 5 — User ID Controlled by Request Parameter ✅

**Vulnerability type:** Horizontal privilege escalation — classic IDOR on user ID in URL

**What this lab proves:** The server fetches user data based on a URL parameter without verifying the parameter matches the logged-in session.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. Clicked My Account — URL was:
```
/my-account?id=wiener
```
Changed the URL parameter to:
```
/my-account?id=carlos
```
The server returned carlos's account page. Found carlos's API key displayed on the page.

**Carlos's API key:**
```
tPztf2HgV471s0BnNvtjizqgy0Ge8L8i
```

Submitted the API key as the solution.

**Why it worked:**

The server received `id=carlos`, queried the database for carlos's record, and returned it to wiener's browser. It never compared the `id` parameter against the session token to verify ownership. Authentication passed (wiener is logged in) but authorization was completely absent (no check that wiener owns the carlos record).

**The vulnerable pattern:**
```python
# Server does this:
user_id = request.GET['id']           # Takes "carlos" from URL
account = db.get_user(user_id)        # Fetches carlos's data
return render(account)                # Returns it to whoever asked

# Server never does this:
if user_id != session.user_id:
    return 403
```

---

### Lab 6 — User ID Controlled by Request Parameter With Unpredictable User IDs ✅

**Vulnerability type:** Horizontal privilege escalation — GUID-based IDOR with ID leaked in blog posts

**What this lab proves:** GUIDs prevent brute force but not IDOR when the ID is disclosed elsewhere in the application.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. The account URL contained a GUID instead of a username — not guessable by brute force. Browsed the blog posts on the site looking for posts authored by carlos. Found a post by carlos. Viewed the page source of that post — found carlos's GUID in the author link:

```html
<p><span id=blog-author><a href='/blogs?userId=6d5f5046-88aa-4c86-ae3a-bb5b79901b8e'>carlos</a></span>
```

Carlos's GUID: `6d5f5046-88aa-4c86-ae3a-bb5b79901b8e`

Navigated to:
```
/my-account?id=6d5f5046-88aa-4c86-ae3a-bb5b79901b8e
```

Got carlos's account page. Found his API key.

**Carlos's API key:**
```
TtFwg2f9q2Bv3sk2e6lJnt3QJvYOzclf
```

**Why it worked:**

The developer used GUIDs thinking unpredictability prevented IDOR. Unpredictability prevents guessing — it does not prevent IDOR when the ID is disclosed in another feature. The blog post author link leaked the GUID. Once you have the ID — IDOR works identically regardless of whether it is numeric or a GUID. The vulnerability is the missing authorization check, not the ID format.

---

### Lab 7 — User ID Controlled by Request Parameter With Data Leakage in Redirect ✅

**Vulnerability type:** Horizontal privilege escalation — sensitive data in redirect response body

**What this lab proves:** The server sends response data AND redirect instruction together. Intercepting the response before the browser follows the redirect reveals data the browser would have discarded.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. Changed the user ID parameter to `carlos`. The browser redirected away — appearing to block access. Intercepted the response in Burp before the browser followed the redirect. The response body contained carlos's full account page including his API key — despite the 302 status code.

**Carlos's API key:**
```
VuviRvuT5uX52Hx1tNSgMrVcdLe5PLST
```

**Why it worked:**

HTTP redirects work like this: the server generates the response body first, then adds a `Location` header and a 302 status code. The browser sees the 302, ignores the body, and navigates to the new URL. But Burp sits between the browser and server — it sees the full response including the body the browser discarded. The developer added a redirect for unauthorized access but forgot that the response body was already populated with the target user's data before the redirect was applied.

**The vulnerable pattern:**
```
Server logic (wrong):
1. Fetch carlos's account data
2. Populate response body with carlos's data   ← data already in response
3. Check: is this wiener's account? No.
4. Add Location header → redirect to home      ← too late, data is in body

Browser: follows redirect, discards body
Burp: sees everything including the body
```

---

### Lab 8 — User ID Controlled by Request Parameter With Password Disclosure ✅

**Vulnerability type:** Horizontal + Vertical privilege escalation — IDOR exposing administrator password

**What this lab proves:** IDOR on a profile page that pre-populates password fields leaks credentials in the HTML source — enabling direct account takeover.

**Credentials used:** `wiener:peter`

**How it was solved:**

Logged in as wiener. Noticed the account page pre-fills the password field (masked in browser UI). Changed the user ID in the URL to `administrator`. The administrator's account page loaded. In Burp — intercepted the response and could clearly see the administrator's password in the response body.

**Administrator's password found in Burp response:**
```
ct4gj1dj4ghjhpfxfrbh
```

Logged out of wiener. Logged in as `administrator` with password `ct4gj1dj4ghjhpfxfrbh`. Navigated to the admin panel. Deleted carlos.

**Why it worked:**

The server returned the administrator's profile page with their password pre-populated in an HTML input field. The browser masked it visually with asterisks — but the HTML source contained the plaintext value:
```html
<input type="password" value="ct4gj1dj4ghjhpfxfrbh">
```
IDOR gave access to the page. The password field did the rest. Two failures compounded: the missing authorization check (IDOR) and storing/returning plaintext passwords to the client.

---

### Lab 9 — Insecure Direct Object References ✅

**Vulnerability type:** IDOR on static files — predictable filename with no authorization check

**What this lab proves:** Files stored on a server with sequential predictable filenames are directly accessible to anyone who guesses the filename — no authentication required on the download endpoint.

**How it was solved:**

Opened the live chat feature. Sent a message. Clicked View Transcript — this triggered a download. In Burp HTTP History found the download request:
```
GET /download-transcript/2.txt
```
The filename was `2.txt` — a sequential number. This means `1.txt` existed before our transcript. Sent a request in Burp Repeater:
```
GET /download-transcript/1.txt
```

**Response received:**
```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="1.txt"
X-Frame-Options: SAMEORIGIN
Content-Length: 520

CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, I think I've forgotten my password and need confirmation that I've got the right one
Hal Pline: Sure, no problem, you seem like a nice guy. Just tell me your password and I'll confirm whether it's correct or not.
You: Wow you're so nice, thanks. I've heard from other people that you can be a right ****
Hal Pline: Takes one to know one
You: Ok so my password is 8yklbn48eefan3gu72o5. Is that right?
Hal Pline: Yes it is!
You: Ok thanks, bye!
Hal Pline: Do one!
```

**Carlos's password found in transcript:**
```
8yklbn48eefan3gu72o5
```

Logged in as `carlos` with password `8yklbn48eefan3gu72o5`. Navigated to My Account — lab solved.

**Why it worked:**

Transcript files are stored on the server with sequential numeric names: `1.txt`, `2.txt`, `3.txt`. The download endpoint applies no authorization check — it returns any file to anyone who requests it by name. The filename is the only thing standing between the attacker and the data. Sequential numbers are trivially predictable. This is IDOR on a file system — the "object" being referenced is a file, the "insecure direct reference" is the sequential filename with no ownership validation.

---

## 4. Vulnerable Source Code — The Pattern Behind All Labs

Every lab tonight shared the same root cause expressed differently. Here is the vulnerable code pattern and the fix:

**Vulnerable — No ownership check:**
```python
def get_account(request):
    user_id = request.GET['id']          # Takes ID directly from attacker-controlled request
    account = db.query(
        "SELECT * FROM users WHERE id = ?", user_id
    )
    return render(account)               # Returns whoever's data — no ownership check
```

**Why this is wrong:**
The function accepts any ID the user sends, fetches that record, and returns it. The session is never consulted. The server has no idea if the requesting user owns the returned data.

**Fixed — Ownership check against server-controlled session:**
```python
def get_account(request):
    user_id = request.GET['id']
    session_user = request.session['user_id']    # Server controls this — user cannot forge it

    if user_id != session_user:                   # Ownership validation
        return HttpResponse(403)                  # Forbidden — you do not own this

    account = db.query(
        "SELECT * FROM users WHERE id = ?", user_id
    )
    return render(account)
```

**Why the fix works:**
The session is stored server-side and signed — the user cannot forge it. Before fetching any data, the server compares the requested ID against the session owner. Even if the attacker sends `id=administrator`, the check `administrator != wiener` returns 403. The attacker never sees the data.

**For file IDOR — the fix:**
```python
def download_transcript(request, filename):
    transcript = db.get_transcript(filename)

    # Check ownership — does this transcript belong to the logged-in user?
    if transcript.owner_id != request.session['user_id']:
        return HttpResponse(403)

    return send_file(transcript.path)
```

---

## 5. Chain Thinking — IDOR to Full Account Takeover

```
Today's vulnerability: IDOR (User ID controlled by request parameter)
        ↓
Combines with: Password pre-populated in profile page response
        ↓
Combined impact: Full account takeover of any user including administrator
        ↓
Severity upgrade: Medium IDOR + Low information disclosure = Critical account takeover
```

**The full attack chain:**
```
Step 1: Attacker creates account and logs in
        GET /my-account?id=wiener  →  sees own account

Step 2: Attacker changes ID to administrator
        GET /my-account?id=administrator

Step 3: IDOR returns administrator's profile page
        Response body contains:
        <input type="password" value="ct4gj1dj4ghjhpfxfrbh">

Step 4: Attacker extracts password from Burp response
        administrator_password = "ct4gj1dj4ghjhpfxfrbh"

Step 5: Attacker logs in as administrator
        POST /login
        username=administrator&password=ct4gj1dj4ghjhpfxfrbh

Step 6: Full application compromise
        Admin panel access
        All user data accessible
        Ability to delete, modify, create any user
        Complete application takeover
```

**Real world scenario:**
A fintech application stores user profile data and pre-fills password fields for convenience. IDOR on the profile endpoint plus password returned in response equals any attacker who creates a free account can take over the CEO's account, access every transaction record, and drain connected bank accounts. This chain has been found and paid at **$8,000–$15,000** on major platforms.

---

## 6. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|-------------------|--------------|
| Unprotected admin panel | Full application compromise — any visitor becomes admin | $1,000 – $5,000 |
| Cookie-based role control | Admin takeover by any authenticated user | $500 – $3,000 |
| Classic IDOR on user ID | Mass exposure of all user data | $500 – $10,000 |
| GUID IDOR with leaked ID | Targeted user data exposure | $500 – $5,000 |
| Password disclosure via IDOR | Direct account takeover | $3,000 – $15,000 |
| File IDOR on transcripts | Private communication exposure | $200 – $2,000 |

IDOR is consistently the most commonly reported vulnerability class on HackerOne and Bugcrowd. It requires no special tools — only a browser and the ability to modify a request.

---

## 7. The Fix — Defense in Depth

**Layer 1 — Server-side ownership validation (mandatory):**
Every request for a user-owned resource must be validated against the server-side session before data is fetched or returned. The session is server-controlled — the user cannot forge it.

**Layer 2 — Indirect object references:**
Instead of exposing database IDs directly, map them to temporary session-scoped references. The user sees `ref=abc` which maps to their actual record only within their session. Another user's `ref=abc` maps to a different record or returns nothing.

**Layer 3 — Principle of least privilege:**
Users should only be able to access endpoints and objects they need. Admin routes should require explicit role checks — not just authentication.

**Layer 4 — Never trust client-side data for authorization:**
Cookies, URL parameters, request body fields, and headers are all user-controlled. Authorization decisions must be based on server-side session data only.

**Layer 5 — Never return sensitive fields to the client:**
Passwords should never be returned in any response — not even pre-populated in forms. Use server-side form pre-population that renders the field without the value attribute.

---

## 8. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| IDOR | Insecure Direct Object Reference — accessing another user's object by changing an ID |
| Horizontal escalation | Same privilege level — accessing another user's data |
| Vertical escalation | Lower privilege gaining higher privilege (user → admin) |
| Authentication | Verifying who you are (login, session, cookie) |
| Authorization | Verifying what you are allowed to access |
| Mass assignment | API blindly applying all request fields including unauthorized ones |
| Security through obscurity | Hiding something instead of protecting it — always fails |
| Redirect data leakage | Sensitive data in response body before redirect executes |
| File IDOR | Predictable filenames with no ownership check on download endpoint |
| GUID IDOR | Unpredictable ID that is still IDOR when ID is leaked elsewhere |

---

## 9. Payloads and Commands Reference

**URL parameter IDOR:**
```
/my-account?id=carlos
/my-account?id=administrator
/my-account?id=6d5f5046-88aa-4c86-ae3a-bb5b79901b8e
```

**Cookie manipulation (Firefox DevTools → Storage → Cookies):**
```
Admin=false  →  Admin=true
```

**JSON parameter injection (Burp Intercept → modify request body):**
```json
{"email":"test@test.com"}
→
{"email":"test@test.com","roleid":2}
```

**File IDOR (Burp Repeater):**
```
GET /download-transcript/1.txt HTTP/2
GET /download-transcript/2.txt HTTP/2
```

**robots.txt discovery:**
```
GET /robots.txt
```

**Admin panel direct access:**
```
GET /administrator-panel
GET /admin
```

---

## 10. Foundation Checklist

Answer these from memory — not from these notes:

1. **What CAUSES IDOR?** (Not what it is — what specific developer mistake creates it?)
2. **Can you exploit IDOR using only your browser with no tools?** How?
3. **Explain IDOR to a developer in 2 minutes without using the word IDOR** — what would you say?
4. **Describe 2 real world scenarios where IDOR would be rated Critical severity**
5. **How does IDOR chain with password disclosure and what is the combined impact?**
6. **What is the correct fix and why does it work at the server level?**

---
