# Day 23 — Authentication Attacks
**Date:** May 6, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 6 Labs
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was entirely focused on authentication vulnerabilities. We completed 6 PortSwigger labs covering every major authentication attack pattern: username enumeration via different responses, username enumeration via subtly different responses, 2FA simple bypass, broken password reset logic, IP-based brute force protection bypass, and username enumeration via account lockout behavior. Every lab was solved manually using Burp Suite Intruder, Repeater, and Intercept — zero automated tools beyond Intruder wordlist attacks.

---

## 2. The Foundation — Why Authentication Vulnerabilities Exist

### Root Cause

Developers build login systems to verify identity. The problem is that login systems are complex — they handle wrong passwords, locked accounts, forgotten passwords, two-factor codes, and session management all at once. Every one of these features is a potential failure point.

The fundamental mistake: **developers leak information through their login system without realizing it.** Error messages, response times, account lockout behavior, password reset flows — all of these can tell an attacker things the developer never intended to reveal.

A second mistake: developers implement security controls — rate limiting, account lockout, 2FA — but implement them incorrectly. They check the right things in the wrong order. They trust client-supplied data to make security decisions. They enforce rules on one step of a multi-step flow but forget to enforce them on another step.

Authentication vulnerabilities are not about breaking encryption or bypassing firewalls. They are about exploiting the gap between what the developer intended and what the code actually does.

### Real World Analogy

Imagine a bank vault with a combination lock. The bank tells customers: *"If you enter the wrong combination, we will tell you whether the first number was correct."*

An attacker does not need to know the full combination upfront. They try every possible first number until the bank says yes. Then they move to the second number. Then the third. What should have been one hard three-number combination becomes three separate single-number guesses — trivially easy.

This is username enumeration feeding into password brute force. The application splits one hard problem into multiple easy ones by leaking partial information at each step.

### Three Conditions for Authentication Attacks

1. The application leaks information — different responses for valid vs invalid usernames, different timing, different error messages
2. The application has no effective rate limiting — or the rate limiting can be bypassed by manipulating headers, rotating values, or resetting counters
3. The application trusts client-supplied data for security decisions — usernames in reset requests, step indicators in parameters, token values in URLs

### Authentication vs Authorization — Reminder

Authentication answers: **Who are you?**
Authorization answers: **What are you allowed to do?**

Authentication vulnerabilities attack the first question — they let you prove you are someone you are not, or bypass the proof entirely.

### What Authentication Attacks Can and Cannot Do

**Can do:**
- Enumerate valid usernames from an application with thousands of accounts
- Bypass 2FA even when correctly implemented — if the logic order is wrong
- Reset any user's password if the reset token is not tied to the correct user server-side
- Bypass IP-based rate limiting by interleaving valid logins to reset the failure counter
- Gain full account access without knowing the original password

**Cannot do:**
- Break properly implemented rate limiting with genuine network-level IP blocking
- Bypass 2FA that enforces completion server-side on every protected endpoint
- Crack strong unique passwords through online brute force in reasonable time
- Work against accounts with hardware security keys (FIDO2/WebAuthn)

### Real World Example — Snapchat 2014

A researcher warned Snapchat that their API had no rate limiting on the login endpoint. Snapchat ignored the warning. An attacker enumerated 4.6 million usernames and phone numbers by sending automated requests — no rate limiting, no lockout, responses leaked whether a username existed. The data was published publicly. Bug bounty payouts for authentication vulnerabilities: **$500 to $25,000** depending on impact — account takeover on high-value targets pays at the top end.

### Why Timing Attacks Work

When a server checks a username — if the username does not exist, the server returns immediately. If the username exists, the server has to do extra work — fetch the account, hash the password, compare hashes. That extra work takes measurable time. Even a difference of 50–100 milliseconds is enough to enumerate usernames across hundreds of requests.

### The Complete Login Page Testing Methodology

When you land on a login page in real bug bounty — test every single one of these:

```
1. Username enumeration
   → Try valid username + wrong password vs invalid username + wrong password
   → Compare: response body, status code, response time, redirect behavior

2. Password brute force
   → Is there rate limiting? After how many attempts?
   → Is lockout per IP or per account?

3. Rate limiting bypass
   → Add X-Forwarded-For header — does it reset the counter?
   → Does including the correct password in the rotation reset lockout?

4. Password reset flow
   → Is the token in the URL? (leaked in Referer header)
   → Is the token tied to the user it was issued for?
   → Does the reset accept a client-supplied username?

5. 2FA logic
   → After entering username + password — can you skip the 2FA step?
   → Navigate directly to account pages before completing 2FA
   → Is the 2FA code brute-forceable?

6. Session management after login
   → Does the session token change after login?
   → Is the stay-logged-in cookie predictable?
```

Never test just one thing on a login page. This complete methodology is what separates thorough testers from surface-level testers.

---

## 3. Lab Walkthroughs

---

### Lab 1 — Username Enumeration via Different Responses ✅

**Vulnerability type:** Username enumeration — different error messages for invalid username vs invalid password

**What this lab proves:** Different error messages for "username not found" vs "password incorrect" leak which usernames exist — allowing an attacker to build a valid username list before attempting any passwords.

**How it was solved:**

Set up Burp Intruder with a Sniper attack on the username parameter. Used the PortSwigger username wordlist as the payload. Ran the attack and analyzed results by response length.

**Identifying the valid username:**
- Invalid usernames returned response length: **3252**
- Valid username returned response length: **3254** — the longer response contained the "Incorrect password" message instead of "Invalid username"

**Valid username found:** `accounting`

Then ran a second Intruder attack with `accounting` as the fixed username and the password wordlist as the payload. Identified the correct password by status code — all wrong passwords returned **200**, the correct password returned **302** (redirect to account page).

**Credentials found:**
```
Username: accounting
Password: 555555
Status code on correct password: 302
Response length difference: 3254 (valid username) vs 3252 (invalid username)
```

**Why it worked:**

The developer wrote two different error messages:
- Username does not exist → **"Invalid username"**
- Username exists but password wrong → **"Incorrect password"**

This was probably intentional to help legitimate users understand what went wrong. But it created a perfect enumeration oracle. What should have been one hard problem (guess username AND password simultaneously) became two easy sequential problems: first find valid usernames, then brute force only those.

**The vulnerable pattern:**
```python
# Vulnerable — different messages leak username validity
def login(request):
    user = db.get_user(request.POST['username'])
    if not user:
        return error("Invalid username")        # ← leaks username doesn't exist
    if not check_password(request.POST['password'], user.hash):
        return error("Incorrect password")      # ← leaks username DOES exist
    return login_success(user)

# Fixed — identical message always
def login(request):
    user = db.get_user(request.POST['username'])
    password_correct = user and check_password(request.POST['password'], user.hash)
    if not password_correct:
        return error("Invalid username or password")   # ← identical always
    return login_success(user)
```

---

### Lab 2 — Username Enumeration via Subtly Different Responses ✅

**Vulnerability type:** Username enumeration — tiny unintentional difference in error messages across code paths

**What this lab proves:** Even when a developer tries to use identical error messages — a tiny unintentional difference (missing punctuation, extra space) still leaks username validity when responses are compared programmatically.

**How it was solved:**

Set up Intruder with the username wordlist. Used **Grep - Extract** in Burp Settings to extract the exact error message text from every response. Ran the attack and sorted by the extracted column — one username returned a subtly different message (different punctuation or spacing) revealing it as valid.

Found valid username `puppet`. Then brute forced the password with `puppet` fixed — found correct password by response difference.

**Credentials found:**
```
Username: puppet
Password: pepper
```

**Why it worked:**

The developer intended to use the same error message for both cases — better than Lab 1. But made a tiny inconsistency in one code path — perhaps a missing period, an extra space, or a slightly different phrasing. A human reading the page would never notice. Burp Intruder extracting the exact string from hundreds of responses makes the difference instantly visible in a sortable column.

**Key technique — Grep Extract vs Grep Match:**
- **Grep Match:** flags responses containing a specific string — works when messages are completely different
- **Grep Extract:** pulls the exact text from a defined region of every response — works when differences are subtle, making them visible side by side in the results table

**Why this matters in real bug bounty:** Developers increasingly try to unify error messages. Grep Extract finds the tiny mistakes they miss. Always extract the full error message text, not just match for a known string.

---

### Lab 3 — 2FA Simple Bypass ✅

**Vulnerability type:** 2FA bypass — partial authentication session allows direct navigation to protected pages

**What this lab proves:** 2FA implemented as a UI redirect flow — without server-side enforcement on every protected endpoint — can be bypassed entirely by navigating directly to the protected page.

**How it was solved:**

Logged in as `carlos:montoya`. Reached the 2FA page — no verification code available for carlos. Instead of entering a code — navigated directly to:
```
/my-account?id=carlos
```
Bypassed the 2FA page entirely. Carlos's account page loaded immediately.

**Why it worked:**

When carlos entered his username and password — the application created a partially authenticated session and redirected to the 2FA page. But the `/my-account` endpoint only checked "is there a session?" — not "did this session complete 2FA?" The 2FA page was a UI-level redirect only. There was no server-side flag verified on protected pages confirming 2FA completion.

**The developer's mistake:**
```python
# Vulnerable — protected page only checks session exists
def my_account(request):
    if not request.session:
        return redirect('/login')
    return render_account(request.session.user)  # Never checks 2FA was verified

# Fixed — checks 2FA completion flag
def my_account(request):
    if not request.session:
        return redirect('/login')
    if not request.session.get('2fa_verified'):   # Must have completed 2FA
        return redirect('/login/2fa')
    return render_account(request.session.user)
```

**Key lesson:** Implementing the 2FA page is not the same as enforcing 2FA. Enforcement means every protected endpoint independently verifies that 2FA was completed for the current session — not just that a session exists.

---

### Lab 4 — Password Reset Broken Logic ✅

**Vulnerability type:** Broken password reset — token not tied to user server-side, client-supplied username trusted

**What this lab proves:** When a password reset token is validated independently of the username supplied in the same request — an attacker can use their own valid token to reset any other user's password.

**How it was solved:**

Requested a password reset for `wiener`. Got a valid reset token from the email client. Went to the reset page. Turned Intercept ON and submitted the password reset form. Modified the frozen request — changed the `username` parameter from `wiener` to `carlos` while keeping the valid token:

**Modified reset request:**
```
temp-forgot-password-token=spqmltp50ffi0r6slxztyzjg5xcpjxk5&username=carlos&new-password-1=test&new-password-2=test
```

Forwarded the request. Carlos's password was changed to `test`. Logged in as `carlos:test` — lab solved.

**Why it worked:**

The server checked: "is this a valid token?" — yes, it was wiener's valid token. But instead of looking up which user that token was issued for — it used the `username` field from the POST body. The token and username were never validated together. The token proved "a valid reset was initiated" but the username determined whose password was changed — and the username was user-controlled.

**The vulnerable pattern:**
```python
# Vulnerable — trusts client-supplied username
def reset_password(request):
    token = request.POST['temp-forgot-password-token']
    username = request.POST['username']              # ← attacker controls this
    new_password = request.POST['new-password-1']

    if db.token_exists(token):                       # Only checks token is real
        db.update_password(username, new_password)   # Uses attacker-supplied username
        db.delete_token(token)

# Fixed — looks up user from token, never trusts client username
def reset_password(request):
    token = request.POST['temp-forgot-password-token']
    new_password = request.POST['new-password-1']

    user = db.get_user_by_token(token)               # Token determines the user
    if not user:
        return error("Invalid or expired token")

    db.update_password(user.id, new_password)        # Server-determined user only
    db.delete_token(token)
```

---

### Lab 5 — Broken Brute-Force Protection, IP Block ✅

**Vulnerability type:** Rate limiting bypass — successful login resets failed attempt counter

**What this lab proves:** IP-based rate limiting that resets on successful login can be bypassed by interleaving correct logins between brute force attempts — keeping the counter below the lockout threshold indefinitely.

**How it was solved:**

Tested the rate limiting — lockout triggered after 3 failed attempts. Identified the bypass: a successful login resets the counter. Built a Pitchfork Intruder attack with two synchronized payload lists — interleaving `wiener:peter` (correct login) every 3rd attempt to reset the counter before lockout triggers.

**Username payload list pattern:**
```
carlos
carlos
wiener
carlos
carlos
wiener
... (repeat for full password list)
```

**Password payload list pattern:**
```
[password-1 from wordlist]
[password-2 from wordlist]
peter
[password-3 from wordlist]
[password-4 from wordlist]
peter
... (peter every 3rd entry)
```

Ran Pitchfork attack. Identified carlos's correct password by **302 status code** on a carlos attempt (all others returned 200).

**Credentials found:**
```
Username: carlos
Password: killer
```

**Why it worked:**

The rate limiter counted failed attempts per IP and reset on any successful login. The developer assumed a real user would only log in with their own account. They never considered an attacker could interleave a valid login between brute force attempts. The counter kept resetting to zero before reaching the lockout threshold. The security control was bypassed not by breaking it — but by exploiting its own reset mechanism.

**Burp Intruder setup:**
```
Attack type: Pitchfork
Position 1: username parameter
Position 2: password parameter
Payload set 1: username list (carlos/carlos/wiener pattern)
Payload set 2: password list (wordlist with peter every 3rd entry)
Identify success: status code 302 on a carlos entry
```

---

### Lab 6 — Username Enumeration via Account Lock ✅

**Vulnerability type:** Username enumeration — account lockout behavior reveals valid usernames

**What this lab proves:** Account lockout applied only to valid accounts — never to invalid ones — makes the lockout behavior itself an enumeration oracle.

**How it was solved:**

Set up a Cluster Bomb Intruder attack:
- Position 1: username field — full username wordlist
- Position 2: password field — 5 dummy passwords (`wrong1` through `wrong5`)

This sent every username 5 times. Valid accounts triggered lockout after repeated failures — returning a longer response containing the lockout message. Invalid accounts returned the same short "Invalid username or password" response every time.

Identified valid username by **response length difference** — the locked account response was longer. Waited for lockout to expire. Brute forced the password against the valid username. Found the correct password by identifying the response that contained neither the "Invalid username or password" message nor the lockout message — a clean response indicating successful login.

**Why it worked:**

The developer implemented account lockout correctly for valid accounts — a genuine security control. But invalid accounts cannot be locked because they do not exist. This asymmetry — lockout triggers for valid accounts, nothing for invalid — is the oracle. The security feature designed to prevent brute force became the tool that revealed which usernames to brute force.

**The irony:** Removing account lockout would make this specific enumeration technique impossible — but would make password brute force easier. The correct fix is to return identical responses for lockout and invalid username: "Too many attempts — try again later" regardless of whether the account exists.

**Cluster Bomb vs Sniper vs Pitchfork:**
```
Sniper:       One payload list, one position — enumerate usernames
Pitchfork:    Two synchronized lists — username:password pairs in sync
Cluster Bomb: Two independent lists — every username tried with every password
              Used here: every username tried with 5 dummy passwords
              Total requests: (username count) × 5
```

---

## 4. Vulnerable Source Code — Patterns Behind All Labs

**Generic authentication flaw — information leakage:**
```python
# Vulnerable
if not user:
    return "Invalid username"
if not password_match:
    return "Incorrect password"

# Fixed — identical response always
if not user or not password_match:
    return "Invalid username or password"
# Also: always run password hash comparison even when user doesn't exist
# to prevent timing differences leaking username validity
```

**Password reset flaw — client-trusted username:**
```python
# Vulnerable
if token_valid(token):
    reset_password(request.POST['username'], new_password)  # trusts client

# Fixed
user = db.lookup_user_by_token(token)  # server determines user from token
if not user:
    return error()
reset_password(user.id, new_password)
```

**2FA enforcement flaw:**
```python
# Vulnerable — only checks session exists
if request.session:
    return account_page()

# Fixed — checks 2FA completion
if request.session and request.session['2fa_complete']:
    return account_page()
else:
    return redirect('/2fa')
```

**Rate limiting flaw — resets on success:**
```
# Vulnerable logic:
failed_attempts[ip] += 1
if failed_attempts[ip] > 3: lockout
if login_success: failed_attempts[ip] = 0   ← attacker exploits this reset

# Fixed logic:
# Rate limit per account not just per IP
# Do not reset counter on success during a brute force session
# Use progressive delays instead of hard lockout
# Implement CAPTCHA after N failures
```

---

## 5. Chain Thinking — Authentication to Full Account Takeover

```
Username enumeration (Lab 1 — different responses)
        ↓
Valid username identified: carlos
        ↓
Combines with: Password reset broken logic (Lab 4)
        ↓
Request password reset for wiener → get valid token
Modify reset request: token=valid&username=carlos&new-password=hacked
        ↓
Carlos's password changed without knowing original
        ↓
Log in as carlos — full account access
        ↓
If carlos is admin → complete application compromise
        ↓
Severity: Medium enumeration + Medium reset flaw = Critical account takeover
```

**Full attack code:**
```
Step 1: Enumerate valid username
        Intruder Sniper on username field
        Payload: username wordlist
        Identify: response length 3254 vs 3252
        Valid username: carlos

Step 2: Request password reset for own account (wiener)
        POST /forgot-password
        username=wiener
        → Receive token in email client

Step 3: Intercept and modify reset submission
        POST /forgot-password-confirm
        temp-forgot-password-token=spqmltp50ffi0r6slxztyzjg5xcpjxk5
        &username=carlos         ← changed
        &new-password-1=hacked
        &new-password-2=hacked

Step 4: Log in as carlos
        POST /login
        username=carlos&password=hacked
        → 302 redirect to account page
        → Full access
```

**Real world scenario:** A SaaS platform has username enumeration on login and broken password reset logic. Attacker enumerates the CEO's email. Uses their own throwaway account to generate a valid reset token. Modifies the username in the reset request to the CEO's email. Gains full access to the CEO's account — all company data, billing, user management. Paid at **$5,000–$20,000** on real programs.

---

## 6. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|------------------|--------------|
| Username enumeration | Enables targeted brute force — reduces search space from billions to one account | $200 – $1,000 |
| 2FA simple bypass | Full account takeover despite 2FA being enabled | $1,000 – $5,000 |
| Broken password reset | Account takeover of any user without knowing original password | $1,000 – $8,000 |
| Brute force protection bypass | Unlimited password attempts against any account | $500 – $3,000 |
| Account lockout enumeration | Username list from application with lockout "protection" | $200 – $800 |
| Full chain: enumerate + reset | Critical account takeover — CEO/admin level | $5,000 – $20,000 |

---

## 7. The Fix — Defense in Depth

**Layer 1 — Generic error messages:**
Always return identical messages regardless of whether the username exists or the password is wrong. "Invalid username or password" — never reveal which one failed.

**Layer 2 — Constant-time password checking:**
Always run the password hash comparison even when the username does not exist — use a dummy hash. Prevents timing differences from leaking username validity.

**Layer 3 — Password reset token ownership:**
The server must look up which user a token belongs to from the database. Never accept a client-supplied username in a reset request. Token determines user — always.

**Layer 4 — 2FA server-side enforcement:**
Every protected endpoint must independently verify a session flag confirming 2FA was completed. Redirect to 2FA if the flag is absent — never trust that the user went through the 2FA page.

**Layer 5 — Rate limiting that cannot be reset by attacker:**
Rate limit per account not just per IP. Do not reset the counter on successful login. Use progressive delays. Implement CAPTCHA after N failures. Rate limit at the network level not just application level.

**Layer 6 — Account lockout with consistent messaging:**
Return the same response for "account locked" and "invalid username" — "Too many attempts, please try again later." Never reveal whether the account exists.

---

## 8. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| Username enumeration | Identifying valid usernames from application response differences |
| Grep Match | Burp flag for responses containing a specific string — for obvious differences |
| Grep Extract | Burp extraction of exact text region — for subtle differences |
| 2FA bypass | Navigating directly to protected pages after partial authentication |
| Partial authentication | Session created after username+password but before 2FA completion |
| Broken password reset | Reset token not tied to user server-side — client username trusted |
| Pitchfork attack | Burp Intruder attack type — two synchronized payload lists |
| Cluster Bomb attack | Burp Intruder attack type — two independent lists, every combination |
| Rate limit reset bypass | Interleaving valid logins to reset failed attempt counter |
| Account lockout oracle | Lockout triggers for valid accounts only — asymmetry reveals valid usernames |
| Timing attack | Response time difference reveals username validity without message differences |

---

## 9. Payloads and Commands Reference

**Intruder — username enumeration (Sniper):**
```
Position: username=§candidate§&password=wrongpassword
Payload: PortSwigger username wordlist
Identify valid: different response length or message content
```

**Intruder — password brute force after enumeration (Sniper):**
```
Position: username=validuser&password=§candidate§
Payload: PortSwigger password wordlist
Identify success: status code 302
```

**Intruder — account lockout enumeration (Cluster Bomb):**
```
Position 1: username=§candidate§
Position 2: password=§dummy§
Payload 1: username wordlist
Payload 2: [wrong1, wrong2, wrong3, wrong4, wrong5]
Identify valid: longer response length (lockout message)
```

**Intruder — rate limit bypass (Pitchfork):**
```
Position 1: username=§user§
Position 2: password=§pass§
Payload 1: [carlos, carlos, wiener, carlos, carlos, wiener, ...]
Payload 2: [pass1, pass2, peter, pass3, pass4, peter, ...]
Identify success: status 302 on a carlos entry
```

**2FA bypass — direct navigation:**
```
After logging in with target credentials (before completing 2FA):
Navigate directly to: /my-account?id=TARGET-USERNAME
```

**Password reset token manipulation:**
```
Original: token=VALID-TOKEN&username=wiener&new-password-1=x&new-password-2=x
Modified: token=VALID-TOKEN&username=carlos&new-password-1=hacked&new-password-2=hacked
```

---

## 10. Foundation Checklist

Answer these from memory — not from these notes:

1. **What causes username enumeration?** What specific developer decision creates the information leak?
2. **Why does 2FA bypass work?** What did the developer implement vs what did they forget to enforce?
3. **What is the root cause of broken password reset?** What should the server look up instead of trusting client input?
4. **How does the IP block bypass work?** What assumption does the rate limiter make that the attacker exploits?
5. **How does account lockout become an enumeration oracle?** What asymmetry creates the leak?
6. **Describe the complete chain from username enumeration to account takeover** in 4 steps without looking at notes.

---
