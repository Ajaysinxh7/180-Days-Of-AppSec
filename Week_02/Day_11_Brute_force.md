# Day 11 Notes — Brute Force Attacks + Burp Intruder

---

## 1. What We Did Today Overview

- Understood what brute force attacks are and how they work
- Intercepted the DVWA login request and sent it to Burp Intruder
- Set up a Sniper attack to brute force the admin password
- Identified the correct password using response length differences
- Enumerated valid usernames using the same technique
- Used Burp Comparer to diff a failed vs successful login response
- Observed rate limiting in action on Medium security

---

## 2. What is Brute Force

Brute force is the act of systematically trying every possible value for a parameter — usually a password — until the correct one is found. It requires no knowledge of the actual password, just time and automation.

In web security brute force attacks target:
- Login forms — trying passwords against a known username
- Username fields — finding which usernames exist on a system
- OTP fields — trying all possible 4 or 6 digit codes
- API keys, session tokens, reset codes

Burp Intruder automates this entirely — sending hundreds of requests per second with different values from a wordlist, then letting you analyze the responses to spot which one worked.

---

## 3. What is Burp Intruder

Burp Intruder is a tab in Burp Suite that takes any intercepted HTTP request and lets you:
- Mark specific parameter values as payload positions (§ markers)
- Define a list of payloads to try at each position
- Send all variations automatically
- Analyze every response in a results table

It turns a manual process of trying one password at a time into an automated attack that tries thousands in seconds.

### Attack types in Intruder

| Type | What it does | When to use |
|---|---|---|
| Sniper | One payload position, one wordlist — tries each payload at that position | Brute forcing a single field like password |
| Battering ram | Same payload inserted at all positions simultaneously | When username and password must match |
| Pitchfork | Multiple positions, multiple wordlists — pairs them in order | Known username:password pairs |
| Cluster bomb | Multiple positions, tries all combinations | Unknown username AND password |

Tonight we used **Sniper** — one position (password field), one wordlist.

---

## 4. Task 1 — Intercepting the Login Request

### What the DVWA Brute Force page does
A simple login form with username and password fields. Two possible responses:
- Wrong credentials → "Username and/or password incorrect"
- Correct credentials → "Welcome to the password protected area admin"

This difference in response content = difference in response length = how Intruder detects the correct password.

### What the intercepted request looked like
```
GET /vulnerabilities/brute/?username=admin&password=test&Login=Login HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=...; security=low
```

Key observations:
- It's a **GET request** — credentials go in the URL, not the body
- Both `username` and `password` are visible as plain URL parameters
- The cookie confirms security=low is active

---

## 5. Task 2 — Setting Up the Intruder Attack

### Step by step what we configured

**Positions tab:**
1. Sent request to Intruder
2. Clicked **Clear §** to remove all default markers
3. Highlighted the value `test` in `password=test`
4. Clicked **Add §** → became `password=§test§`
5. Left `username=admin` unchanged — we know the username
6. Attack type = **Sniper**

**Payloads tab:**
1. Payload type = Simple list
2. Added passwords manually:
```
123456
password
admin
letmein
abc123
charley
test
qwerty
dragon
master
```

### Why we used a short manual list tonight
Kali has rockyou.txt at `/usr/share/wordlists/rockyou.txt` with 14 million passwords. Burp Community Edition throttles Intruder to slow speeds — combining 14 million entries with throttling would take hours. For practice a short targeted list is enough. In real bug bounty use the full rockyou list with Burp Pro or a custom tool like hydra.

---

## 6. Task 3 — Reading the Intruder Results

### What the results table showed

| Payload | Status | Length |
|---|---|---|
| 123456 | 200 | 4702 |
| admin | 200 | 4703 |
| letmein | 200 | 4702 |
| abc123 | 200 | 4702 |
| **password** | **200** | **4741** |
| charley | 200 | 4703 |
| test | 200 | 4702 |

### How we identified the correct password
All wrong passwords returned length **4702 or 4703** — small natural variation in response size. The correct password `password` returned length **4741** — noticeably larger because the response contained the extra text "Welcome to the password protected area admin" instead of "Username and/or password incorrect."

**The rule: sort by Length column — the outlier is the correct answer.**

The status code is useless here — everything returned 200 OK because the page always loads, it just shows different content. Length is the only signal that matters.

### Confirming in the response tab
Clicked the `password` row → Response tab → searched for "Welcome" → confirmed the full welcome message appeared. Attack successful.

---

## 7. Task 4 — Username Enumeration

Instead of brute forcing the password we brute forced the username to find which accounts exist.

### Setup
- Payload position on `username=§admin§` instead of password
- Left `password=password` fixed
- Wordlist:
```
admin
administrator
user
test
guest
gordon
pablo
smithy
root
dvwa
```

### Results
Sorted by Length — two usernames returned a different length:
- **admin** → longer response → exists ✓
- **smithy** → longer response → exists ✓

All others returned the standard "incorrect" length — those usernames don't exist in the database.

### Why username enumeration matters
In real hacking username enumeration is often reported as its own vulnerability. If a login page tells you "username not found" vs "wrong password" — or responds differently in length/time — an attacker can first enumerate all valid usernames, then only brute force those. Cuts the attack surface dramatically.

A secure login page should always return the exact same response for wrong username AND wrong password so attackers can't tell the difference.

---

## 8. Task 5 — Burp Comparer

Comparer is a Burp tab that shows you the exact difference between two HTTP responses side by side.

### What we did
1. Right clicked a **failed login** response in Intruder results → Send to Comparer
2. Right clicked a **successful login** response → Send to Comparer
3. Comparer tab → clicked **Words**
4. Saw exactly which text differed between the two responses

### What Comparer showed
The only difference was the message text:
- Failed: `Username and/or password incorrect.`
- Success: `Welcome to the password protected area admin`

Everything else — headers, HTML structure, CSS, JavaScript — was identical. This explains the length difference: the success message is longer than the failure message by exactly 38 bytes — which is why successful logins showed length 4741 vs 4702-4703 for failures.

### When Comparer is useful in real bug bounty
- Comparing responses to find subtle differences that indicate true/false conditions
- Blind SQLi — comparing "exists" vs "missing" responses at the byte level
- Checking if two API responses are truly identical or have hidden differences
- Verifying that a security fix actually changed the response

---

## 9. Task 6 — Medium Security Rate Limiting

### What changed on Medium security
DVWA Medium security adds a `sleep(2)` in the PHP code for every failed login attempt. Each wrong password causes the server to pause 2 seconds before responding.

### What we observed
Running the same Intruder attack on Medium — each request took approximately 2 seconds to complete. With 10 passwords in our list that's 20 seconds minimum. With rockyou's 14 million passwords that would be:
```
14,000,000 × 2 seconds = 28,000,000 seconds = ~324 days
```
Rate limiting via sleep makes brute force practically infeasible.

### Why this matters in real bug bounty
Login endpoints **without** rate limiting are a real finding. If you can send 1000 login attempts per second with no slowdown or lockout — that's a vulnerability worth reporting. Severity depends on context:
- No rate limiting on admin login → High severity
- No rate limiting on user login → Medium severity
- No rate limiting + no account lockout → Critical

Always test: can you send 50+ rapid login attempts without getting blocked or slowed down?

### Real rate limiting vs sleep()
DVWA's sleep() approach is a weak implementation. Real rate limiting involves:
- **Account lockout** — lock the account after N failed attempts
- **IP-based throttling** — block or slow IPs sending too many requests
- **CAPTCHA** — require human verification after N failures
- **Token-based limits** — require a valid anti-CSRF token per attempt

Sleep alone is bypassable by running multiple parallel attack threads simultaneously.

---

## 10. Key Concepts Summary

| Term | Meaning |
|---|---|
| Brute force | Systematically trying all possible values until one works |
| Burp Intruder | Burp tab that automates sending payloads and analyzing responses |
| Sniper attack | One payload position, one wordlist — tries each value at that position |
| Payload position | The parameter value marked with § that Intruder replaces with each payload |
| Response length | The size of the HTTP response in bytes — key signal for detecting correct answers |
| Username enumeration | Finding which usernames exist by observing different responses |
| Burp Comparer | Tool that diffs two responses to show exactly what changed |
| Rate limiting | Deliberately slowing or blocking rapid repeated requests |
| Account lockout | Blocking an account after N failed login attempts |
| rockyou.txt | Wordlist of 14 million real-world leaked passwords — standard for brute force |

---

## 11. Payloads and Commands Reference

**rockyou.txt location on Kali:**
```bash
locate rockyou.txt
# usually at /usr/share/wordlists/rockyou.txt

# if compressed:
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

**Intruder setup checklist:**
```
1. Intercept login request → Send to Intruder
2. Positions tab → Clear § → highlight target value → Add §
3. Attack type = Sniper
4. Payloads tab → Simple list → add wordlist
5. Start Attack
6. Sort results by Length
7. Outlier length = correct answer
8. Click row → Response tab → confirm
```

**What to look for in real bug bounty:**
```
- No rate limiting → can send unlimited requests
- No account lockout → account never gets blocked
- Response difference → length or content reveals valid usernames
- Timing difference → slower response = valid username (timing attack)
```

---

## 12. Brute Force Defense Checklist

When you find a login form in bug bounty test all of these:

| Test | How | Vulnerability if... |
|---|---|---|
| Rate limiting | Send 50 rapid requests with Intruder | No slowdown after multiple failures |
| Account lockout | Try 20+ wrong passwords | Account never locks |
| Username enumeration | Compare response for valid vs invalid username | Different response content or length |
| Timing attack | Measure response time for valid vs invalid | Valid username takes longer |
| CAPTCHA bypass | Try submitting without solving CAPTCHA | Request goes through anyway |

---

*Day 11 complete. You can now set up and run Burp Intruder attacks, identify correct credentials from response length, enumerate valid usernames, use Burp Comparer to diff responses, and understand rate limiting as a defense. Tomorrow is Day 12 — File Inclusion vulnerabilities on DVWA.*
