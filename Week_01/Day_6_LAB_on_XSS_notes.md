# Day 5 & 6 Notes — PortSwigger XSS Labs + First Write-up

---

## 1. What We Did Today Overview

- Created PortSwigger Web Security Academy account
- Completed Lab 1: Reflected XSS into HTML context with nothing encoded
- Completed Lab 2: Stored XSS into HTML context with nothing encoded
- Wrote first professional security finding write-up
- Understood the difference between lab environments vs DVWA

---

## 2. PortSwigger Web Security Academy — What It Is

PortSwigger is the company that makes Burp Suite. Their Web Security Academy is a free platform with:
- Theory pages explaining each vulnerability
- Real live vulnerable labs hosted on their servers
- Each lab is a real website spun up specifically for you to hack

Unlike DVWA which runs locally on your machine, PortSwigger labs are:
- Hosted externally on their servers
- Accessed through your browser directly
- Each lab gives you a unique URL like `https://[random-id].web-security-academy.net`
- The lab auto-destructs after a set time

This is closer to real bug bounty hunting because you're testing an actual live web server instead of something on localhost.

---

## 3. Lab 1 — Reflected XSS into HTML context with nothing encoded

### What the lab is testing
Whether you can find a parameter that reflects your input directly into the HTML response without any encoding or sanitization — and exploit it with a basic XSS payload.

### The target
A simple website with a search box. Whatever you type in the search box gets reflected back on the page in the results.

### What we did step by step

**1.** Opened the lab → a live website loaded with a search box

**2.** First tested normal input — typed `hello` in the search box → page showed "0 search results for 'hello'" — confirmed input is being reflected back on the page

**3.** Injected XSS payload into the search box:
```html
<script>alert(1)</script>
```

**4.** Hit Enter → alert box popped with "1" → lab marked as solved

### Why it worked
The server took our search input and put it directly into the HTML response like this:
```html
<p>0 search results for '<script>alert(1)</script>'</p>
```
The browser received that HTML, saw the `<script>` tag, and executed it immediately. No filtering, no encoding, nothing stopping it.

### What "HTML context with nothing encoded" means
- **HTML context** = your input lands inside the HTML body of the page (not inside a JavaScript string, not inside an attribute — just raw in the HTML)
- **Nothing encoded** = the server does zero sanitization — `<` stays as `<`, `>` stays as `>`, so the browser treats your input as actual HTML tags

This is the most basic form of XSS. Real apps usually have some filtering which requires bypasses — but understanding this baseline is essential before learning bypasses.

### Difference from DVWA
On DVWA we used a name field. Here we used a search box. The vulnerability is identical — the specific input field doesn't matter. What matters is that the input is reflected in the response unsanitized. Any input field on any page can potentially be vulnerable.

---

## 4. Lab 2 — Stored XSS into HTML context with nothing encoded

### What the lab is testing
Whether you can inject a payload that gets saved in the database and executes for every user who visits the page — not just the person who submitted it.

### The target
A blog website with posts and a comment section under each post. Comments get saved to the database and displayed to all visitors.

### What we did step by step

**1.** Opened the lab → a blog website loaded with several posts

**2.** Clicked on any blog post → scrolled down to the comment section

**3.** Filled in the comment form:
- **Comment field:** `<script>alert(1)</script>`
- **Name:** any name
- **Email:** test@test.com
- **Website:** http://test.com

**4.** Clicked Post Comment → got redirected back to the blog post page

**5.** Alert fired immediately on redirect — lab solved

**6.** Reloaded the page → alert fired again

### Why the alert fires on every reload
The payload is now saved in the database. Every time the blog post page loads the server fetches all comments from the database and puts them into the HTML:
```html
<div class="comment">
    <p><script>alert(1)</script></p>
</div>
```
Every visitor's browser loads that HTML and executes the script. It doesn't matter if they submitted anything — just visiting the page triggers it.

### Why reload confirmed it is stored XSS
This is the key difference from reflected XSS:
- **Reflected** = only fires for the person who submitted the payload in that specific request. Reload the page with a normal URL = no alert.
- **Stored** = fires for everyone on every page load because it lives in the database. Reload = alert fires again.

That one test — reloading the page — is how you confirm in real bug bounty hunting whether XSS is reflected or stored.

### Why stored XSS is more severe than reflected
| Factor | Reflected | Stored |
|---|---|---|
| Who gets hit | Only victim who clicks attacker's link | Every single visitor automatically |
| Requires victim action | Yes — must click a crafted link | No — just visiting the page is enough |
| Persistence | Gone after one request | Permanent until database is cleared |
| Scale of attack | One victim at a time | Entire user base at once |
| Real world example | Phishing email with malicious link | Malicious comment on a popular forum |

In bug bounty stored XSS almost always rates higher severity than reflected XSS because of the scale — one payload can hit thousands of users.

---

## 5. Browser vs Burp — When to Use Which

For these two labs we did everything directly in the browser without Burp. Here's when each approach makes sense:

### Browser only (what we did today)
- Simple labs where the payload goes in a visible input field
- When you just want to confirm if the vulnerability exists
- Faster for basic apprentice-level labs

### Burp Repeater approach (what we did on DVWA)
- When you want to test many payloads quickly without reloading the browser
- When the parameter is hidden (not in a visible form field)
- When you need to modify headers, cookies, or other parts of the request
- When the payload needs URL encoding or other manipulation
- For real bug bounty work — Burp gives you full control

Both skills are essential. Browser for quick confirmation, Burp for deep testing.

---

## 6. PortSwigger Labs vs DVWA — Key Differences

| | DVWA | PortSwigger Labs |
|---|---|---|
| Where it runs | Locally on your machine | Hosted on PortSwigger's servers |
| Internet required | No | Yes |
| Realism | Lower — basic intentionally vulnerable app | Higher — purpose-built realistic scenarios |
| Burp needed | Recommended | Optional for basic labs |
| Cookie values | Your local PHPSESSID | PortSwigger session tokens |
| Best for | Learning basics, experimenting freely | Structured skill progression |

Use DVWA to experiment and break things freely. Use PortSwigger labs to learn specific vulnerability classes in a structured way. Both together give you the best foundation.

---

## 7. What Makes a Good Security Finding Write-up

Today we also wrote our first professional write-up. Here's what every write-up needs and why:

### Title
Clear, specific, tells you exactly what the bug is and where.
```
Reflected XSS in DVWA Name Parameter
```
Not: "XSS bug found" — too vague.

### Severity
How bad is this? Use a standard like CVSS or just High/Medium/Low/Critical with justification. Reflected XSS = High. Stored XSS = Critical.

### Description
One paragraph explaining what the vulnerability is in plain English. Assume the reader is a developer, not a security expert.

### Steps to Reproduce
Numbered, exact, reproducible. A developer should be able to follow these steps exactly and see the same result. If they can't reproduce it they can't fix it.

### Proof of Concept
The exact payload used + screenshot or output showing it worked. This is your evidence. No proof = no credibility.

### Impact
What can an attacker actually DO with this? Don't just say "XSS is bad." Say specifically: steal session cookies, hijack accounts, redirect to phishing pages, capture keystrokes.

### Root Cause
Why does this vulnerability exist? What is the bad code doing? This shows you understand the vulnerability deeply, not just that you ran a payload.

### Remediation
How to fix it. Always include the fix — security researchers who only find bugs without suggesting fixes are less valuable than those who do both.

### References
Link to OWASP, PortSwigger, or CVEs. Shows you understand the broader context.

---

## 8. Key Concepts Summary

| Term | Meaning |
|---|---|
| PortSwigger Academy | Free platform with XSS, SQLi, and other vuln labs |
| HTML context | Your input lands directly in the HTML body of the page |
| Nothing encoded | Server does zero sanitization on your input |
| Stored XSS | Payload saved in DB, fires for every visitor on every load |
| Reflected XSS | Payload fires only for the person who sent that specific request |
| Reload test | Reloading the page confirms if XSS is stored (fires again) or reflected (doesn't) |
| Write-up | Professional document describing a security finding end to end |

---

## 9. Payloads Used Today

**Lab 1 — Reflected XSS (search box):**
```html
<script>alert(1)</script>
```

**Lab 2 — Stored XSS (comment field):**
```html
<script>alert(1)</script>
```

Same payload, completely different vulnerability class and impact. The payload is simple — what matters is WHERE it lands and WHETHER it gets stored.

---

## 10. Week 1 Complete — What You Can Now Do

After this week you can:
- Set up Burp Suite and intercept any HTTP traffic including localhost
- Read and understand raw HTTP requests and responses
- Identify and exploit Command Injection manually
- Identify and exploit Reflected XSS manually
- Identify and exploit Stored XSS manually
- Steal session cookies using JavaScript
- Understand the difference between reflected and stored XSS
- Write a professional security finding report
- Use PortSwigger Academy labs independently

Next week is Week 2 — deep dive into XSS on PortSwigger. You'll go from basic payloads to filter bypasses, DOM-based XSS, and chaining XSS with other vulnerabilities.

---

*Week 1 complete. 4 days of actual hacking done. First write-up published. You're ahead of most people who say they want to get into AppSec.*
