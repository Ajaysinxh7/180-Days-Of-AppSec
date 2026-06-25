
# Day 43 Notes — Race Conditions Part 1 (Foundations + Limit Overrun)

**Author:** Ainz  
**Date:** 25 June 2026  
**Platform:** PortSwigger Web Security Academy

---

## 1. What We Did Today Overview

Today we studied **Race Conditions**, focusing on the fundamental concepts and the basic exploitation technique using parallel requests.

**Main Activity:**
- Completed Lab 1: Limit Overrun Race Conditions (discount code)
- Observed and analyzed inconsistency in results when using normal parallel requests

---

## 2. The Foundation (Deep Dive)

### 2.1 What Is a Race Condition?

A **race condition** is a class of vulnerability that arises when a system's correctness depends on the **exact timing or ordering** of uncontrollable events — specifically, when two or more operations "race" each other to read or write shared state, and the outcome changes depending on which operation finishes first.

In web applications, race conditions are a **concurrency bug**. They do not exist in single-threaded, single-request scenarios. They only manifest when the server processes **multiple requests simultaneously** (which is the default behavior of every modern web server — Apache, Nginx, Node.js, etc. all handle concurrent connections).

> **Key Insight:** Race conditions are not about sending "fast" requests. They are about exploiting the **gap in time** between two logically connected operations that the developer assumed would execute without interruption.

### 2.2 Why Web Servers Are Vulnerable by Design

Modern web servers are designed to handle many users at once. They achieve this through:

| Concurrency Model | How It Works | Examples |
|---|---|---|
| **Multi-threaded** | Each incoming request is assigned to a separate OS thread. All threads share the same memory and database. | Apache (worker MPM), Java Servlet containers (Tomcat) |
| **Multi-process** | Each request is handled by a separate process. Processes share the database but have isolated memory. | Apache (prefork MPM), PHP-FPM |
| **Event-loop + async** | A single thread handles many connections using non-blocking I/O, but database calls are still shared. | Node.js, Python asyncio |

In **every model above**, the database is a shared resource. When two requests both read and write to the same database row (e.g., a coupon's `used` flag), they can interfere with each other if the operations are not properly synchronized.

> **Foundation Principle:** The vulnerability does not live in the HTTP layer. It lives in the **backend logic and database interaction layer** where shared state is read and modified without proper concurrency control.

### 2.3 The TOCTOU Flaw (Time Of Check To Time Of Use) — Full Breakdown

**TOCTOU** is the formal name for the pattern that causes most race conditions. It describes a situation where:

1. **Time of Check (TOC):** The application reads some state to make a decision. Example: `SELECT used FROM coupons WHERE code = 'PROMO20'` → result is `used = 0` (not yet used).

2. **Time gap (the race window):** Between the check completing and the next operation executing, time passes. Even if it is only **microseconds**, this gap exists because CPUs execute instructions sequentially and databases process queries one at a time per connection.

3. **Time of Use (TOU):** The application acts on the old information it read during the check. Example: `UPDATE coupons SET used = 1 WHERE code = 'PROMO20'` and `apply_discount()`.

**The problem:** During that time gap, another request can perform its **own check** and still see the old state (coupon not yet used), because the first request hasn't finished updating it yet.

#### Visual Timeline of a TOCTOU Attack

```
Timeline →

Request A:  ──[CHECK: coupon unused?]──────────────[ACT: mark used + apply discount]──
                    ↓                                         ↓
              reads used=0                              writes used=1
              (sees: valid)                             (discount applied ✓)

Request B:  ────────[CHECK: coupon unused?]──────────────[ACT: mark used + apply discount]──
                         ↓                                         ↓
                   reads used=0                              writes used=1
                   (STILL sees: valid,                       (discount applied AGAIN ✓)
                    because A hasn't
                    written yet)

                         ↑
                    THIS IS THE RACE WINDOW
                    (A has checked but not yet acted)
```

Both requests see `used = 0` because they both checked **before** either one updated the value. The coupon gets applied twice.

#### Why Microseconds Matter

Modern databases can process a simple `SELECT` query in **0.1 to 2 milliseconds**. The `UPDATE` that follows might take another **0.5 to 5 milliseconds**. That means the race window can be as small as **1-5 milliseconds** — but that is more than enough time for another request to slip through, especially when the attacker sends many requests simultaneously.

### 2.4 Understanding Atomicity — The Core Defense Concept

**Atomicity** means "all or nothing." An atomic operation either completes entirely or doesn't happen at all — there is no in-between state visible to other operations.

#### Non-Atomic (Vulnerable):
```
Step 1: Read the coupon status        ← Other requests CAN see state here
Step 2: Apply the discount            ← Other requests CAN see state here  
Step 3: Mark coupon as used           ← State finally updated
```

Each step is a separate database query. Between steps, the database is in an **inconsistent state** where the coupon has been read as valid but not yet marked as used. Other concurrent requests can observe this inconsistent state.

#### Atomic (Safe):
```
[BEGIN TRANSACTION + LOCK]
  Step 1: Read the coupon status      ← Other requests are BLOCKED
  Step 2: Apply the discount          ← Other requests are BLOCKED
  Step 3: Mark coupon as used         ← Other requests are BLOCKED
[COMMIT TRANSACTION]
                                      ← Other requests can now proceed
```

Inside a transaction with proper locking, all steps execute as a single indivisible unit. No other transaction can read the coupon row until this transaction commits.

### 2.5 The Exact Developer Assumption That Breaks

The developer writes code like this mentally:

```
if coupon is not used:
    apply discount
    mark coupon as used
```

They think of this as **one operation**, but the computer executes it as **three separate operations** with time gaps between them. The developer's mental model is **sequential** (one user at a time), but the server handles **concurrent** requests.

This is called the **single-user assumption** — the developer tests with one browser, sees it work correctly, and ships it. They never test what happens when two users (or one attacker with parallel requests) hit the same endpoint at the same time.

### 2.6 Real Life Analogy (Expanded)

Two people walk into different branches of the same bank at the exact same moment. Both want to withdraw the last $100 from a shared account.

- Teller A checks the balance → sees $100 → approves withdrawal.
- At the exact same moment, Teller B also checks the balance → still sees $100 (because Teller A hasn't finished updating the account) → also approves withdrawal.

The bank loses $100 because the check and the deduction were not performed as one unbreakable action.

**Why the analogy works precisely:** Each bank teller is like a separate server thread processing a request. The shared bank account is like the shared database row. The delay between checking the balance and updating it is the race window.

**How the bank fixes it in real life:** They use a **lock** — when one teller starts a withdrawal, the account is temporarily "locked" so no other teller can check or modify it until the first transaction completes. This is exactly what `SELECT ... FOR UPDATE` does in a database.

### 2.7 Three Required Conditions for a Race Condition

For a race condition to be exploitable, **all three** conditions must be true:

| # | Condition | What It Means | How to Verify |
|---|---|---|---|
| 1 | **Check-then-act sequence exists** | The application reads some state and then makes a decision based on that state in separate steps | Read the application logic or observe behavior (e.g., "coupon applied" followed by "coupon already used") |
| 2 | **The operations are not atomic** | There is no database transaction, lock, or mutex protecting the sequence | Attempt to trigger the race — if it ever succeeds, the operations are not atomic |
| 3 | **Attacker can send concurrent requests** | The endpoint does not serialize requests (e.g., no per-user request queuing) | Send parallel requests using Burp Repeater groups or Turbo Intruder |

> **Important:** If any one of these conditions is missing, the race condition cannot be exploited. For example, if the developer uses `SELECT ... FOR UPDATE`, condition 2 is eliminated, and the race window disappears.

### 2.8 What Race Conditions Can and Cannot Do

**Can do:**
- Allow one-time-use resources (discount codes, vouchers, referral bonuses) to be used multiple times
- Bypass usage limits and rate limits in some cases (e.g., "only 1 vote per user" → vote multiple times)
- Cause financial loss through duplicate withdrawals, transfers, or refunds
- Bypass invite-only registration (use one invite code many times)
- Escalate privileges if role assignment has a check-then-act pattern

**Cannot do:**
- Work reliably if the critical operation is properly protected with atomic transactions or row-level locking
- Bypass limits that are enforced at the database constraint level (e.g., a `UNIQUE` constraint on `(user_id, coupon_code)`)
- Work if the server serializes all requests through a single queue (rare but possible)

### 2.9 Where Race Conditions Commonly Hide

| Feature | Vulnerable Operation | What Goes Wrong |
|---|---|---|
| Coupon/discount codes | Check if used → apply → mark used | Discount applied multiple times |
| Account balance | Check balance → deduct | Double withdrawal / overdraft |
| Rate limiting | Check request count → increment counter | Bypass rate limits |
| File upload | Check filename → write file | Overwrite another user's file |
| Voting / Likes | Check if already voted → insert vote | Multiple votes |
| Registration invites | Check invite valid → mark invite used | One invite creates many accounts |
| Account linking | Check if OAuth account linked → link | Link to multiple accounts |

---

## 3. Understanding the Tooling

### 3.1 Burp Suite Repeater — Group Tabs and Parallel Send

Burp Suite's **Repeater** tab allows you to group multiple request tabs and send them simultaneously. This is the basic method for testing race conditions.

**How to set it up:**

1. **Capture the request** in Burp Proxy (intercept the coupon application request).
2. **Send to Repeater** (right-click → Send to Repeater, or `Ctrl+R`).
3. **Duplicate the tab** multiple times (right-click the Repeater tab → Duplicate Tab). Create as many copies as you want to send in parallel (e.g., 16-20 tabs).
4. **Create a group**: Select all the tabs → right-click → Add to group → Create new group. Name it something like "Race Test."
5. **Send group in parallel**: Click the dropdown arrow next to "Send" → **Send group in parallel**. This tells Burp to fire all requests at the same time rather than one after another.

### 3.2 Why "Send Group in Parallel" Is Imperfect

When you use "Send group in parallel," Burp attempts to send all requests simultaneously, but there is a critical technical limitation:

**Each request in the group uses its own separate TCP connection.**

This means:
- Each request must independently complete the **TCP three-way handshake** (`SYN → SYN-ACK → ACK`) before the HTTP request can be sent.
- Each handshake takes a slightly different amount of time due to **network jitter** — tiny, unpredictable variations in packet travel time caused by network congestion, routing differences, and OS scheduling.
- By the time all connections are established and all requests are actually sent, they may arrive at the server **milliseconds apart** rather than at the exact same instant.

**Result:** The requests arrive at different times, and some may complete the full check-update cycle before others even arrive. This causes **inconsistent results** — sometimes many succeed, sometimes only one does.

```
What you want:          What actually happens (network jitter):

Request 1  ─→  |       Request 1  ─→      |
Request 2  ─→  |       Request 2  ──→       |
Request 3  ─→  | ←     Request 3  ───→        |
Request 4  ─→  |       Request 4  ─→       |
                        (arrive at different times)
All arrive     ↑
at same time   server
```

> **This limitation is the entire motivation for the single-packet attack technique covered in Day 44.** The single-packet attack eliminates network jitter by packing all requests into a single TCP packet, ensuring they are processed by the server at the exact same instant.

### 3.3 HTTP/2 vs HTTP/1.1 — Why It Matters for Race Conditions

The requests in this lab use **HTTP/2** (notice `HTTP/2` in the request line). This matters because:

| Feature | HTTP/1.1 | HTTP/2 |
|---|---|---|
| Connections | One request per connection (or pipelining, rarely supported) | Multiple requests **multiplexed** over a single connection |
| Parallel requests | Requires multiple TCP connections | Can send many requests over **one** TCP connection |
| Single-packet attack | Not feasible (separate connections = separate packets) | **Feasible** — multiple requests can fit in one TCP packet |

HTTP/2's multiplexing is what makes the **single-packet attack** (Day 44) possible. Since multiple HTTP/2 requests can share one TCP connection, an attacker can craft a single TCP packet containing multiple complete HTTP/2 requests, ensuring they all arrive at the server simultaneously with zero network jitter.

---

## 4. Lab Completed

### Lab 1: Limit Overrun Race Conditions

**Goal:** Redeem a one-time-use discount code more than once.

#### How it worked (Step by Step)

1. **Browse the application** — Login with provided credentials (`wiener:peter`), add the target item to the cart, and locate the coupon input field on the `/cart` page.

2. **Apply the coupon normally** — Enter `PROMO20` in the coupon field and submit. Observe the discount being applied. This generates the POST request we need.

3. **Capture the request** — In Burp Proxy, find the `POST /cart/coupon` request. This is the request that applies the coupon.

4. **Understand the server-side logic** — The server receives the coupon code, checks if it has already been applied to this user's cart, and if not, applies the discount and marks it as used. These are separate operations with a race window between them.

5. **Prepare parallel requests** — Send the captured request to Burp Repeater. Duplicate it into 16+ tabs. Group all tabs together.

6. **Reset the cart** — Remove the coupon from the cart (important: you need to start from a clean state where the coupon has NOT been applied).

7. **Send group in parallel** — Fire all 16 requests simultaneously using "Send group in parallel."

8. **Analyze responses** — Check each tab's response. Some return "Coupon applied" (success), others return "Coupon already applied" (failure). The ones that succeeded all slipped through the race window.

#### Exact Request Sent

```
POST /cart/coupon HTTP/2
Host: 0a4600fd0358083984f84bd700c900ae.web-security-academy.net
Cookie: session=9yMb0SM31us5CeYMw8GtXwDOYKwEqPUy
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: https://0a4600fd0358083984f84bd700c900ae.web-security-academy.net
Referer: https://0a4600fd0358083984f84bd700c900ae.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

csrf=p5URIrodJzejAcz3yVXElNWigGahV3Rl&coupon=PROMO20
```

#### Understanding Each Header in the Request

| Header | Purpose | Relevance to Race Condition |
|---|---|---|
| `POST /cart/coupon HTTP/2` | The method (POST), path (`/cart/coupon`), and protocol (HTTP/2). This tells the server to apply a coupon to the cart. | This is the vulnerable endpoint. HTTP/2 enables multiplexing which is critical for the single-packet attack (Day 44). |
| `Host` | Identifies which virtual host on the server should handle the request. Required in HTTP/2. | Lab-specific — identifies your unique lab instance. |
| `Cookie: session=...` | The session cookie that authenticates you as the user `wiener`. The server uses this to know which cart to apply the coupon to. | **Critical** — all parallel requests must use the same session cookie so they all target the same cart/account, creating the race condition on shared state. |
| `Content-Type: application/x-www-form-urlencoded` | Tells the server the body is form data (key=value pairs separated by `&`). | Standard for HTML form submissions. The server parses the body as form fields. |
| `Content-Length: 52` | The size of the request body in bytes. The server uses this to know when the body ends. | Must match the actual body length. If you modify the body, update this header (Burp does this automatically). |
| `csrf=...&coupon=PROMO20` | The request body. Contains the CSRF token (anti-forgery protection) and the coupon code `PROMO20`. | `coupon=PROMO20` is the payload. Every parallel request sends the same coupon code, racing to apply it before the server marks it as used. |
| `Origin` / `Referer` | Tell the server where the request originated from. Used for CSRF protection and access control. | Must match the lab domain, otherwise the server may reject the request. |
| `Upgrade-Insecure-Requests: 1` | Browser hint that it prefers HTTPS. | Not relevant to the attack, but part of the original browser request. |
| `Sec-Fetch-*` headers | Metadata about how the request was initiated (by a document navigation, from the same origin, by a user action). | The server may use these for additional security checks. Keeping them unchanged ensures the request is accepted. |

#### Responses Observed

**Success Response:**
```
HTTP/2 302 Found
Location: /cart
X-Frame-Options: SAMEORIGIN
Content-Length: 14

Coupon applied
```

**Failure Response (when race window was missed):**
```
HTTP/2 302 Found
Location: /cart?couponError=COUPON_ALREADY_APPLIED&coupon=PROMO20
X-Frame-Options: SAMEORIGIN
Content-Length: 22

Coupon already applied
```

#### Understanding the Response Differences

| Aspect | Success Response | Failure Response |
|---|---|---|
| **Status Code** | `302 Found` (redirect) | `302 Found` (redirect) |
| **Location header** | `/cart` (clean redirect, no error) | `/cart?couponError=COUPON_ALREADY_APPLIED&coupon=PROMO20` (redirect with error parameter) |
| **Body** | `Coupon applied` (14 bytes) | `Coupon already applied` (22 bytes) |
| **What happened server-side** | Request arrived during the race window — the check passed (coupon was still marked unused) and the discount was applied | Request arrived **after** another request had already completed the update — the check failed (coupon was already marked used) |
| **Content-Length** | 14 | 22 |

> **Detection Tip:** When testing for race conditions, you can quickly identify winners and losers by sorting responses by `Content-Length` or by the `Location` header. Different lengths or redirect URLs indicate different outcomes.

#### Observations
- Sent **16 requests** in parallel.
- Observed clear **inconsistency** (e.g., sometimes 2 out of 4 requests succeeded).
- This inconsistency is caused by network jitter when using separate TCP connections.
- **The inconsistency itself is evidence** — if the coupon logic were truly atomic, you would see exactly 1 success and 15 failures every time. Variable results prove the race window exists.

---

## 5. Why the Technique Is Unreliable (Deep Analysis)

The basic parallel request method suffers from **network jitter**. Here is what happens at each layer:

### Layer-by-Layer Breakdown

```
Application Layer (HTTP):    "Send 16 requests simultaneously"
                                    ↓
Transport Layer (TCP):       Each request needs its own TCP connection.
                             16 separate three-way handshakes.
                             Each handshake takes a slightly different time.
                                    ↓
Network Layer (IP):          16 separate IP packets travel through
                             different network paths (routing).
                             Each encounters different congestion.
                                    ↓
Server's TCP Stack:          Packets arrive at different times.
                             Server processes them in arrival order.
                                    ↓
Application Logic:           Some requests complete the check+update
                             cycle before others even arrive.
                             Race window may close before all requests
                             get a chance to exploit it.
```

### Quantifying the Problem

| Factor | Typical Range | Impact |
|---|---|---|
| TCP handshake variance | 0.5 - 5 ms per connection | Requests start at different times |
| Network jitter | 0.1 - 10 ms | Packets arrive at different times |
| Race window size | 1 - 5 ms (for simple DB operations) | The window you're trying to hit |
| Server processing time | 0.1 - 2 ms per request | How fast the server closes the window |

If your requests arrive spread across **10ms** but the race window is only **2ms**, only the requests that happen to arrive during those 2ms will succeed. The rest will see the updated state and fail.

> **This is the key limitation that Day 44 (Single-Packet Attack) solves.** By packing all HTTP/2 requests into a single TCP packet, the network jitter is reduced to **zero** — all requests are received by the server at the exact same instant.

---

## 6. Chain Thinking

**Race Condition on one-time discount code**  
↓ (Multiple successful applications in the race window)  
**Combine with business logic** (discounts can stack)  
↓  
**Apply the same high-value discount many times**  
↓  
**Order total becomes zero or negative**  
↓  
**Significant financial impact**

### Why This Chain Matters

In real-world bug bounties, a race condition that applies a 5% discount twice is **low severity**. But if the same race condition can be used to stack a 20% discount 5 times (100% off), that becomes **critical severity** because it enables purchasing items for free.

The chain thinking transforms a "maybe interesting" bug into a "definitely critical" finding.

---

## 7. The Fix (Detailed Explanation)

### Vulnerable Pattern:
```python
discount = db.query("SELECT * FROM coupons WHERE code = ? AND used = 0", code)
if discount:
    db.execute("UPDATE coupons SET used = 1 WHERE code = ?", code)
    apply_discount(user_id, discount.percent)
```

**Why this is vulnerable — line by line:**

1. `db.query("SELECT ... AND used = 0")` — This reads the coupon status. If `used = 0`, the coupon is available. **But this read is not locked** — other requests can read the same row at the same time and also see `used = 0`.

2. `if discount:` — The code branches based on stale data. By the time this line executes, another request may have already started its own `SELECT` and also seen `used = 0`.

3. `db.execute("UPDATE ... SET used = 1")` — This finally marks the coupon as used, but it's **too late** — other requests have already passed the check in step 1.

4. `apply_discount(...)` — The discount is applied. If multiple requests reached this point, the discount is applied multiple times.

### Fixed Pattern (Atomic Transaction + Locking):
```python
with db.transaction():
    discount = db.query(
        "SELECT * FROM coupons WHERE code = ? AND used = 0 FOR UPDATE", code
    )
    if discount:
        db.execute("UPDATE coupons SET used = 1 WHERE code = ?", code)
        apply_discount(user_id, discount.percent)
```

**Why this is safe — line by line:**

1. `with db.transaction():` — Opens a database transaction. All operations inside this block are treated as a single atomic unit. If anything fails, all changes are rolled back.

2. `"SELECT ... FOR UPDATE"` — The `FOR UPDATE` clause does two critical things:
   - **Acquires a row-level lock** on the matched row. No other transaction can read this row with `FOR UPDATE` (or modify it) until this transaction completes.
   - **Eliminates the race window** — if Request B tries to `SELECT ... FOR UPDATE` the same row while Request A holds the lock, Request B will **block (wait)** until Request A's transaction commits or rolls back.

3. `if discount:` — Now this check is safe because the row is locked. No other request can be checking this same row simultaneously.

4. `db.execute("UPDATE ... SET used = 1")` — The update happens while the lock is still held.

5. When the `with` block exits, the transaction **commits** — the lock is released, and Request B (which has been waiting) can now proceed. But when Request B's `SELECT ... FOR UPDATE` finally executes, it sees `used = 1` and the `if discount:` check fails. The race is eliminated.

### Alternative Fix — Single Atomic UPDATE

An even simpler fix uses a single SQL statement that combines the check and the update:

```python
rows_affected = db.execute(
    "UPDATE coupons SET used = 1 WHERE code = ? AND used = 0", code
)
if rows_affected == 1:
    apply_discount(user_id, discount.percent)
```

**Why this works:** A single `UPDATE` statement with a `WHERE` clause is inherently atomic in most databases. The database engine locks the row, checks the condition, and updates it — all in one step. If two requests execute this simultaneously, the database ensures only one will match the `WHERE used = 0` condition and return `rows_affected = 1`. The other will get `rows_affected = 0` and the discount won't be applied.

---

## 8. Key Concepts Summary

| Concept | Description | Why It Matters |
|---|---|---|
| TOCTOU | Time Of Check To Time Of Use — the gap between reading state and acting on it | Core flaw behind most race conditions |
| Non-atomic operation | Check and act performed as separate database queries without a transaction or lock | Creates the exploitable time window between check and act |
| Race Window | The brief period (often 1-5ms) where shared state is inconsistent | The window the attacker must hit with concurrent requests |
| Network Jitter | Small, unpredictable timing variations between packets on different TCP connections | Makes basic parallel attacks unreliable — requests don't arrive simultaneously |
| Inconsistency | Varying success rate across repeated attempts of the same attack | Clear diagnostic sign that a race condition exists (atomic operations produce consistent results) |
| Atomicity | An operation that completes fully or not at all, with no visible intermediate state | The defense concept — making check+act into a single indivisible operation |
| `SELECT ... FOR UPDATE` | SQL clause that acquires a row-level lock, blocking other transactions from reading/writing that row | Primary database-level defense against race conditions |
| HTTP/2 Multiplexing | Multiple HTTP requests sharing a single TCP connection | Enables the single-packet attack (Day 44) by eliminating per-request connection overhead |
| Single-Packet Attack | Packing multiple HTTP/2 requests into one TCP packet to eliminate network jitter | The reliable exploitation technique (covered in Day 44) |

---

## 9. Foundation Checklist

### Conceptual Understanding
- [ ] What does TOCTOU stand for and why does it matter?
- [ ] Draw the timeline showing how two concurrent requests can both pass a check before either updates the state.
- [ ] Explain the difference between a non-atomic and an atomic operation. Give a database example of each.
- [ ] What are the three conditions required for a race condition to be exploitable?
- [ ] Why do web servers handle requests concurrently, and how does this enable race conditions?

### Technical Understanding
- [ ] Why do normal parallel requests often produce inconsistent results?
- [ ] What is network jitter and at which layer does it occur?
- [ ] How does HTTP/2 multiplexing differ from HTTP/1.1 in the context of race condition attacks?
- [ ] What does `SELECT ... FOR UPDATE` do and why does it eliminate the race window?
- [ ] How does a single atomic `UPDATE ... WHERE` query prevent race conditions without explicit locking?

### Practical Understanding
- [ ] If a developer says they added rate limiting, can race conditions still occur? *(Yes — rate limiting typically has its own check-then-act pattern that may itself be vulnerable to race conditions.)*
- [ ] How can race conditions lead to financial loss? Give three examples.
- [ ] How do you distinguish a successful race condition exploitation from normal application behavior by looking at responses?
- [ ] Why is the inconsistency in results actually **evidence** of the vulnerability rather than a failure of the attack?

---

*Day 43 complete. Strong understanding of basic race condition exploitation and its limitations built. Ready for Day 44 (Single-Packet Attack Technique).*