# Day 25 — Business Logic Vulnerabilities Part 2
**Date:** May 8, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 6 Labs
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was the second day of business logic vulnerabilities — covering the more advanced and creative patterns. We completed 6 PortSwigger labs: integer overflow to generate negative order totals, input truncation to craft privileged email addresses, authentication state machine bypass by dropping a key request, infinite money loop by chaining gift cards with discount coupons, encryption oracle to forge admin session tokens, and email parser discrepancy to bypass access controls. These labs represent the hardest class of business logic bugs — the ones that require deep reasoning about how systems behave at their edges.

---

## 2. The Foundation — What Today Adds to Yesterday

### Three New Categories Beyond Day 24

**Category 1 — Arithmetic flaws:**
What happens when numbers exceed the limits of the data type storing them? Prices stored as integers can overflow — wrap from a huge positive number to a negative number. The developer never considered that a user could add enough items to trigger an integer overflow.

**Category 2 — Exceptional input handling:**
What happens when input is much longer, much larger, or structurally different from what the developer expected? Truncation, parsing differences, and edge case handling create gaps between what the developer intended and what the code does.

**Category 3 — Flawed state machines:**
Multi-step processes have states — logged out, partially authenticated, fully authenticated, admin. What happens if you skip a state transition, drop a request that should change state, or send requests out of order? The application may end up in a state the developer never intended.

### Integer Overflow — The Core Arithmetic Concept

Computers store numbers in fixed-size containers. A 32-bit signed integer can store values from **-2,147,483,648 to 2,147,483,647**. If a number exceeds the maximum positive value — it does not stay at the maximum. It **wraps around to the most negative number** and starts counting up from there.

```
2,147,483,647 + 1 = -2,147,483,648   (overflow — wraps to most negative)
```

In an e-commerce application — if the order total is stored as a 32-bit integer and you add enough items to push the total past 2,147,483,647 — the total wraps to a massive negative number. A negative order total means the application owes you money. You can then add cheaper items to bring the total back to just above zero — and place the order for effectively free.

### State Machine Thinking

Applications can be modeled as state machines:
```
State 0: Not logged in
State 1: Username + password verified (partially authenticated)
State 2: 2FA or role selection completed (fully authenticated)
State 3: Admin privileges granted
```

Every state transition requires a specific action. The question is: **what happens if you skip a transition, drop a request mid-flow, or send requests out of expected order?** If the application grants the highest privilege state when a step is dropped — you get admin without earning it.

### Encryption Is Not Authentication

Encryption guarantees confidentiality — it scrambles data so it cannot be read without the key. It does NOT guarantee that the encrypted content is trustworthy. If an attacker can control what gets encrypted using the application's own key — they can craft encrypted tokens with arbitrary content. The server decrypts them and trusts them because they are "properly encrypted" — but the content was crafted by the attacker.

---

## 3. Lab Walkthroughs

---

### Lab 1 — Low-Level Logic Flaw ✅

**Vulnerability type:** Integer overflow — adding enough items pushes cart total past 32-bit integer maximum, wrapping to a large negative number

**What this lab proves:** Arithmetic limits of data types are a security boundary. Developers rarely test what happens at the extreme edges of numeric ranges. A negative cart total allows purchasing items for free.

**How it was solved:**

Logged in as `wiener:peter`. Added the leather jacket to cart. Used Burp Intruder with Null payloads set to continue indefinitely — sending requests that added 99 jackets per request. Watched the cart total climb to a very large positive number then suddenly flip to a large negative number — the integer overflow point. Stopped the Intruder attack. Added a cheaper product in small quantities to bring the total from a large negative number back to a small positive amount within the $100 budget. Placed the order.

**Why it worked:**

The application stored the cart total as a fixed-size integer — likely a 32-bit signed integer with a maximum value of 2,147,483,647. The developer never validated that the total stays within a reasonable range. Adding enough items at $1337 each pushed the stored value past the maximum — the value wrapped to a large negative number. A negative total means the store owes the attacker money. Adding cheap items brought the total back to a small positive amount within budget.

**Intruder setup:**
```
Attack type: Sniper
Position: quantity=§99§ (99 jackets per request — maximum per request)
Payload type: Null payloads
Setting: Continue indefinitely
Resource pool: Maximum concurrent requests = 1
Watch: Cart total in browser — wait for flip from large positive to large negative
Stop: When total becomes negative
Then: Add cheap items to bring total to small positive within $100 budget
```

**The vulnerable pattern:**
```python
# Vulnerable — no range check on total
def calculate_total(cart):
    total = 0
    for item in cart:
        total += item.price * item.quantity   # Can overflow if unchecked
    return total                              # Returns negative if overflowed

# Fixed — validate total stays in reasonable range
def calculate_total(cart):
    total = 0
    for item in cart:
        total += item.price * item.quantity
        if total > MAX_ORDER_VALUE or total < 0:   # Catches overflow
            raise ValueError("Invalid order total")
    return total
```

---

### Lab 2 — Inconsistent Handling of Exceptional Input ✅

**Vulnerability type:** Input truncation — abnormally long email address truncated to end with privileged domain after storage

**What this lab proves:** When an application truncates input that is too long — the truncation itself can be exploited to craft input that passes validation at one layer but means something different after truncation at the storage layer.

**How it was solved:**

The admin panel was restricted to `@dontwannacry.com` email addresses. The application truncated email addresses longer than 255 characters when storing them. Crafted an email address that:
- Was long enough to trigger truncation
- After truncation to 255 characters — ended with `@dontwannacry.com`
- Before truncation — was a valid email at the exploit server for receiving verification

**Calculation:**
```
Maximum stored length: 255 characters
@dontwannacry.com = 17 characters
Prefix length needed: 255 - 17 = 238 characters of 'a'
```

**Crafted email:**
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@dontwannacry.com.YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

The verification email went to the exploit server (the full address before truncation). After storage — the email was truncated to `aaa...@dontwannacry.com`. Verified the account, logged in, navigated to `/admin` — access granted. Deleted carlos.

**Why it worked:**

Two different layers of the application handled the same email differently:
- **Validation layer:** accepted the full long address as a valid email format — sent verification to exploit server
- **Storage layer:** truncated to 255 characters — stored only `aaa...@dontwannacry.com`
- **Access control layer:** read the stored email — saw `@dontwannacry.com` — granted admin access

The gap between how input was processed at validation vs storage was the exploitable difference.

**Key lesson:** Every layer that processes input must handle edge cases consistently. If storage truncates input — validation must reject input that would produce a different meaning after truncation.

---

### Lab 3 — Authentication Bypass via Flawed State Machine ✅

**Vulnerability type:** State machine bypass — dropping the role selection request causes the application to assign a default privileged role

**What this lab proves:** When a multi-step authentication flow assigns a default role for incomplete flows — and that default is the most privileged role rather than the least — dropping a request grants admin access.

**How it was solved:**

Observed the normal login flow as `wiener:peter`:
```
Step 1: POST /login → username + password verified
Step 2: GET /role-selector → role selection page presented
Step 3: POST /role-selector → role selected → account page
```

Logged out. Turned Burp Intercept ON. Logged in as `wiener:peter`. The login POST request appeared — forwarded it. The redirect to the role selection page appeared — **dropped this request entirely** instead of forwarding. Turned Intercept OFF. Navigated manually to `/admin`.

**Expected result:** Admin panel accessible. The application assigned the default role when the role selection step was dropped — and that default was administrator. Deleted carlos.

**Why it worked:**

The developer built a role selection step assuming users would always complete it. When the step was dropped — the application needed to assign some default role. Instead of defaulting to the least privileged role (regular user) — it defaulted to the most privileged role (admin). The developer never tested what happens when the role selection request is never sent.

**The vulnerable pattern:**
```python
# Vulnerable — insecure default when step is skipped
def complete_login(request):
    if request.session.get('role_selected'):
        role = request.session['selected_role']
    else:
        role = 'administrator'    # ← insecure default

# Fixed — force completion of the step, default to least privilege
def complete_login(request):
    if not request.session.get('role_selected'):
        return redirect('/role-selector')   # Force the step
    role = request.session['selected_role']

# Or if defaulting is necessary:
    role = request.session.get('selected_role', 'user')  # ← least privilege default
```

**State machine diagram:**
```
Normal flow:
[Not logged in] → [Credentials verified] → [Role selected] → [Authenticated user]

Exploit flow:
[Not logged in] → [Credentials verified] → [Role selection DROPPED] → [Default: Admin]
```

---

### Lab 4 — Infinite Money Logic Flaw ✅

**Vulnerability type:** Business logic loop — gift card purchase with discount coupon generates net profit per cycle

**What this lab proves:** Two individually reasonable features — gift cards and discount coupons — combine to create an infinite money loop. Neither feature alone is broken. Their interaction is the vulnerability.

**How it was solved:**

Logged in as `wiener:peter`. Identified two features:
- Gift card product: costs $10, redeems for $10 store credit
- Newsletter signup coupon: 30% discount on purchases

**The loop:**
```
Buy $10 gift card with 30% coupon → pay $7 → receive $10 gift card
Redeem $10 gift card → store credit becomes $10
Net gain per cycle: $3
```

Confirmed the loop manually once. Then automated using Burp Macro:

**Macro setup — four requests in sequence:**
1. POST to add gift card to cart
2. POST to apply coupon code
3. POST to place order
4. POST to redeem gift card code

**Session handling rule:** Run macro on each Intruder request.

**Intruder:** Null payloads, ran enough iterations to accumulate store credit exceeding $1337 (leather jacket price). Each cycle netted $3 — ran approximately 450 cycles. Purchased the leather jacket with accumulated credit.

**Why it worked:**

The developer implemented gift cards and discount coupons as independent features. Neither feature alone is broken:
- Gift cards: buy $10, get $10 — fair exchange
- Coupons: get 30% off — legitimate discount

Combined: buying a $10 gift card with 30% off costs $7 but redeems for $10 — a $3 profit per transaction. The developer never analyzed the interaction between features. This is the hardest class of business logic bug to find — it requires understanding how multiple features interact, not just how each one works in isolation.

**Burp Macro steps:**
```
Settings → Sessions → Macros → Add
Select requests in order:
1. Add gift card to cart
2. Apply coupon
3. Place order
4. Redeem gift card

Settings → Sessions → Session handling rules → Add
Action: Run macro
Scope: Gift card and checkout URLs

Intruder → Null payloads → Run ~450 iterations
Monitor store credit until it exceeds jacket price
Purchase jacket with accumulated credit
```

---

### Lab 5 — Authentication Bypass via Encryption Oracle ✅

**Vulnerability type:** Encryption oracle — same encryption key used for stay-logged-in tokens and notification cookies allows crafting arbitrary encrypted tokens

**What this lab proves:** Encryption is not authentication. When the same encryption function and key are used for both security tokens and user-facing features — an attacker can use the accessible feature as an oracle to encrypt content of their choosing.

**How it was solved:**

Logged in as `wiener:peter` with Stay logged in checked. Found the `stay-logged-in` cookie — an encrypted token. Found that submitting an invalid email in the blog comment feature generated an encrypted notification cookie using the same encryption key.

**Steps:**
1. Decrypted own `stay-logged-in` cookie via the notification feature — observed format: `wiener:TIMESTAMP`
2. Submitted `administrator:TIMESTAMP` as an invalid email in the comment form — received encrypted notification cookie
3. Used Burp Decoder to handle block cipher padding — removed the padding prefix bytes from the encrypted value
4. Set the crafted encrypted value as the `stay-logged-in` cookie
5. Navigated to `/admin` — recognized as administrator
6. Deleted carlos

**Why it worked:**

The application used the same encryption key and function for two completely different purposes:
- **Stay-logged-in cookie:** encrypted `username:timestamp` — security token
- **Notification cookie:** encrypted error message — user-facing feature

By using the notification feature as an encryption oracle — we encrypted content of our choosing using the application's own key. The resulting ciphertext was accepted as a valid stay-logged-in token because it was genuinely encrypted with the correct key. The server decrypted it, saw `administrator:timestamp`, and granted admin access.

**The core lesson — encryption vs authentication:**
```
Encryption guarantees: No one can READ the content without the key
Encryption does NOT guarantee: The content itself is trustworthy

If the attacker controls what gets encrypted:
→ They can create validly encrypted tokens with arbitrary content
→ The server decrypts and trusts it — it is "properly encrypted" after all
→ Authentication bypassed
```

**The vulnerable pattern:**
```python
# Vulnerable — same key for different purposes
SHARED_KEY = 'secret'

def create_stay_logged_in(username):
    return encrypt(f"{username}:{timestamp()}", SHARED_KEY)

def create_notification(message):
    return encrypt(message, SHARED_KEY)    # Same key — oracle available

# Fixed — separate keys for different purposes
STAY_LOGGED_IN_KEY = secrets.token_bytes(32)
NOTIFICATION_KEY = secrets.token_bytes(32)

def create_stay_logged_in(username):
    return encrypt(f"{username}:{timestamp()}", STAY_LOGGED_IN_KEY)

def create_notification(message):
    return encrypt(message, NOTIFICATION_KEY)   # Different key — no oracle
```

---

### Lab 6 — Bypassing Access Controls Using Email Address Parsing Discrepancies ✅

**Vulnerability type:** Parser differential on email addresses — different components parse the same email differently, allowing registration with an address that sends verification to attacker but stores as privileged domain

**What this lab proves:** When different components of the same application parse email addresses using different rules — the same email string can mean different things to different parts of the system. This gap is exploitable.

**How it was solved:**

The admin panel was restricted to `@dontwannacry.com` email addresses. Found that different email parsing components interpreted the `@` symbol differently — specifically when multiple `@` symbols appeared in the address.

Registered with an email in this format:
```
attacker@exploit-server.net@dontwannacry.com
```

- **Verification sender:** parsed the first `@` as the domain separator — sent verification email to `exploit-server.net`
- **Access control checker:** parsed the last `@` as the domain separator — read domain as `dontwannacry.com` — granted admin access

Received verification email at exploit server. Verified account. Logged in. Navigated to `/admin` — full access. Deleted carlos.

**Why it worked:**

Email address parsing is governed by RFC 5321 — a complex specification with many edge cases. Different email parsing libraries implement the RFC differently — or make different decisions about ambiguous cases like multiple `@` symbols. The verification component and the access control component used different parsers or different parsing logic. The same email string was interpreted as two different addresses by two different parts of the same application.

**Connection to Day 22 SSRF whitelist bypass:**

This is the same class of vulnerability as the SSRF whitelist parser differential:

| Lab | Component 1 interpretation | Component 2 interpretation | Gap exploited |
|-----|---------------------------|---------------------------|---------------|
| SSRF whitelist | Filter sees trusted host | HTTP client sees localhost | Fetch internal resource |
| Email parser | Verification sends to exploit server | Access control sees privileged domain | Bypass domain restriction |

Both exploit the fact that two components of the same system understand the same input differently.

**The vulnerable pattern:**
```python
# Vulnerable — different parsers used for verification vs access control
def register(email):
    send_verification(email)                    # Uses Parser A — first @ is separator
    store_email(email)                          # Uses Parser B — last @ is separator

def check_admin_access(stored_email):
    domain = stored_email.split('@')[-1]        # Gets dontwannacry.com
    return domain == 'dontwannacry.com'         # Grants admin

# Fixed — use the same parser everywhere, validate email format strictly
def register(email):
    normalized = normalize_email(email)         # Single parsing function
    if not is_valid_email(normalized):          # Strict validation
        return error("Invalid email")
    send_verification(normalized)               # Same normalized form
    store_email(normalized)                     # Same normalized form
```

---

## 4. Vulnerable Source Code — Advanced Patterns

**Integer overflow — the arithmetic flaw:**
```python
# Vulnerable — no bounds check
total = sum(item.price * item.quantity for item in cart)
# At 2,147,483,647 + 1 → wraps to -2,147,483,648

# Fixed
MAX_CART_VALUE = 10_000_00  # $10,000 in cents
total = sum(item.price * item.quantity for item in cart)
if not (0 < total <= MAX_CART_VALUE):
    raise ValueError("Cart total out of valid range")
```

**Truncation exploit:**
```python
# Vulnerable — truncates after validation
def register(email):
    if is_valid_email(email):           # Validates full email
        stored_email = email[:255]      # Truncates — meaning changes
        save(stored_email)

# Fixed — validate the truncated form
def register(email):
    truncated = email[:255]
    if is_valid_email(truncated):       # Validate what will actually be stored
        save(truncated)
```

**Infinite money loop — feature interaction:**
```python
# Vulnerable — no interaction check between discount and gift card redemption
def apply_coupon(cart, coupon):
    cart.total *= (1 - coupon.discount)   # 30% off gift cards too

# Fixed — exclude gift cards from coupon discounts
def apply_coupon(cart, coupon):
    for item in cart.items:
        if item.type != 'gift_card':      # Gift cards excluded
            item.price *= (1 - coupon.discount)
```

---

## 5. Chain Thinking — Business Logic to Infrastructure Compromise

```
Today's vulnerability: Authentication bypass via flawed state machine
        ↓
Combines with: Infinite money loop (Lab 4)
        ↓
Combined impact: Admin access + unlimited store credit + free merchandise
        ↓
Further chain: Admin access → export all user data → sell PII
        ↓
Severity: Critical financial damage + data breach
```

**The full attack chain:**
```
Step 1: Bypass state machine → gain admin access
        Login → drop role selection request → default admin role assigned
        Navigate to /admin → full admin panel

Step 2: Exploit infinite money loop
        Buy gift card with coupon → $7 cost → $10 credit
        Automate 500 cycles → $1,500 store credit accumulated

Step 3: Admin panel access
        Export all customer data (names, emails, addresses, payment info)
        Access all orders and transaction records

Step 4: Combined damage
        $1,500+ in merchandise obtained for free
        All customer PII exfiltrated
        Full application control maintained
        Financial damage + data breach + regulatory liability
```

**Real world scenario:** A retail platform has both a flawed role selection state machine and a gift card discount loop. An attacker gains admin access by dropping the role selection request, generates unlimited store credit through the gift card loop, and exfiltrates all customer data from the admin panel. Combined bug bounty value: **$15,000–$50,000** depending on platform size and data sensitivity.

---

## 6. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|------------------|--------------|
| Integer overflow in cart | Purchase expensive items for free via arithmetic wrap | $1,000 – $8,000 |
| Input truncation privilege escalation | Admin access via crafted long email | $1,000 – $5,000 |
| State machine bypass | Admin access by dropping one request | $2,000 – $10,000 |
| Infinite money loop | Unlimited store credit from $0 starting balance | $2,000 – $15,000 |
| Encryption oracle | Forge admin session tokens using accessible feature | $3,000 – $15,000 |
| Email parser discrepancy | Admin access via ambiguous email format | $1,000 – $5,000 |

Business logic vulnerabilities at the complexity level of today's labs routinely pay in the $5,000–$15,000 range on major platforms — because they require human reasoning that automated tools cannot replicate.

---

## 7. The Fix — Defense in Depth

**Integer overflow:**
Validate that numeric totals stay within reasonable bounds after every calculation. Use arbitrary precision arithmetic for financial calculations — never rely on fixed-size integer types for money.

**Input truncation:**
Validate the normalized, truncated form of input — not the raw input before truncation. If storage truncates to N characters — validation must reject any input that would produce a different semantic meaning after truncation.

**State machine:**
Every protected endpoint must independently verify that all required prior steps were completed. Default to the least privileged state when steps are incomplete — never the most privileged. Force re-completion of skipped steps rather than assigning defaults.

**Feature interaction:**
Analyze combinations of features — not just individual features in isolation. Explicitly test whether applying discount X to product type Y produces an unintended financial outcome. Gift cards and coupons are a known dangerous combination.

**Encryption oracle:**
Use separate encryption keys for separate purposes. Never reuse a key across security tokens and user-facing features. Consider using authenticated encryption (AES-GCM) which ties the ciphertext to its purpose — a token encrypted for one purpose cannot be used for another.

**Parser discrepancies:**
Use a single, consistent email parsing library across all components. Normalize email addresses to a canonical form immediately on input — store and check only the normalized form. Reject any email that produces different results under different parsing rules.

---

## 8. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| Integer overflow | Numeric value exceeds data type maximum — wraps to most negative value |
| 32-bit signed integer max | 2,147,483,647 — adding 1 wraps to -2,147,483,648 |
| Input truncation | Application stores shorter version of input — semantic meaning may change |
| State machine | Model of application as discrete states with defined transitions between them |
| Insecure default | Application assigns most privileged state when a step is skipped |
| Infinite money loop | Two features whose interaction produces net financial gain per cycle |
| Encryption oracle | Accessible feature that encrypts attacker-controlled content using a shared key |
| Encryption ≠ authentication | Encrypted content is not trustworthy if attacker controls what gets encrypted |
| Parser differential | Two components interpret the same input differently — gap is exploitable |
| Feature interaction bug | Vulnerability that only exists when two individually correct features combine |

---

## 9. Payloads and Commands Reference

**Integer overflow — Intruder setup:**
```
Attack type: Sniper
Position: quantity=§99§
Payload type: Null payloads → Continue indefinitely
Resource pool: 1 concurrent request
Watch: Cart total flip from large positive to large negative
```

**Truncation exploit — email format:**
```
[238 x 'a']@dontwannacry.com.[EXPLOIT-SERVER-DOMAIN]
Total before truncation: 238 + 17 + exploit-server-length characters
Total after truncation: 255 characters ending in @dontwannacry.com
```

**State machine bypass:**
```
1. Turn Intercept ON
2. Login with credentials
3. Forward the login POST request
4. DROP the role selection redirect request
5. Turn Intercept OFF
6. Navigate to /admin
```

**Infinite money loop — macro sequence:**
```
Request 1: POST /cart — add gift card
Request 2: POST /cart/coupon — apply SIGNUP30
Request 3: POST /cart/checkout — place order
Request 4: POST /gift-card — redeem gift card code
Run via Intruder null payloads — ~450 iterations for $1337
```

**Encryption oracle — token crafting:**
```
1. Login with Stay logged in → capture stay-logged-in cookie
2. Submit invalid email in blog comment → capture notification cookie
3. Use notification to encrypt: administrator:TIMESTAMP
4. Decode base64 → remove padding prefix bytes → re-encode
5. Set as stay-logged-in cookie value
6. Navigate to /admin
```

**Email parser discrepancy:**
```
Register with: attacker@exploit-server.net@dontwannacry.com
Verification sent to: exploit-server.net (first @ parsed)
Access control reads: dontwannacry.com (last @ parsed)
```

---

## 10. Foundation Checklist

Answer these from memory — not from these notes:

1. **What is integer overflow and why does it create a security vulnerability** in financial applications?
2. **How does input truncation create a privilege escalation path?** What two layers handled the input differently?
3. **What is the insecure default in the state machine lab?** What should the application have done when the role selection step was dropped?
4. **Why does the infinite money loop work?** What two individually reasonable features combined to create the vulnerability?
5. **What is an encryption oracle?** Why does using the same key for two different purposes create a security risk?
6. **What do Labs 2 and 6 have in common at a conceptual level?** Two components handling the same input differently — what is this called and where else did you see it this week?

---