# Day 24 — Business Logic Vulnerabilities Part 1
**Date:** May 7, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 6 Labs
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was entirely focused on business logic vulnerabilities — the most AI-resistant skill in application security. We completed 6 PortSwigger labs covering every core business logic pattern: client-side price manipulation, negative quantity exploitation, post-registration security control bypass, coupon stacking via flawed repeat-use checks, payment workflow bypass, and dual-use endpoint parameter removal. Every lab was solved using only the browser and Burp Suite — zero injection payloads, zero malformed input. Pure logic exploitation.

---

## 2. The Foundation — Why Business Logic Vulnerabilities Exist

### Root Cause

Every other vulnerability class involves injecting unexpected data types or characters to break code. Business logic vulnerabilities are completely different. You use the application exactly as intended — valid inputs, normal requests, real features. The vulnerability is in the **rules the developer forgot to enforce**, not in how the code parses input.

A developer builds an e-commerce site. They implement a discount coupon feature. They write code that applies the coupon. They forget to check whether the coupon has already been used. That is a business logic flaw — not a code bug, a **design flaw**.

The root cause: developers think about the **happy path** — what happens when everything works correctly. They forget to think about what happens when a user behaves unexpectedly — negative quantities, skipped steps, replayed requests, combined discount stacks. They enforce rules in one place and forget to enforce them everywhere else the rule applies.

**This is why automated scanners cannot find business logic vulnerabilities.** A scanner sends malformed input and looks for error messages or crashes. Business logic flaws produce no errors — the application works perfectly, it just does something it was never supposed to do.

### Real World Analogy

Imagine a supermarket self-checkout machine. The rules are: scan every item, pay the total, leave with your items. A business logic flaw would be: the machine checks that you scanned items and that you paid — but never checks that the amount paid matches the items scanned. You scan a cheap item, then place an expensive item in the bagging area without scanning it. The machine sees weight added and a payment made — it never cross-checked the two. You paid $1 and walked out with $100 of groceries. No hacking. No malformed input. You used the machine exactly as designed — you just found a gap in the rules it enforced.

### Three Conditions for Business Logic Vulnerabilities

1. The application enforces a rule in one place but not everywhere that rule applies
2. The application trusts client-supplied values for business-critical decisions — price, quantity, discount amount
3. The application assumes users will follow the intended workflow — never testing skipped, reversed, or repeated steps

### What Business Logic Vulnerabilities Can and Cannot Do

**Can do:**
- Purchase items for free or at massively reduced prices
- Access features or content not intended for the current user
- Bypass workflow steps — skip payment, skip verification, skip approval
- Accumulate infinite credits, discounts, or rewards
- Elevate privileges by manipulating account data post-registration

**Cannot do:**
- Execute arbitrary code on the server (that is RCE)
- Read other users' data directly (that is IDOR)
- Work if the application validates all business rules server-side consistently

### The Core Mindset — Three Questions for Every Feature

For every feature tested — ask:
```
1. What is this feature SUPPOSED to prevent?
2. What assumptions did the developer make about how users behave?
3. How can I violate those assumptions while staying within normal input bounds?
```

If you can answer question 3 — you have found a business logic vulnerability.

### Technical Vulnerability vs Logic Vulnerability

| Aspect | Technical Vulnerability | Logic Vulnerability |
|--------|------------------------|---------------------|
| How it works | Malformed input breaks the code | Valid input used in unintended way |
| Can scanner find it? | Often yes | Never |
| Requires understanding of | The injection technique | What the application is supposed to do |
| Example | SQLi — `' OR 1=1--` | Price manipulation — change price=1000 to price=1 |
| Fix | Input validation, parameterized queries | Enforce business rules server-side consistently |

### Real World Example — Starbucks 2017

A researcher found that Starbucks gift cards could be used to purchase more gift cards. The balance transfer logic had no check preventing circular transfers. By transferring balance between cards in a loop — the researcher generated unlimited Starbucks credit from a $5 starting balance. Pure business logic flaw — no injection, no malformed input. Payout: **$4,000**. Similar infinite money loops have been found at major retailers paying **$2,000–$15,000**.

---

## 3. Lab Walkthroughs

---

### Lab 1 — Excessive Trust in Client-Side Controls ✅

**Vulnerability type:** Client-side price manipulation — server trusts browser-supplied price value

**What this lab proves:** Any value sent from the browser — including product price — can be intercepted and modified in Burp before it reaches the server. The server must never trust these values.

**How it was solved:**

Logged in as `wiener:peter`. Found the leather jacket (~$1337). Turned Intercept ON and clicked Add to Cart. The frozen POST request body contained:
```
productId=1&redir=PRODUCT&quantity=1&price=133700
```
The price was being sent from the browser to the server. Changed the price parameter to `1` ($0.01):
```
productId=1&redir=PRODUCT&quantity=1&price=1
```
Forwarded the modified request. Cart showed the leather jacket at $0.01. Placed the order — completed successfully.

**Why it worked:**

The developer built the Add to Cart button to send the product price from the browser to the server. The server trusted that price value instead of looking up the real price from its own database. The browser is completely user-controlled — anything sent from the browser can be modified in Burp. The price field should never come from the client.

**The vulnerable pattern:**
```python
# Vulnerable — trusts price from browser request
def add_to_cart(request):
    product_id = request.POST['productId']
    quantity = request.POST['quantity']
    price = request.POST['price']              # ← attacker controls this
    cart.add(product_id, quantity, price)

# Fixed — looks up price from database server-side
def add_to_cart(request):
    product_id = request.POST['productId']
    quantity = request.POST['quantity']
    product = db.get_product(product_id)
    price = product.price                      # ← server looks up real price
    cart.add(product_id, quantity, price)
```

---

### Lab 2 — High-Level Logic Vulnerability ✅

**Vulnerability type:** Negative quantity exploitation — quantity validated as a number but not as a positive number

**What this lab proves:** Validating the data type of input (must be a number) without validating the range (must be positive) allows negative quantities that reduce the cart total — bypassing the price entirely.

**How it was solved:**

Logged in as `wiener:peter`. Account balance: $100. Leather jacket price: ~$1337 — unaffordable normally. Turned Intercept ON, added the leather jacket to cart, modified the quantity to a negative value in the frozen request:
```
quantity=-1
```
The cart total decreased. Added negative quantities of a cheaper item to bring the total to just under $100 while keeping it above $0. Placed the order within the $100 budget.

**Why it worked:**

The server validated that the quantity field contained a number — but never checked that it was a positive number. A negative quantity mathematically reduces the cart total. The business rule "you cannot buy negative items" was never enforced. Quantity of -1 for a $1337 item subtracts $1337 from the total — effectively giving a $1337 discount.

**The vulnerable pattern:**
```python
# Vulnerable — validates type but not range
def add_to_cart(request):
    quantity = int(request.POST['quantity'])   # Validates it is a number
    # Missing: if quantity < 1: reject         # ← no range check
    cart.add(product_id, quantity)

# Fixed — validates range
def add_to_cart(request):
    quantity = int(request.POST['quantity'])
    if quantity < 1:                           # Rejects negative and zero
        return error("Invalid quantity")
    cart.add(product_id, quantity)
```

---

### Lab 3 — Inconsistent Security Controls ✅

**Vulnerability type:** Post-registration security control bypass — email domain restriction enforced at registration but not on email change

**What this lab proves:** Security rules applied only at the point of initial registration can be bypassed by changing account data after registration — if the change feature does not re-validate the same rules.

**How it was solved:**

The admin panel was restricted to `@dontwannacry.com` email domain employees. Registered a new account using the lab's email client — used a real receivable email address for verification. Verified the account and logged in. Went to account settings — changed the email address to:
```
attacker@dontwannacry.com
```
Navigated to `/admin` — full admin panel accessible. Deleted carlos.

**Why it worked:**

The developer restricted admin access to `@dontwannacry.com` email addresses — a reasonable rule. But they only enforced this at registration — assuming users could not change their email to a company address afterward. The email change feature accepted any email including the privileged domain, with no validation against the restricted domain. The security check was applied once at the wrong point in the user lifecycle.

**Key lesson:** Every feature that changes security-relevant data must re-validate all security rules that depend on that data. Registration-time checks are not permanent — users can change their data after the fact.

---

### Lab 4 — Flawed Enforcement of Business Rules ✅

**Vulnerability type:** Coupon stacking — coupon repeat-use check only prevents consecutive use of the same coupon, not alternating use

**What this lab proves:** A business rule implemented as "do not apply the same coupon twice in a row" is not the same as "each coupon can only be used once per order." Alternating between two coupons bypasses the consecutive check entirely.

**How it was solved:**

Logged in as `wiener:peter`. Found two coupon codes:
- `NEWCUST5` — shown on the homepage banner
- `SIGNUP30` — available by signing up to the newsletter

Added the leather jacket to cart. Applied `NEWCUST5` — discount applied. Applied `SIGNUP30` — second discount applied. Attempted `NEWCUST5` again — the application blocked applying the same coupon consecutively. Tried alternating:
```
NEWCUST5 → SIGNUP30 → NEWCUST5 → SIGNUP30 → repeat
```
Each application passed the "not same as last coupon" check. Discounts stacked with each application. Continued alternating until the price dropped within the $100 budget. Placed the order.

**Why it worked:**

The developer implemented a check: do not apply the same coupon twice in a row. They checked only the last applied coupon — not whether a coupon had been used at all in this session. By alternating two coupons — each application passed the consecutive check — and the discounts stacked indefinitely. The intended rule was "each coupon usable once per order" — the implemented rule was "no consecutive duplicate coupons" — completely different enforcement.

**The vulnerable pattern:**
```python
# Vulnerable — only checks last applied coupon
def apply_coupon(cart, coupon):
    if cart.last_coupon == coupon:
        return error("Coupon already applied")    # Only consecutive check
    cart.apply_discount(coupon)
    cart.last_coupon = coupon

# Fixed — checks if coupon was used at all this session
def apply_coupon(cart, coupon):
    if coupon in cart.applied_coupons:            # Tracks all used coupons
        return error("Coupon already applied")
    cart.apply_discount(coupon)
    cart.applied_coupons.add(coupon)
```

---

### Lab 5 — Insufficient Workflow Validation ✅

**Vulnerability type:** Payment step bypass — order confirmation endpoint does not verify payment was completed

**What this lab proves:** Multi-step workflows enforced only by UI flow — not by server-side state validation on each endpoint — can be bypassed by sending the final step request directly, skipping all intermediate steps.

**How it was solved:**

Logged in as `wiener:peter`. Completed a normal cheap item purchase first — observed the full workflow in Burp HTTP History. Identified the order confirmation endpoint — the final request in the checkout flow:
```
GET /cart/order-confirmation?order-confirmed=true
```
Added the leather jacket to cart. Did not proceed through checkout or payment. Navigated directly to the order confirmation URL:
```
GET /cart/order-confirmation?order-confirmed=true
```
The order went through without payment. Lab solved.

**Why it worked:**

The developer built a multi-step workflow: add to cart → checkout → payment → confirmation. The payment step was enforced by the UI — the confirm button only appears after payment. But the server-side confirmation endpoint only checked "is there a valid cart?" — not "was payment completed for this cart?" By sending the confirmation request directly — bypassing the UI — the payment step was skipped entirely. Burp makes this trivial — any request can be replayed regardless of what the UI allows.

**The vulnerable pattern:**
```python
# Vulnerable — confirmation does not check payment status
def order_confirmation(request):
    cart = get_cart(request.session)
    if not cart:
        return error("No cart found")
    # Missing: check cart.payment_completed     ← payment never verified
    place_order(cart)
    return render("Order confirmed")

# Fixed — validates payment was completed before confirming
def order_confirmation(request):
    cart = get_cart(request.session)
    if not cart:
        return error("No cart found")
    if not cart.payment_completed:              # Payment state checked
        return redirect('/checkout/payment')
    place_order(cart)
    return render("Order confirmed")
```

---

### Lab 6 — Weak Isolation on Dual-Use Endpoint ✅

**Vulnerability type:** Dual-use endpoint parameter removal — removing the current password parameter skips the security check entirely

**What this lab proves:** An endpoint that serves two purposes — password change and admin password reset — with different required parameters for each use case, skips validation entirely when a required parameter is absent instead of rejecting the request.

**How it was solved:**

Logged in as `wiener:peter`. Found the Change Password function. Turned Intercept ON, submitted a password change, and examined the frozen POST request body:
```
username=wiener&current-password=peter&new-password-1=test&new-password-2=test
```
The endpoint accepted a `username` parameter — a signal that it serves multiple purposes. Modified the request:
- Changed `username` from `wiener` to `administrator`
- Removed the `current-password` parameter entirely:
```
username=administrator&new-password-1=hacked&new-password-2=hacked
```
Forwarded the request. Administrator's password changed to `hacked`. Logged out. Logged in as `administrator:hacked`. Accessed the admin panel. Deleted carlos.

**Why it worked:**

The endpoint served dual purposes — password change for regular users (requires current password) and password reset for admins (no current password needed). When `current-password` was present — the server validated it. When absent — the server skipped the check entirely instead of rejecting the request. Combined with the client-controlled `username` parameter — any account's password could be changed by removing one parameter.

**The vulnerable pattern:**
```python
# Vulnerable — skips validation when parameter is missing
def change_password(request):
    username = request.POST['username']          # User controls this
    current_pw = request.POST.get('current-password')

    if current_pw:                               # Only validates IF present
        if not verify_password(username, current_pw):
            return error("Wrong password")
    # If current-password absent — skips check entirely
    update_password(username, request.POST['new-password-1'])

# Fixed — separate endpoints for separate use cases
def change_own_password(request):
    username = request.session['user']           # From session — not client
    current_pw = request.POST['current-password']  # Always required
    if not verify_password(username, current_pw):
        return error("Wrong password")
    update_password(username, request.POST['new-password-1'])

def admin_reset_password(request):
    if not request.session['is_admin']:          # Admin check first
        return error(403)
    target_username = request.POST['username']
    update_password(target_username, request.POST['new-password-1'])
```

---

## 4. Vulnerable Source Code — The Common Pattern

All six labs share one root cause expressed differently:

**The developer enforced a rule — but not in all the right places.**

| Lab | Rule Intended | Where Enforced | Where Missing |
|-----|--------------|----------------|---------------|
| Lab 1 | Price comes from database | UI only | Server-side price lookup |
| Lab 2 | Quantity must be positive | Type check only | Range check |
| Lab 3 | Only company emails get admin | Registration | Email change |
| Lab 4 | Each coupon used once | Consecutive check | Session-wide check |
| Lab 5 | Payment before confirmation | UI flow | Server-side state |
| Lab 6 | Current password required | When parameter present | When parameter absent |

---

## 5. Chain Thinking — Business Logic to Full Compromise

```
Today's vulnerability: Workflow bypass (Lab 5) — skip payment step
        ↓
Combines with: Dual-use endpoint (Lab 6) — change admin password
        ↓
Combined impact: Free merchandise at scale + full admin account takeover
        ↓
Severity upgrade: Medium logic flaw + Medium auth bypass = Critical financial + admin compromise
```

**The full attack chain:**
```
Step 1: Skip payment via workflow bypass
        Add expensive items to cart
        Navigate directly to:
        GET /cart/order-confirmation?order-confirmed=true
        Items ordered — zero payment taken

Step 2: Escalate to admin via dual-use endpoint
        POST /my-account/change-password
        username=administrator
        new-password-1=hacked
        new-password-2=hacked
        (current-password parameter removed entirely)

Step 3: Log in as administrator
        POST /login
        username=administrator&password=hacked
        Full admin panel access

Step 4: Combined impact
        Free merchandise at any scale (financial damage)
        Admin account compromised (full application takeover)
        All user data and payment records exposed
```

**Real world scenario:** An e-commerce platform has both a checkout workflow bypass and a dual-use password endpoint. An attacker orders $50,000 of electronics for free via workflow bypass, then escalates to admin access — exposing all customer payment data and PII. Combined bug bounty value: **$10,000–$30,000** on a major platform.

---

## 6. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|------------------|--------------|
| Client-side price trust | Purchase any item for $0.01 | $500 – $5,000 |
| Negative quantity exploit | Reduce any order total to near zero | $500 – $3,000 |
| Post-registration bypass | Privilege escalation to admin via email change | $1,000 – $5,000 |
| Coupon stacking | Infinite discount via alternating coupons | $500 – $4,000 |
| Payment workflow bypass | Order any item without payment | $2,000 – $10,000 |
| Dual-use endpoint | Change any user's password without knowing original | $1,000 – $8,000 |

---

## 7. The Fix — Defense in Depth

**Layer 1 — Never trust client-supplied business values:**
Price, discount amount, and role must always be looked up server-side from the database. Never accept them from the request body, URL parameters, or cookies.

**Layer 2 — Validate input range, not just type:**
Every numeric field must have both type validation (is it a number?) and range validation (is it positive? is it within allowed limits?). A quantity of -1 or 0 should always be rejected.

**Layer 3 — Re-validate security rules on every data change:**
Every endpoint that modifies security-relevant data (email, role, permissions) must re-validate all security rules that depend on that data — not just at registration or initial setup.

**Layer 4 — Track rule application across the entire session:**
Coupon usage, discount application, and one-time actions must be tracked for the entire session — not just the last action. Use a set to track all applied coupons, not just the most recent one.

**Layer 5 — Server-side workflow state:**
Every step in a multi-step workflow must set a server-side state flag. Each subsequent step must verify all prior flags are set before proceeding. UI flow is not enforcement — server state is.

**Layer 6 — Separate endpoints for separate use cases:**
Never build a dual-use endpoint that skips validation based on parameter presence. Separate security-critical operations into separate endpoints with clearly defined required parameters for each.

---

## 8. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| Business logic vulnerability | Design flaw exploited using valid inputs in unintended ways |
| Happy path assumption | Developer only tests intended user behavior — misses edge cases |
| Client-side trust | Accepting security-critical values from the browser instead of the database |
| Negative quantity exploit | Using negative numbers to reduce totals — passes type check, fails range check |
| Coupon stacking | Alternating coupons to bypass consecutive-duplicate check |
| Workflow bypass | Sending final workflow step request directly, skipping intermediate steps |
| Dual-use endpoint | Single endpoint serving multiple purposes with inconsistent validation |
| Parameter removal | Deleting a required parameter from a request to skip its associated validation |
| AI-resistant vulnerability | Class of bug automated scanners cannot find — requires human reasoning |

---

## 9. Payloads and Commands Reference

**Price manipulation (Burp Intercept — modify POST body):**
```
Original: productId=1&redir=PRODUCT&quantity=1&price=133700
Modified: productId=1&redir=PRODUCT&quantity=1&price=1
```

**Negative quantity (Burp Intercept — modify POST body):**
```
Original: productId=1&redir=PRODUCT&quantity=1
Modified: productId=1&redir=PRODUCT&quantity=-100
```

**Coupon alternating stack:**
```
Apply: NEWCUST5
Apply: SIGNUP30
Apply: NEWCUST5
Apply: SIGNUP30
Repeat until price within budget
```

**Workflow bypass (direct URL navigation):**
```
GET /cart/order-confirmation?order-confirmed=true
```

**Dual-use endpoint parameter removal (Burp Intercept):**
```
Original: username=wiener&current-password=peter&new-password-1=test&new-password-2=test
Modified: username=administrator&new-password-1=hacked&new-password-2=hacked
```

---

## 10. Foundation Checklist

Answer these from memory — not from these notes:

1. **Why can automated scanners not find business logic vulnerabilities?** What specifically do they miss?
2. **What is the developer assumption in Lab 1?** What should they have done instead?
3. **How does negative quantity bypass price validation?** What rule was enforced and what was missing?
4. **What made the coupon bypass in Lab 4 work?** What did the developer check vs what did they forget?
5. **Why does skipping the payment step work in Lab 5?** What should every protected endpoint verify?
6. **Describe a business logic vulnerability you could look for in a real food delivery app** — think about ordering, discounts, refunds, delivery fees.

---
