# Engineering Report: API-Jack Detection Methodology

## OWASP API Security Top 10 Coverage

| # | Category | Coverage | Detection Method |
|---|----------|----------|------------------|
| API1 | Broken Object Level Authorization | ✅ Full | ID enumeration, baseline comparison |
| API2 | Broken Authentication | ✅ Partial | Missing auth header detection |
| API3 | Excessive Data Exposure | ✅ Full | Recursive key scanning against sensitive patterns |
| API4 | Lack of Resources & Rate Limiting | ✅ Full | Rapid request burst + response analysis |
| API5 | Broken Function Level Authorization | ❌ | Requires context-specific access control testing |
| API6 | Mass Assignment | ✅ Full | Privileged field injection in request bodies |
| API7 | Security Misconfiguration | ❌ | Out of scope (headers/SSL config) |
| API8 | Injection | ❌ | Out of scope (requires payload fuzzing) |
| API9 | Improper Assets Management | ❌ | Out of scope (requires API inventory) |
| API10 | Insufficient Logging & Monitoring | ❌ | Out of scope (requires server-side analysis) |

**Coverage Summary:** 5 of 10 categories addressed. The scanner focuses on the most common and easily automated checks. API5, API7, API8, API9, and API10 are intentionally excluded as they require either manual context, payload fuzzing, or server-side log analysis — areas better served by specialized tools.

---

## Detection Methodology

### 1. Missing Authentication (API1/API2)

**Method:** For each endpoint marked `auth_type: "required"`, the scanner sends a request **without** any `Authorization` header.

**Detection logic:**
- If the response returns HTTP `200` (or the `expected_status` of the endpoint), the endpoint is flagged as missing authentication.
- If the response returns `401` or `403`, authentication is considered enforced.

**False positive analysis:**
- Some endpoints may use IP-based allowlisting, certificate-based auth, or custom header-based auth. These will produce false positives as API-Jack only tests for Bearer token-based auth.
- Rate-limited endpoints may return `429` which is not `401/403`, causing a potential false positive.
- Public-facing static assets served by the same path may not require auth.

**Mitigation:** The `auth_type` field in `endpoints.json` allows marking public endpoints as `"none"` to skip this check.

---

### 2. Broken Object Level Authorization — BOLA (API1)

**Method:** The scanner extracts numeric IDs from URL paths, then iterates through a configurable range of IDs (default: 1-5) making requests without authorization context.

**Detection logic:**
1. Send a baseline request with the original ID to capture expected response characteristics.
2. For each test ID in the range, send a request replacing the original ID.
3. If a test ID returns HTTP `200` with meaningful response body (not a generic error), the object is considered accessible without proper authorization.

**False positive analysis:**
- The test range (1-5 by default) is small. A rate-limited API using UUIDs with sequential integers only in non-sensitive contexts would produce false positives.
- Endpoints that return a generic "not found" message with 200 status (e.g., `{"error": "not found"}` with a 200 code) could produce false positives if the response body is large enough.
- Resources that happen to exist at the tested IDs (e.g., users 1-5 genuinely exist and are public) would be incorrectly flagged.

**Limitations:**
- Only works with numeric sequential IDs. UUID-based APIs are skipped with an INFO finding.
- Cannot test BOLA in POST request bodies or query parameters.
- No detection of horizontal privilege escalation where the attacker's own ID is replaced.

---

### 3. Excessive Data Exposure (API3)

**Method:** The scanner performs a recursive scan of the JSON response body, comparing every key name against a list of sensitive field patterns.

**Detection patterns (30+ patterns):**
```python
sensitive_patterns = [
    "password", "secret", "token", "credit_card", "ssn",
    "social_security", "api_key", "api-key", "apikey",
    "private_key", "passphrase", "pin", "cvv", "cvc",
    "authorization", "access_token", "refresh_token",
    "session_id", "cookie", "jwt", "bearer",
]
```

**Severity scoring:**
- **HIGH** if any of: `password`, `secret`, `token`, `credit`, `ssn` appear in field names.
- **MEDIUM** if other sensitive patterns match.

**Additional check:** Response payloads larger than 100KB trigger a LOW-severity finding for potential excessive data due to lack of pagination or field filtering.

**False positive analysis:**
- Field name matching is purely lexical. A field called `secret_note` (user-generated content) would be flagged even though it's not a credential.
- API responses that include the string "token" in unrelated contexts (e.g., `payment_token` in a payment gateway response) produce false positives.
- The scanner cannot distinguish between hashed/salted credentials stored in fields vs. plaintext — both trigger findings.
- Responses with application-specific field names containing pattern substrings (e.g., `my_password_hint`) will be flagged.

**Mitigation:** Users can extend the blocklist or whitelist specific field names through configuration (planned feature).

---

### 4. Missing Rate Limiting (API4)

**Method:** The scanner sends a burst of requests (default: 100) to the target endpoint in rapid succession and analyzes responses.

**Detection logic:**
- If **no** HTTP `429` (Too Many Requests) or `503` (Service Unavailable) responses are received, and no rate-limit-related headers are found (`X-RateLimit-*`, `Retry-After`, etc.), the endpoint is flagged as missing rate limiting.
- A secondary LOW finding is generated if throughput exceeds 50 req/s, indicating weak throttling even if some rate limiting exists.

**False positive analysis:**
- The test sends requests sequentially (not concurrent). An API that rate-limits per-second but allows the burst within a single TCP connection might not trigger 429s with sequential requests.
- Some APIs return `200` but silently drop or queue excessive requests — the scanner cannot detect this.
- The scanner uses a single IP. Distributed denial-of-service scenarios are not tested.
- Rate limiting that kicks in after more than 100 requests (not uncommon) would not be detected with the default count.

**Mitigation:** Use `--requests` to increase the request count for more thorough testing.

---

### 5. Mass Assignment (API6)

**Method:** The scanner sends a POST/PATCH request containing privileged fields (`is_admin: true`, `role: "admin"`, `balance: 999999`) and checks if they are reflected in the response.

**Detection logic:**
- If the request returns `2xx` and injected fields appear in the response body → **CRITICAL** finding (confirmed mass assignment).
- If the request returns `2xx` but fields are not reflected → **MEDIUM** finding (potential mass assignment, but not confirmed).
- If the request returns `400` or `422` → properly rejected (no finding).

**Field injection mapping:**

| Field Keyword | Injected Value |
|---------------|----------------|
| `is_admin`, `admin`, `isadmin` | `true` |
| `role` | `"admin"` |
| `balance`, `credit`, `score`, `points` | `999999` |
| Any other field | `"injected"` |

**False positive analysis:**
- The scanner only checks if the field *name* appears in the response. An API that accepts the injection but doesn't actually modify the underlying resource (e.g., a GraphQL endpoint that ignores extra fields) would be a false positive.
- A `2xx` response might indicate the field was accepted at the API layer but rejected at the database layer (e.g., by a database column constraint or ORM allow-list).
- Some endpoints echo back the entire request body in the response regardless of whether fields were actually bound (e.g., debugging endpoints). This produces false positives.
- The scanner only tests POST/PATCH. Mass assignment in PUT or query parameters is not tested.

**Limitations:**
- Cannot confirm that the injected values were actually persisted — only that they were accepted and/or reflected.
- Does not test for mass assignment through nested object properties.

---

## Severity Classification

| Severity | Threshold | Action Required |
|----------|-----------|-----------------|
| **CRITICAL** | Direct exploitation possible (BOLA, confirmed mass assignment) | Immediate remediation |
| **HIGH** | Significant security control missing (no auth, no rate limiting, sensitive data exposed) | Fix in current sprint |
| **MEDIUM** | Potential vulnerability or partial control weakness | Investigate and plan fix |
| **LOW** | Informational — potential improvement area | Consider for backlog |
| **INFO** | Diagnostic information, no vulnerability | No action required |

---

## Performance Considerations

- **Network:** Each BOLA test makes `N+1` requests (1 baseline + N test IDs). The rate limit test makes up to 100 requests per endpoint. For large scans, this can generate significant traffic.
- **Timeouts:** Default timeout is 15 seconds per request. Adjust by modifying `timeout` in `APIClient.__init__` if testing slow endpoints.
- **Concurrency:** Requests are sequential. Parallel request support is a planned enhancement.

## False Negative Areas

Known blind spots where vulnerabilities exist but API-Jack will not detect them:

1. **BOLA via query parameters** — `/api/users?id=1` is not parsed for ID patterns.
2. **BOLA via POST body** — Object references in request bodies are not enumerated.
3. **Rate limiting via concurrent connections** — Testing is sequential per connection.
4. **Mass assignment via PUT** — Only POST is tested by default.
5. **Authentication bypass via header injection** — Not tested.
6. **Broken Function Level Authorization** — Requires role-specific testing not implemented.
7. **Stored vs. reflected mass assignment** — Cannot confirm server-side persistence.
8. **IDOR via non-numeric identifiers** — UUID, email, or slug-based IDs are not enumerated.

---

## OWASP References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [API2: Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [API3: Excessive Data Exposure](https://owasp.org/API-Security/editions/2023/en/0xa3-excessive-data-exposure/)
- [API4: Lack of Resources & Rate Limiting](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [API6: Mass Assignment](https://owasp.org/API-Security/editions/2023/en/0xa6-mass-assignment/)
