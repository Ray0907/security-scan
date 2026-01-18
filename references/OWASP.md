# OWASP Top 10 (2025) Reference

Official source: https://owasp.org/Top10/2025/

## A01:2025 - Broken Access Control

**Description:** Failures in access control allow users to act outside their intended permissions.

**Common Vulnerabilities:**
- Bypassing access control checks by modifying URLs, application state, or HTML pages
- Permitting viewing or editing someone else's account (IDOR)
- Accessing APIs with missing access controls for POST, PUT, DELETE
- Elevation of privilege (acting as admin when logged in as user)
- Metadata manipulation (replaying/tampering JWT tokens)
- CORS misconfiguration allowing unauthorized API access

**Detection Patterns:**
```
- Missing authorization checks on endpoints
- Direct object references without ownership validation
- Role checks only on frontend
```

---

## A02:2025 - Security Misconfiguration

**Description:** Missing security hardening or improperly configured permissions.

**Common Issues:**
- Default credentials in use
- Unnecessary features enabled (ports, services, pages)
- Error handling reveals stack traces
- Security headers missing
- Outdated software/components
- Debug mode enabled in production
- Cloud storage permissions misconfigured

**Detection Patterns:**
```
- DEBUG = True in production config
- Default admin/admin credentials
- Directory listing enabled
- Stack traces in error responses
- Missing security headers (CSP, X-Frame-Options)
- Open S3 buckets / GCS buckets
```

---

## A03:2025 - Software Supply Chain Failures (NEW)

**Description:** Failures related to dependencies, third-party components, and build pipelines.

**Common Issues:**
- Using components with known vulnerabilities
- Dependency confusion attacks
- Typosquatting packages
- Compromised build pipelines
- Unsigned packages/artifacts
- Outdated dependencies without security patches
- Transitive dependency vulnerabilities

**Detection:**
```bash
# Dependency vulnerability scanning
npm audit
pip-audit
trivy fs .
govulncheck ./...
cargo audit
snyk test

# Check for typosquatting
# Verify package names carefully
# Use lockfiles
```

**Prevention:**
- Use Software Bill of Materials (SBOM)
- Pin dependency versions
- Use lockfiles
- Verify package integrity (checksums, signatures)
- Regular dependency updates
- Monitor security advisories

---

## A04:2025 - Cryptographic Failures

**Description:** Failures related to cryptography that expose sensitive data.

**Common Vulnerabilities:**
- Transmitting data in clear text (HTTP, SMTP, FTP)
- Using old/weak cryptographic algorithms (MD5, SHA1, DES)
- Using default/weak crypto keys
- Not enforcing encryption (missing security headers)
- Improper certificate validation
- Using deprecated hash functions for passwords

**Detection Patterns:**
```
- Hardcoded passwords/secrets/API keys
- MD5/SHA1 usage for security purposes
- HTTP URLs for sensitive data
- Weak random number generators
- ECB mode encryption
```

---

## A05:2025 - Injection

**Description:** User-supplied data is not validated, filtered, or sanitized.

**Types:**
- SQL Injection
- NoSQL Injection
- OS Command Injection
- LDAP Injection
- XSS (Cross-Site Scripting)
- Expression Language Injection
- Server-Side Template Injection (SSTI)

**Detection Patterns:**
```sql
-- SQL Injection
query = "SELECT * FROM users WHERE id = " + userId
db.query(`SELECT * FROM users WHERE name = '${name}'`)

-- Command Injection
exec("ls " + userInput)
os.system("ping " + host)

-- XSS
innerHTML = userInput
document.write(data)

-- SSTI
render_template_string(user_input)
```

**Prevention:**
- Use parameterized queries / prepared statements
- Input validation (whitelist)
- Output encoding
- Use ORMs carefully
- Content Security Policy (CSP)

---

## A06:2025 - Insecure Design

**Description:** Missing or ineffective security controls in design.

**Common Issues:**
- Missing rate limiting on sensitive operations
- No account lockout for brute force
- Missing multi-factor authentication
- Insufficient logging and monitoring
- Trust boundaries not defined
- Business logic flaws

**Detection Patterns:**
```
- No rate limiting on login/password reset
- Missing CAPTCHA on public forms
- No fraud detection on financial transactions
- Missing threat modeling
```

---

## A07:2025 - Authentication Failures

**Description:** Weaknesses in authentication mechanisms.

**Common Issues:**
- Permits brute force attacks
- Permits weak passwords
- Uses weak credential recovery
- Uses plain text passwords
- Missing/ineffective MFA
- Session IDs in URL
- Session fixation
- Credential stuffing vulnerabilities

**Detection Patterns:**
```
- No password complexity requirements
- Session tokens don't rotate after login
- Remember me tokens don't expire
- Password hints stored
- No MFA option
```

---

## A08:2025 - Software or Data Integrity Failures

**Description:** Code and infrastructure without integrity verification.

**Common Issues:**
- Using untrusted CDNs without integrity checks
- Insecure deserialization
- Auto-update without signature verification
- CI/CD pipeline without access controls
- Unsigned/unencrypted serialized data

**Detection Patterns:**
```javascript
// Insecure deserialization
JSON.parse(userInput)
pickle.loads(data)
unserialize($data)
yaml.load(data)  // unsafe loader

// Missing SRI
<script src="https://cdn.example.com/lib.js">
// Should be:
<script src="..." integrity="sha384-...">
```

---

## A09:2025 - Security Logging and Alerting Failures

**Description:** Insufficient logging, detection, monitoring, and active response.

**Common Issues:**
- Auditable events not logged
- Warnings/errors generate no logs
- Logs only stored locally
- No alerting thresholds
- Penetration testing doesn't trigger alerts
- Logs not protected from tampering
- No real-time alerting

**Required Logging:**
```
- Login attempts (success/failure)
- Access control failures
- Server-side input validation failures
- Transactions with high value
- Admin operations
- Security-relevant events
```

---

## A10:2025 - Mishandling of Exceptional Conditions (NEW)

**Description:** Improper handling of errors, exceptions, and edge cases leading to security issues.

**Common Issues:**
- Unhandled exceptions exposing stack traces
- Fail-open instead of fail-closed
- Resource exhaustion not handled
- Race conditions
- Integer overflow/underflow
- Null pointer dereferences
- Improper error messages revealing system info

**Detection Patterns:**
```python
# Fail-open anti-pattern
try:
    if not authorize(user):
        deny()
except:
    pass  # Fails open - user gets access on error!

# Should be fail-closed
try:
    if authorize(user):
        allow()
except:
    deny()  # Deny on any error
```

**Prevention:**
- Always fail closed (deny by default)
- Handle all exceptions explicitly
- Don't expose internal errors to users
- Implement proper resource limits
- Test edge cases and error paths

---

## Quick Reference Table

| Code | Category | Key Focus |
|------|----------|-----------|
| A01 | Broken Access Control | Authorization, IDOR, privilege escalation |
| A02 | Security Misconfiguration | Hardening, defaults, headers |
| A03 | Software Supply Chain | Dependencies, SBOM, build security |
| A04 | Cryptographic Failures | Encryption, secrets, hashing |
| A05 | Injection | SQL, XSS, Command injection |
| A06 | Insecure Design | Threat modeling, security controls |
| A07 | Authentication Failures | Login, session, MFA |
| A08 | Integrity Failures | Deserialization, CI/CD, SRI |
| A09 | Logging Failures | Audit logs, alerting, monitoring |
| A10 | Exceptional Conditions | Error handling, fail-closed |
