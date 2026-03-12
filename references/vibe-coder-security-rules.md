# Vibe Coder Security Rules — Claris V6.1
*30 Security Rules Every Vibe Coder Ignores Until They Get Burnt*

---

> **Origin:** Shared by August James, March 12, 2026.
> These 30 rules are now part of Claris's core training database and are enforced
> by `vibe_coder_guard.py` during code review. Initium Builder is also trained on these.
> **Ship fast. But ship secure.**

---

## The 30 Rules — Full Training Database

### RULE 01 — Storage: Never Put Secrets in localStorage
**Category:** Client-Side Security / Storage
**Severity:** CRITICAL

```
Never store sensitive data in localStorage. Use httpOnly cookies.
```

**Why it matters:**
localStorage is accessible by any JavaScript on the page — including injected scripts from XSS attacks. If an attacker gets XSS on your site, they drain localStorage immediately. Tokens, session data, user PII — gone.

**httpOnly cookies** cannot be read by JavaScript at all. Server sets them, server reads them. The JS layer never sees them.

**What Claris checks for:**
- `localStorage.setItem('token'` — FLAG
- `localStorage.setItem('session'` — FLAG
- `localStorage.setItem('user'` — FLAG
- Any localStorage write containing: token, auth, session, key, secret, password, credential

**Secure pattern:**
```javascript
// ❌ NEVER
localStorage.setItem('authToken', token);

// ✅ ALWAYS — set httpOnly cookie server-side
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
```

---

### RULE 02 — Server Config: Disable Directory Listing
**Category:** Server Hardening / Information Disclosure
**Severity:** HIGH

```
Disable directory listing on your server. Never expose file structure.
```

**Why it matters:**
An exposed directory listing reveals your entire project structure — config files, backup files, `.env` files, private assets. Attackers use it to map your attack surface in seconds.

**What Claris checks for:**
- nginx config without `autoindex off`
- Apache config without `Options -Indexes`
- Express `express.static` without proper configuration

**Secure pattern:**
```nginx
# nginx — always include
autoindex off;

# Apache .htaccess
Options -Indexes
```

---

### RULE 03 — Sessions: Regenerate ID After Login
**Category:** Session Management
**Severity:** HIGH

```
Always regenerate session IDs after login.
```

**Why it matters:**
Session fixation attacks: an attacker creates a session ID, tricks a user into authenticating with it, then uses that same ID to hijack the authenticated session. Regenerating after login breaks this entirely.

**Secure pattern:**
```javascript
// Express + express-session
req.session.regenerate((err) => {
  req.session.userId = user.id;
  res.redirect('/dashboard');
});
```

---

### RULE 04 — Headers: Content Security Policy on Every Page
**Category:** HTTP Security Headers
**Severity:** HIGH

```
Use Content Security Policy headers on every page.
```

**Why it matters:**
CSP is your last line of defense against XSS. Even if an attacker injects a script tag, a properly configured CSP prevents it from executing or exfiltrating data to external domains.

**Secure pattern:**
```javascript
// Helmet.js (Node/Express)
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'nonce-{random}'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
}));
```

---

### RULE 05 — Validation: Always Re-Validate Server-Side
**Category:** Input Validation / Trust Boundaries
**Severity:** CRITICAL

```
Never trust client-side validation alone. Always re-validate server-side.
```

**Why it matters:**
Client-side validation is UX, not security. Any attacker with curl, Postman, or browser DevTools can bypass it entirely. The server is the only trust boundary that matters.

**What Claris checks for:**
- API endpoints that accept input without server-side validation libraries (Zod, Joi, Yup, etc.)
- Form handlers that skip re-checking after client validation

**Secure pattern:**
```javascript
// Client validates for UX. Server validates for security.
import { z } from 'zod';

const schema = z.object({
  email: z.string().email(),
  amount: z.number().positive().max(10000),
});

app.post('/transfer', (req, res) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: result.error });
  // proceed with validated data only
});
```

---

### RULE 06 — Headers: X-Frame-Options DENY
**Category:** HTTP Security Headers / Clickjacking
**Severity:** HIGH

```
Set X-Frame-Options to DENY. Prevents clickjacking attacks.
```

**Why it matters:**
Clickjacking: attacker embeds your site in an invisible iframe, overlays fake UI, tricks users into clicking buttons on your site (approve transaction, change email, etc.) thinking they're clicking something else.

**Secure pattern:**
```javascript
// Helmet
app.use(helmet.frameguard({ action: 'deny' }));

// Manual header
res.setHeader('X-Frame-Options', 'DENY');

// Modern CSP approach
frame-ancestors 'none';
```

---

### RULE 07 — File Uploads: Strip Metadata
**Category:** File Security / Privacy
**Severity:** HIGH

```
Strip metadata from every user-uploaded file before storing.
```

**Why it matters:**
Image metadata (EXIF) can contain GPS coordinates, device info, timestamps, and author data. A user uploads a photo from their home — you store it — you've just exposed their home address to anyone who downloads that file.

**Secure pattern:**
```javascript
// Node.js with sharp
import sharp from 'sharp';

const stripped = await sharp(uploadedBuffer)
  .rotate() // applies orientation, removes EXIF rotation
  .withMetadata(false) // strips ALL metadata
  .toBuffer();
```

---

### RULE 08 — Errors: Never Expose Stack Traces in Production
**Category:** Information Disclosure
**Severity:** HIGH

```
Never expose stack traces or error details in production responses.
```

**Why it matters:**
Stack traces reveal your file structure, library versions, internal variable names, and sometimes even code logic. This is free reconnaissance for an attacker — a roadmap to your vulnerabilities.

**Secure pattern:**
```javascript
// Development: detailed errors
// Production: generic errors only
app.use((err, req, res, next) => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (isProduction) {
    // Log full error internally
    logger.error(err);
    // Return nothing useful to attacker
    return res.status(500).json({ error: 'Internal server error' });
  }
  
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

---

### RULE 09 — Files: Use Presigned URLs for Private Storage
**Category:** Cloud Storage Security
**Severity:** HIGH

```
Use short-lived presigned URLs for private file access. Never public bucket URLs.
```

**Why it matters:**
Public S3/R2/GCS URLs are accessible by anyone, forever. Presigned URLs expire. They're scoped to one object. They can be audited. When you use public URLs for private files, you've created a permanent data exposure.

**Secure pattern:**
```javascript
// AWS S3 presigned URL — expires in 15 minutes
const command = new GetObjectCommand({ Bucket: 'my-bucket', Key: fileKey });
const url = await getSignedUrl(s3Client, command, { expiresIn: 900 });
```

---

### RULE 10 — CSRF: Tokens on Every State-Changing Request
**Category:** CSRF Protection
**Severity:** HIGH

```
Implement CSRF tokens on every state-changing form or request.
```

**Why it matters:**
Cross-Site Request Forgery: an attacker's page makes a request to your site using the victim's browser cookies. The browser sends the cookies automatically. Without CSRF tokens, the server can't tell the difference.

**Secure pattern:**
```javascript
// csurf middleware (Express)
app.use(csrf({ cookie: true }));

app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// In your form
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

---

### RULE 11 — Forms: Disable Autocomplete on Sensitive Fields
**Category:** Client-Side Security
**Severity:** MEDIUM

```
Disable autocomplete on sensitive form fields (passwords, card numbers).
```

**Why it matters:**
Autocomplete stores field values in the browser — accessible to other users on shared devices, and potentially readable by browser extensions.

**Secure pattern:**
```html
<input type="password" autocomplete="new-password" />
<input type="text" name="cardNumber" autocomplete="off" />
<input type="text" name="cvv" autocomplete="off" />
```

---

### RULE 12 — Passwords: bcrypt Minimum Cost Factor 12
**Category:** Authentication / Cryptography
**Severity:** CRITICAL

```
Always hash passwords with bcrypt minimum cost factor of 12.
```

**Why it matters:**
MD5 and SHA hashes are fast — attackers can test billions of guesses per second. bcrypt is deliberately slow. Cost factor 12 means ~250ms per hash — reasonable for login, prohibitive for bulk cracking. Below 12 is too weak for modern hardware.

**What Claris checks for:**
- `bcrypt.hash(password, 10)` → WARN (cost factor too low)
- `bcrypt.hash(password, 8)` → FLAG (dangerously low)
- `md5(password)` → BLOCK
- `sha1(password)` → BLOCK
- `sha256(password)` for passwords → FLAG

**Secure pattern:**
```javascript
import bcrypt from 'bcrypt';

// Hash (during registration)
const hash = await bcrypt.hash(password, 12); // minimum 12

// Verify (during login)
const valid = await bcrypt.compare(password, storedHash);
```

---

### RULE 13 — Dependencies: Keep Them Minimal
**Category:** Supply Chain Security
**Severity:** HIGH

```
Keep dependency list minimal. Every extra package is an attack surface.
```

**Why it matters:**
The average npm package has 77 transitive dependencies. Each one is a potential supply chain attack vector. Bybit ($1.5B breach, 2025) started with one compromised npm package. If you don't need it, don't install it.

**What Claris checks for:**
- Package count thresholds
- Known vulnerable packages (via OSV database)
- Packages with excessive permissions
- Packages with recent ownership changes

---

### RULE 14 — Scripts: Subresource Integrity for External Scripts
**Category:** Supply Chain Security / Content Integrity
**Severity:** HIGH

```
Use subresource integrity (SRI) for every external script you load.
```

**Why it matters:**
If your CDN gets compromised or a JS library gets updated maliciously, SRI prevents it from running. The browser validates the hash before executing.

**Secure pattern:**
```html
<!-- ❌ NEVER -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ ALWAYS -->
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-[hash]"
  crossorigin="anonymous">
</script>
```

---

### RULE 15 — Logging: Never Log Sensitive Data
**Category:** Data Security / Privacy
**Severity:** CRITICAL

```
Never log user passwords, tokens, or PII, even by accident.
```

**Why it matters:**
Logs are often stored insecurely, shared with third-party logging services, included in crash reports, and retained long-term. A single `console.log(req.body)` in a login route has exposed millions of passwords.

**What Claris checks for:**
- `console.log(req.body)` in auth routes — FLAG
- `logger.info(password)` — BLOCK
- `console.log(token)` — FLAG
- Any log statement containing: password, token, secret, key, credential, ssn, card

---

### RULE 16 — Transport: HTTPS Everywhere
**Category:** Transport Security
**Severity:** CRITICAL

```
Enforce HTTPS everywhere. Redirect all HTTP to HTTPS at server level.
```

**Why it matters:**
HTTP is plaintext. Man-in-the-middle attacks can read and modify everything. HSTS (HTTP Strict Transport Security) tells browsers to never connect over HTTP — even if the user types it.

**Secure pattern:**
```javascript
// Express + helmet
app.use(helmet.hsts({
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: true,
}));

// Redirect HTTP → HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
});
```

---

### RULE 17 — Database: Separate Credentials Per Environment
**Category:** Secrets Management / Least Privilege
**Severity:** CRITICAL

```
Use separate DB credentials per environment. Never share prod creds.
```

**Why it matters:**
If your dev or staging environment is compromised, separate credentials means production data is still safe. Shared creds mean one breach = total data loss. Also: dev should never have write access to prod.

**Secure pattern:**
```bash
# .env.development
DATABASE_URL=postgresql://dev_user:dev_pass@localhost:5432/myapp_dev

# .env.production (never in source control)
DATABASE_URL=postgresql://prod_user:STRONG_PASS@prod-host:5432/myapp_prod
```

---

### RULE 18 — Auth: Account Lockout After 5 Failures
**Category:** Brute Force Protection
**Severity:** HIGH

```
Implement account lockout after 5 failed login attempts.
```

**Why it matters:**
Without lockout, brute force attacks can try millions of passwords until they succeed. Five failures is the industry standard — enough for typos, not enough for automated attacks.

**Secure pattern:**
```javascript
// Redis-based rate limiting
const attempts = await redis.incr(`login:${email}`);
if (attempts === 1) await redis.expire(`login:${email}`, 900); // 15 min window
if (attempts > 5) return res.status(429).json({ error: 'Account locked. Try in 15 minutes.' });
```

---

### RULE 19 — APIs: Validate Content-Type Headers
**Category:** API Security / Input Validation
**Severity:** MEDIUM

```
Validate content-type headers on every API request.
```

**Why it matters:**
Accepting unexpected content types can lead to parser confusion, content-type sniffing attacks, and unexpected behavior. Only accept what you expect.

**Secure pattern:**
```javascript
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    if (!req.is('application/json')) {
      return res.status(415).json({ error: 'Unsupported media type' });
    }
  }
  next();
});
```

---

### RULE 20 — Crypto: Never Use MD5 or SHA1
**Category:** Cryptography
**Severity:** CRITICAL

```
Never use MD5 or SHA1 for anything security-related.
```

**Why it matters:**
MD5 was broken in 1996. SHA1 was officially deprecated in 2017. Both have known collision attacks. Both are trivially crackable for passwords. Use SHA-256 minimum for non-password hashing, bcrypt/argon2 for passwords.

**What Claris checks for:**
- `crypto.createHash('md5')` — BLOCK (if security context)
- `crypto.createHash('sha1')` — FLAG
- Any `md5()` or `sha1()` library call — FLAG

---

### RULE 21 — OAuth: Minimum Scope Tokens
**Category:** OAuth / Authorization
**Severity:** HIGH

```
Scope OAuth tokens to minimum required permissions only.
```

**Why it matters:**
Overpermissioned tokens are a force multiplier for attackers. If your "read profile" use case has a token with admin:write, a stolen token is catastrophic. Request only what you need.

**Secure pattern:**
```javascript
// GitHub OAuth — only request what you need
const scope = 'read:user'; // not 'repo,admin:org,write:packages'

// Google OAuth
const scope = 'email profile'; // not 'https://mail.google.com/'
```

---

### RULE 22 — CSP: Nonces for Every Inline Script
**Category:** Content Security Policy
**Severity:** HIGH

```
Use nonces for every inline script in your CSP policy.
```

**Why it matters:**
`unsafe-inline` in CSP completely defeats the purpose of CSP. Nonces allow specific inline scripts while blocking attacker-injected ones. Generate a new nonce per request.

**Secure pattern:**
```javascript
import crypto from 'crypto';

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy', 
    `script-src 'self' 'nonce-${res.locals.nonce}'`);
  next();
});

// In template
<script nonce="<%= nonce %>">/* your inline script */</script>
```

---

### RULE 23 — Dependencies: Weekly Vulnerability Monitoring
**Category:** Dependency Security / Supply Chain
**Severity:** HIGH

```
Monitor for dependency vulnerabilities with Snyk or similar weekly.
```

**Why it matters:**
New CVEs are published daily. A package that was safe last month may be critically vulnerable today. Automated weekly scanning catches this. Manual checking doesn't.

**Tools:** Snyk, `npm audit`, Dependabot, Socket.dev, OSV Scanner

**Claris automation:**
```bash
# Run weekly via cron
npm audit --audit-level=high
snyk test --severity-threshold=high
```

---

### RULE 24 — Server: Disable Unused HTTP Methods
**Category:** Attack Surface Reduction
**Severity:** MEDIUM

```
Disable HTTP methods you don't use (PUT, DELETE, TRACE, OPTIONS).
```

**Why it matters:**
TRACE enables cross-site tracing (XST) attacks. Unused methods expand attack surface. Only expose what you explicitly need.

**Secure pattern:**
```nginx
# nginx — allow only GET, POST, HEAD
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

```javascript
// Express — reject unexpected methods
app.use((req, res, next) => {
  const allowed = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
  if (!allowed.includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  next();
});
```

---

### RULE 25 — Sessions: Proper Logout = Server Invalidation
**Category:** Session Management
**Severity:** HIGH

```
Implement proper logout: invalidate server-side sessions, not just clear cookies.
```

**Why it matters:**
If you only clear the cookie on logout, the session token is still valid server-side. An attacker who captured the token can continue using it indefinitely. True logout = server destroys the session.

**Secure pattern:**
```javascript
// Express logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {         // destroy server-side session
    res.clearCookie('connect.sid');       // AND clear client cookie
    return res.redirect('/login');
  });
});
```

---

### RULE 26 — Crypto: Constant-Time String Comparison
**Category:** Timing Attacks / Cryptography
**Severity:** HIGH

```
Use constant-time string comparison for token validation. Prevents timing attacks.
```

**Why it matters:**
Regular string comparison (`===`) short-circuits — it returns false the moment it finds a non-matching character. An attacker can measure response time differences (microseconds) to determine how many characters matched, enabling character-by-character token cracking.

**Secure pattern:**
```javascript
import crypto from 'crypto';

// ❌ NEVER
if (token === expectedToken) { ... }

// ✅ ALWAYS for tokens/HMACs
const isValid = crypto.timingSafeEqual(
  Buffer.from(token),
  Buffer.from(expectedToken)
);
```

---

### RULE 27 — Caching: Never Cache Sensitive API Responses
**Category:** Information Disclosure / Caching
**Severity:** HIGH

```
Never cache sensitive API responses. Set Cache-Control: no-store.
```

**Why it matters:**
Cached responses can be read by: CDN providers, shared caches, proxy servers, browser history, ISPs. A cached auth token or user data endpoint is a permanent disclosure to anyone in the chain.

**Secure pattern:**
```javascript
// For any API returning user data, tokens, or sensitive info
res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
res.setHeader('Pragma', 'no-cache');
```

---

### RULE 28 — Headers: Referrer-Policy Strict-Origin
**Category:** Privacy / Information Disclosure
**Severity:** MEDIUM

```
Set Referrer-Policy to strict-origin. Stop leaking URLs to third parties.
```

**Why it matters:**
By default, browsers send the full URL as `Referer` to every resource you load. If your URL contains sensitive data (token in query param, user ID, internal path), you're leaking it to every third-party CDN, analytics tool, or image host.

**Secure pattern:**
```javascript
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

// Helmet
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
```

---

### RULE 29 — Auth: Server-Side Password Complexity
**Category:** Authentication
**Severity:** HIGH

```
Enforce password complexity server-side. Not just a regex on the frontend.
```

**Why it matters:**
Frontend complexity checks are UX, not security. An API call can bypass the frontend entirely. Server must validate length, complexity, and check against common password lists.

**Secure pattern:**
```javascript
import zxcvbn from 'zxcvbn';

function validatePassword(password) {
  if (password.length < 12) throw new Error('Minimum 12 characters');
  
  const result = zxcvbn(password);
  if (result.score < 3) throw new Error('Password too weak');
  
  return true;
}
```

---

### RULE 30 — Docker: Scan Images Before Every Deployment
**Category:** Container Security / Supply Chain
**Severity:** HIGH

```
Scan your docker images for vulnerabilities before every deployment.
```

**Why it matters:**
Base Docker images contain OS packages with known CVEs. An unscanned Node 18 Alpine image might have 40+ vulnerabilities. Automated scanning in CI/CD catches this before it hits production.

**Secure pattern:**
```yaml
# GitHub Actions — scan before deploy
- name: Scan Docker image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:${{ github.sha }}
    exit-code: '1'
    severity: 'CRITICAL,HIGH'
```

```bash
# Trivy CLI
trivy image --severity HIGH,CRITICAL myapp:latest

# Snyk
snyk container test myapp:latest --severity-threshold=high
```

---

## Quick Reference Matrix

| # | Rule | Category | Severity | Claris Detects? |
|---|------|----------|----------|----------------|
| 01 | No sensitive data in localStorage | Storage | CRITICAL | ✅ |
| 02 | Disable directory listing | Server Config | HIGH | ✅ |
| 03 | Regenerate session IDs after login | Sessions | HIGH | ✅ |
| 04 | CSP headers everywhere | HTTP Headers | HIGH | ✅ |
| 05 | Server-side validation always | Input Validation | CRITICAL | ✅ |
| 06 | X-Frame-Options DENY | HTTP Headers | HIGH | ✅ |
| 07 | Strip file metadata | File Security | HIGH | ✅ |
| 08 | No stack traces in production | Info Disclosure | HIGH | ✅ |
| 09 | Presigned URLs for private files | Cloud Storage | HIGH | ✅ |
| 10 | CSRF tokens on all state changes | CSRF | HIGH | ✅ |
| 11 | Disable autocomplete on sensitive fields | Client Security | MEDIUM | ✅ |
| 12 | bcrypt cost ≥ 12 | Cryptography | CRITICAL | ✅ |
| 13 | Minimal dependencies | Supply Chain | HIGH | ✅ |
| 14 | SRI for external scripts | Supply Chain | HIGH | ✅ |
| 15 | Never log sensitive data | Logging | CRITICAL | ✅ |
| 16 | HTTPS everywhere | Transport | CRITICAL | ✅ |
| 17 | Separate DB creds per env | Secrets Mgmt | CRITICAL | ✅ |
| 18 | Account lockout after 5 fails | Auth | HIGH | ✅ |
| 19 | Validate content-type headers | API Security | MEDIUM | ✅ |
| 20 | Never use MD5 or SHA1 | Cryptography | CRITICAL | ✅ |
| 21 | Minimum OAuth scope | OAuth | HIGH | ✅ |
| 22 | CSP nonces for inline scripts | CSP | HIGH | ✅ |
| 23 | Weekly dependency vulnerability scans | Supply Chain | HIGH | ✅ |
| 24 | Disable unused HTTP methods | Attack Surface | MEDIUM | ✅ |
| 25 | Server-side session invalidation on logout | Sessions | HIGH | ✅ |
| 26 | Constant-time token comparison | Timing Attacks | HIGH | ✅ |
| 27 | No-store cache for sensitive APIs | Caching | HIGH | ✅ |
| 28 | Referrer-Policy strict-origin | Privacy | MEDIUM | ✅ |
| 29 | Server-side password complexity | Auth | HIGH | ✅ |
| 30 | Scan Docker images before deploy | Container Sec | HIGH | ✅ |

---

## Categories Summary

**CRITICAL (Must fix immediately — direct breach path):**
Rules 01, 05, 12, 15, 16, 17, 20

**HIGH (Fix in current sprint):**
Rules 02, 03, 04, 06, 07, 08, 09, 10, 13, 14, 18, 21, 22, 23, 25, 26, 27, 29, 30

**MEDIUM (Fix in next sprint):**
Rules 11, 19, 24, 28

---

## Systems Thinking Lens — Why These Rules Exist

These 30 rules are not arbitrary. They map directly to the 6 Core Words:

**TRUST:** Rules 03, 10, 17, 18, 21, 25, 26 — Who can I trust, and how do I verify it?
**ADVERSARIAL:** Rules 02, 06, 08, 24 — What would an attacker see and exploit?
**SURFACE:** Rules 01, 07, 09, 13, 19, 30 — What can be touched, reduced, hardened?
**ENTROPY:** Rules 04, 12, 14, 20, 22, 23 — How do I keep randomness strong and systems current?
**LATERAL:** Rules 05, 15, 16, 27, 28, 29 — How do I limit damage if something gets in?
**POSTURE:** Rules 11, 17, 23, 30 — Am I holding myself correctly as an organism?

**Ship fast. But ship secure.**

---

*Source: August James (2026-03-12) | Trained into Claris AI V6.1 | Also deployed to Initium Builder*
*~Claris · Semper Fortis · V6.1 Vibe Coder Security Rules*
