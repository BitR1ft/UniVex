# UniVex — Security Guide (v2.0)

> **Day 29: Security Hardening & Production Readiness**  
> Last updated: 2026-03-21 · Author: BitR1FT

---

## Table of Contents

1. [Secrets Management](#1-secrets-management)
2. [Two-Factor Authentication (2FA / TOTP)](#2-two-factor-authentication-2fa--totp)
3. [Account Lockout](#3-account-lockout)
4. [IP Allow-Listing](#4-ip-allow-listing)
5. [Role-Based Access Control (RBAC)](#5-role-based-access-control-rbac)
6. [Audit Logging](#6-audit-logging)
7. [Rate Limiting](#7-rate-limiting)
8. [Web Application Firewall (WAF)](#8-web-application-firewall-waf)
9. [Security Headers](#9-security-headers)
10. [TLS / Nginx Configuration](#10-tls--nginx-configuration)
11. [Container Security](#11-container-security)
12. [Secret Rotation](#12-secret-rotation)
13. [Vulnerability Reporting](#13-vulnerability-reporting)

---

## 1. Secrets Management

All secrets are loaded exclusively from **environment variables** — no hard-coded values.

### Required Secrets

| Variable | Description | Minimum Length | Production? |
|----------|-------------|---------------|------------|
| `SECRET_KEY` | JWT signing key | 32 chars | ✅ required |
| `POSTGRES_PASSWORD` | PostgreSQL password | 16 chars | ✅ required |
| `NEO4J_PASSWORD` | Neo4j graph DB password | 16 chars | ✅ required |
| `GRAFANA_PASSWORD` | Grafana admin password | 12 chars | ✅ required |
| `OPENAI_API_KEY` | LLM provider API key | varies | Optional |

### Generating Secrets

```bash
# Generate a cryptographically secure SECRET_KEY
python -c "from app.core.secrets import generate_secret; print(generate_secret(64))"

# Or using the rotate-secrets script
./scripts/rotate-secrets.sh --dry-run   # preview
./scripts/rotate-secrets.sh             # apply
```

### Validation

Startup validation runs automatically via `app.core.secrets.validate_secrets()`:

- In **production**: raises `SecretsValidationError` if any secret fails
- In **development**: logs a warning but continues

---

## 2. Two-Factor Authentication (2FA / TOTP)

UniVex v2.0 supports TOTP-based 2FA (RFC 6238) via `app.core.totp`.

### Setup Flow

```
User enables 2FA → backend generates secret + QR URI + 10 backup codes
→ user scans QR in Google Authenticator / Authy / 1Password
→ user confirms with first token → 2FA activated
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/2fa/setup` | Generate secret + QR URI |
| `POST` | `/api/auth/2fa/confirm` | Confirm enrollment with first token |
| `POST` | `/api/auth/2fa/verify` | Verify TOTP token during login |
| `POST` | `/api/auth/2fa/backup` | Use a one-time backup code |
| `DELETE` | `/api/auth/2fa/disable` | Disable 2FA (admin or self) |

### Backup Codes

- 10 codes generated at setup, each 10 characters
- Stored as **SHA-256 hashes** in the database (never plaintext)
- Each code is single-use (consumed on verification)
- Regeneratable via `/api/auth/2fa/setup` (invalidates old codes)

### Configuration

```python
# app/core/totp.py defaults
TOKEN_DIGITS   = 6
TOKEN_INTERVAL = 30   # seconds (RFC 6238 standard)
VALID_WINDOW   = 1    # ±1 interval → 90 seconds of clock drift tolerance
```

---

## 3. Account Lockout

Brute-force protection via sliding-window lockout (`app.core.lockout`).

### Policy

| Setting | Default | Description |
|---------|---------|-------------|
| `max_attempts` | 5 | Failures before lockout |
| `window_seconds` | 900 | 15-minute sliding window |
| `lockout_seconds` | 900 | 15-minute lockout duration |

### Behaviour

- Tracks both **identity** (email/username) and **source IP** independently
- IP lockout detects credential-stuffing (many users from one IP)
- Identity lockout detects password-spraying (many IPs targeting one account)
- Resets automatically after the lockout period expires
- Successful login clears the failure count

### Integration

```python
from app.core.lockout import account_lockout
from fastapi import Depends

@router.post("/login")
async def login(body: LoginIn, request: Request):
    # Check lockout before processing credentials
    await account_lockout.check_request(body.email, request)

    # ... authenticate ...

    if auth_failed:
        remaining = account_lockout.record_failure(body.email, ip=request.client.host)
        raise HTTPException(401, f"Invalid credentials ({remaining} attempts remaining)")

    # Clear on success
    account_lockout.reset(body.email, ip=request.client.host)
```

---

## 4. IP Allow-Listing

Admin endpoints are restricted to known IP CIDRs (`app.core.ip_allowlist`).

### Configuration

```bash
# Set allowed CIDRs in environment (comma-separated)
ADMIN_IP_ALLOWLIST="10.0.0.0/8,192.168.1.0/24,203.0.113.42"
```

If `ADMIN_IP_ALLOWLIST` is unset, defaults to RFC-1918 private ranges:
- `127.0.0.0/8` — loopback
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — private

### Usage

```python
from app.core.ip_allowlist import admin_ip_check
from fastapi import Depends

@router.get("/admin/users", dependencies=[Depends(admin_ip_check)])
async def list_users():
    ...
```

Nginx also enforces admin IP allowlisting at the proxy level (see `docker/production/nginx/nginx.conf`).

---

## 5. Role-Based Access Control (RBAC)

Three built-in roles with the principle of least privilege:

| Role | Permissions |
|------|-------------|
| `admin` | All permissions |
| `analyst` | Create/read/update/start projects, read/write scans, read graph, read metrics |
| `viewer` | Read projects, read scans, read graph |

Default role for unauthenticated or unrecognised tokens: **viewer** (most restrictive).

---

## 6. Audit Logging

All sensitive operations are emitted to the `univex.audit` structured logger.

### Audited Events

| Event | When |
|-------|------|
| `user.register` | New account created |
| `user.login` | Successful login |
| `user.login_failed` | Failed login attempt |
| `user.logout` | Explicit logout |
| `token.refresh` | Refresh token used |
| `user.password_change` | Password changed |
| `project.create/update/delete/start` | Project lifecycle |
| `security.permission_denied` | 403 response |
| `security.rate_limit_hit` | 429 response |

### SIEM Configuration

Route `univex.audit` to a dedicated sink:

```python
# logging.json (production)
{
  "loggers": {
    "univex.audit": {
      "handlers": ["siem_handler"],
      "level": "INFO",
      "propagate": false
    }
  }
}
```

---

## 7. Rate Limiting

| Limiter | Limit | Window | Applied to |
|---------|-------|--------|-----------|
| User API | 60 req | 1 min | All authenticated API calls |
| Project start | 10 req | 1 hour | `/api/projects/*/start` |
| Login (per IP) | 5 attempts | 15 min | `/api/auth/login` |
| WebSocket connections | 10 | per IP | `/ws` |

Rate limits are enforced at two levels:
1. **Application** — `SlidingWindowRateLimiter` in `app.core.rate_limit`
2. **Nginx** — `limit_req_zone` and `limit_conn_zone` in nginx.conf

---

## 8. Web Application Firewall (WAF)

Query parameters are scanned for common attack patterns:

| Attack Type | Pattern |
|-------------|---------|
| SQL Injection | `SELECT`, `DROP`, `OR 1=1`, `-- comment` |
| XSS | `<script>`, `javascript:`, `onerror=` |
| Path Traversal | `../`, `..\` |

Matching requests receive **HTTP 400** before reaching application logic.

---

## 9. Security Headers

All responses include:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
```

---

## 10. TLS / Nginx Configuration

Production Nginx (`docker/production/nginx/nginx.conf`):

- **TLS 1.2 / 1.3 only** — SSLv3, TLS 1.0, TLS 1.1 disabled
- **Strong ciphers** — ECDHE + CHACHA20, no RC4/DES/3DES
- **OCSP stapling** enabled
- **DH parameters** — 4096-bit (generate with `openssl dhparam -out dhparam.pem 4096`)
- **HTTP/2** — enabled for all HTTPS connections
- **Session tickets** — disabled (perfect forward secrecy)

### Certificate Renewal (Let's Encrypt)

```bash
# Auto-renewal via ACME challenge
certbot renew --webroot -w /var/www/certbot --quiet

# Add to crontab for automatic renewal
0 3 * * * certbot renew --quiet && nginx -s reload
```

---

## 11. Container Security

### Image Scanning

Trivy scans run on every push to `main` / `develop` via CI:

```yaml
# .github/workflows/ci.yml — container-security-scan job
```

Severity threshold: **CRITICAL** and **HIGH** findings are reported to GitHub Security.

### Runtime Security

- All containers run as **non-root users**
- `read_only` filesystems where possible
- Network segmentation: `prod-db` network is `internal: true` (no external access)
- Resource limits enforced via Docker deploy constraints

---

## 12. Secret Rotation

Use `scripts/rotate-secrets.sh` for automated rotation:

```bash
# Dry run — preview changes without applying
./scripts/rotate-secrets.sh --dry-run

# Apply rotation (requires running Docker stack)
./scripts/rotate-secrets.sh --env-file .env.production

# After rotation:
# 1. Update GitHub Actions secrets
# 2. Update Vault / AWS Secrets Manager
# 3. Notify team (need-to-know only)
# 4. Remove backup env file
```

---

## 13. Vulnerability Reporting

If you discover a security vulnerability in UniVex:

1. **Do NOT** open a public GitHub issue
2. Email: `security@univex.dev` (or contact BitR1FT directly)
3. Include: description, reproduction steps, impact assessment
4. Response time: within 48 hours
5. Coordinated disclosure: patch + CVE assignment before public disclosure

---

*UniVex v2.0 — Supernova | Security-first design by BitR1FT*
