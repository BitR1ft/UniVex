# UniVex v1 → v2 Migration Guide

> **Day 30: Documentation, Migration Guide & v2.0 Release**  
> Author: BitR1FT | Released with UniVex v2.0.0 "Supernova"

---

## Overview

UniVex v2.0 ("Supernova") is a major release that adds 35+ new agent tools, multi-agent orchestration, cloud security scanning, compliance mapping, a premium cyberpunk UI, production-grade security hardening, and comprehensive documentation.

This guide walks you through migrating from v1.x to v2.0.

**Estimated migration time:** 30–60 minutes for a standard installation.

---

## Table of Contents

1. [Breaking Changes](#1-breaking-changes)
2. [New Services (Docker Compose)](#2-new-services-docker-compose)
3. [Environment Variable Changes](#3-environment-variable-changes)
4. [Database Schema Migration](#4-database-schema-migration)
5. [API Changes](#5-api-changes)
6. [Frontend Changes](#6-frontend-changes)
7. [Step-by-Step Migration](#7-step-by-step-migration)
8. [Rollback Procedure](#8-rollback-procedure)
9. [Post-Migration Verification](#9-post-migration-verification)

---

## 1. Breaking Changes

| Area | v1.x | v2.0 | Action Required |
|------|------|------|----------------|
| **Docker Compose** | 8 services | 11 services | Add Redis, ChromaDB, Nginx |
| **Nginx** | Optional | Required in production | Deploy `docker/production/nginx/nginx.conf` |
| **Redis** | Optional (in-memory fallback) | Required for job queue & cache | Add `REDIS_URL` env var |
| **Python** | 3.10+ | 3.11+ | Upgrade Python runtime |
| **API prefix** | `/api/v1/` on some routes | All routes use `/api/` | Update any hardcoded clients |
| **CORS** | Permissive defaults | Strict production defaults | Set `BACKEND_CORS_ORIGINS` |
| **JWT** | 30-min access tokens | Configurable (default 30 min) | No action if using defaults |

---

## 2. New Services (Docker Compose)

v2.0 adds three new services. Add these to your `docker-compose.yml`:

### Redis (required)

```yaml
redis:
  image: redis:7.2-alpine
  container_name: univex-redis
  restart: unless-stopped
  command: redis-server --requirepass ${REDIS_PASSWORD} --maxmemory 512mb --maxmemory-policy allkeys-lru
  ports:
    - "6379:6379"
  volumes:
    - redis-data:/data
  networks:
    - app-network
  healthcheck:
    test: ["CMD", "redis-cli", "--no-auth-warning", "-a", "${REDIS_PASSWORD}", "ping"]
    interval: 10s
    timeout: 5s
    retries: 5
```

### ChromaDB (optional — required for RAG knowledge base)

```yaml
chromadb:
  image: chromadb/chroma:0.4.24
  container_name: univex-chromadb
  restart: unless-stopped
  ports:
    - "8020:8000"
  volumes:
    - chromadb-data:/chroma/chroma
  networks:
    - app-network
  environment:
    IS_PERSISTENT: "TRUE"
    ALLOW_RESET: "FALSE"
```

### Nginx (production only — see `docker/production/docker-compose.production.yml`)

The production compose file already includes Nginx with TLS termination, HTTP/2, and security headers. For development, Nginx is optional.

### Volume declarations

Add these to your `volumes:` section:

```yaml
volumes:
  redis-data:
    name: univex-redis-data
  chromadb-data:
    name: univex-chromadb-data
```

---

## 3. Environment Variable Changes

### New Required Variables

```bash
# Redis
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
REDIS_PASSWORD=your-secure-redis-password

# ChromaDB (if using RAG features)
CHROMADB_URL=http://chromadb:8020

# Secret rotation
ADMIN_IP_ALLOWLIST=10.0.0.0/8,192.168.0.0/16  # Optional, defaults to RFC-1918

# Production URL (required in production)
PRODUCTION_URL=https://your-domain.com
PRODUCTION_API_URL=https://your-domain.com/api
PRODUCTION_WS_URL=wss://your-domain.com/ws

# 2FA (optional — enable in production)
TOTP_ENABLED=true
```

### Changed Variables

| Variable | v1.x Default | v2.0 Default | Notes |
|----------|-------------|-------------|-------|
| `VERSION` | `1.0.x` | `2.0.0` | Updated automatically |
| `RATE_LIMIT_ENABLED` | `false` | `true` | Rate limiting now on by default |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | `30` | Shorter for security |

### Removed Variables

None in v2.0. All v1.x variables remain supported.

---

## 4. Database Schema Migration

### PostgreSQL

v2.0 adds the following tables. Run this migration script:

```bash
# Backup first!
./scripts/backup-databases.sh

# Apply migration
docker compose exec backend python -c "
from app.db.migrations import run_v2_migrations
import asyncio
asyncio.run(run_v2_migrations())
"
```

**New tables in v2.0:**

```sql
-- Compliance framework results
CREATE TABLE IF NOT EXISTS compliance_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    framework VARCHAR(50) NOT NULL,  -- OWASP, PCI-DSS, NIST, CIS
    status VARCHAR(20) NOT NULL,     -- passed, failed, partial
    score FLOAT NOT NULL DEFAULT 0.0,
    findings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Campaign execution state
CREATE TABLE IF NOT EXISTS campaign_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    result JSONB,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- 2FA user settings
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret TEXT,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_backup_codes TEXT[],
    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE;

-- External integrations (SIEM, Slack, Jira, etc.)
CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,       -- splunk, elastic, slack, jira, teams
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Plugin registry
CREATE TABLE IF NOT EXISTS plugins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(20) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    config JSONB NOT NULL DEFAULT '{}',
    installed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_compliance_results_project ON compliance_results(project_id);
CREATE INDEX IF NOT EXISTS idx_campaign_targets_campaign ON campaign_targets(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_targets_status ON campaign_targets(status);
CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id);
```

### Neo4j

v2.0 adds new node types for cloud resources. No breaking changes — new constraints are additive:

```cypher
// Cloud resource nodes
CREATE CONSTRAINT cloud_resource_id IF NOT EXISTS
  FOR (r:CloudResource) REQUIRE r.id IS UNIQUE;

// Compliance nodes
CREATE CONSTRAINT compliance_check_id IF NOT EXISTS
  FOR (c:ComplianceCheck) REQUIRE c.id IS UNIQUE;

// Plugin nodes
CREATE CONSTRAINT plugin_name IF NOT EXISTS
  FOR (p:Plugin) REQUIRE p.name IS UNIQUE;
```

---

## 5. API Changes

### New Endpoints in v2.0

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/compliance/{project_id}/run` | Run compliance scan |
| `GET` | `/api/compliance/{project_id}/results` | Get compliance results |
| `GET/POST` | `/api/campaigns` | List / create campaigns |
| `POST` | `/api/campaigns/{id}/start` | Start campaign |
| `GET` | `/api/campaigns/{id}/status` | Campaign status |
| `GET/POST` | `/api/findings` | List / create findings |
| `PATCH` | `/api/findings/{id}` | Update finding (triage) |
| `GET/POST` | `/api/integrations` | List / configure integrations |
| `GET/POST` | `/api/plugins` | List / install plugins |
| `POST` | `/api/auth/2fa/setup` | Begin 2FA enrollment |
| `POST` | `/api/auth/2fa/verify` | Verify TOTP token |
| `GET` | `/api/reports/{id}/pdf` | Download PDF report |
| `POST` | `/api/reports/generate` | Generate report from findings |

### Changed Endpoints

All existing v1.x endpoints remain **backward compatible** — no changes to request/response schemas.

---

## 6. Frontend Changes

### New Pages

| Route | Description |
|-------|-------------|
| `/reports` | Report builder and PDF viewer |
| `/campaigns` | Multi-target campaign dashboard |
| `/findings` | Findings triage and management |
| `/integrations` | SIEM / notification integrations |
| `/plugins` | Plugin marketplace |
| `/settings/2fa` | Two-factor authentication setup |

### Design System Overhaul

v2.0 ships a full cyberpunk design system. If you've customised the frontend:

1. Review `frontend/tailwind.config.js` — new colour tokens added
2. Review `frontend/app/globals.css` — new CSS variables and animations
3. Component API changes: none — all existing components remain API-compatible

### Service Worker / PWA

v2.0 ships a service worker (`frontend/public/sw.js`). The app is now installable as a PWA.

---

## 7. Step-by-Step Migration

### Step 1: Backup everything

```bash
# Backup databases
./scripts/backup-databases.sh --dest /tmp/v1-backup

# Backup environment files
cp .env .env.v1.backup
cp docker-compose.yml docker-compose.yml.v1.backup
```

### Step 2: Pull v2.0 code

```bash
git fetch origin
git checkout v2.0.0
```

### Step 3: Update environment variables

```bash
# Add new required variables to .env
echo "REDIS_URL=redis://:your-redis-password@redis:6379/0" >> .env
echo "REDIS_PASSWORD=your-redis-password" >> .env
echo "CHROMADB_URL=http://chromadb:8020" >> .env
echo "RATE_LIMIT_ENABLED=true" >> .env
```

### Step 4: Pull new Docker images

```bash
docker compose pull
```

### Step 5: Start new services

```bash
# Start Redis and ChromaDB first
docker compose up -d redis chromadb

# Wait for them to be healthy
sleep 10

# Run database migrations
docker compose run --rm backend python -c "
from app.db.base import Base, engine
import asyncio
asyncio.run(engine.run_migrations())
"
```

### Step 6: Deploy application

```bash
# Rolling restart of all services
docker compose up -d --no-build
```

### Step 7: Configure Nginx (production only)

```bash
# Copy nginx config
cp docker/production/nginx/nginx.conf /etc/nginx/nginx.conf

# Generate DH parameters (takes ~5 minutes)
openssl dhparam -out /etc/nginx/certs/dhparam.pem 4096

# Obtain TLS certificate (Let's Encrypt)
certbot certonly --webroot -w /var/www/certbot -d your-domain.com

# Reload Nginx
nginx -s reload
```

### Step 8: Verify migration

```bash
./scripts/health-check.sh
```

---

## 8. Rollback Procedure

If migration fails:

```bash
# Stop v2.0 services
docker compose down

# Restore v1.x env file
cp .env.v1.backup .env

# Checkout v1.x code
git checkout v1.2.0

# Restore database from backup
# PostgreSQL:
docker compose up -d postgres
PGPASSWORD=your-pass pg_restore \
  -h localhost -U univex -d univex \
  /tmp/v1-backup/univex-backup-*.tar.gz

# Restart v1.x services
docker compose up -d
```

---

## 9. Post-Migration Verification

```bash
# 1. Health check all services
./scripts/health-check.sh

# 2. Check API version
curl http://localhost:8000/api/version

# 3. Verify new endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/compliance

# 4. Run test suite
cd backend && python -m pytest tests/ -q --ignore=tests/test_auth.py

# 5. Verify frontend
curl -sf http://localhost:3000 | grep "UniVex"
```

---

*UniVex v2.0 — "Supernova" | Migration guide by BitR1FT*
