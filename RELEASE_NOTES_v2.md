# UniVex v2.0.0 "Supernova" — Release Notes

> **Release Date:** 2026-03-21  
> **Tag:** `v2.0.0`  
> **Codename:** Supernova  
> **Author:** BitR1FT

---

## 🚀 Highlights

UniVex v2.0 "Supernova" is the biggest release in the project's history — adding **35+ new agent tools**, **multi-agent orchestration**, **cloud security scanning** across AWS/Azure/GCP, **compliance mapping** against OWASP/PCI-DSS/NIST/CIS, a complete **cyberpunk UI overhaul**, production-grade **security hardening**, and **3,200+ backend tests**.

---

## ✨ New Features

### 🔴 Phase 1: Web Arsenal Expansion (Days 1–6)

**XSS Detection Engine** (Day 1)
- DOM XSS, reflected XSS, stored XSS detection tools
- Headless browser-based payload testing

**CSRF / SSRF / Open Redirect** (Day 2)
- 5 new tools for CSRF token bypass, SSRF internal probing, redirect chain analysis

**IDOR & Auth Bypass** (Day 3)
- Object-level authorization testing
- Authentication bypass via parameter manipulation

**JWT / OAuth Token Attacks** (Day 4)
- `alg:none` attack, JWT secret brute-force, OAuth token hijacking

**API Security (REST/GraphQL)** (Day 5)
- GraphQL introspection, schema enumeration, BOLA/BFLA detection
- New MCP server: `api-security-server` (port 8005)

**Advanced Injections** (Day 6)
- SSTI detection, XXE parsing, LDAP/NoSQL injection
- New MCP server: `injection-server` (port 8006)

---

### 🟣 Phase 2: AI Brain (Days 7–12)

**Multi-Agent Orchestration** (Day 7)
- Planner, Recon, Exploit, Validator, Reporting agents
- Hierarchical task decomposition with DAG scheduling

**RAG Knowledge Base** (Day 8)
- ChromaDB vector store with CVE/OWASP/technique embeddings
- Semantic similarity search for attack planning

**Attack Planning & Chain-of-Thought** (Day 9)
- Dynamic attack plan generation with backtracking
- Parallel branch exploration for kill-chain optimization

**Plugin Architecture** (Day 10)
- Python-based plugin system with sandboxed execution
- 2 example plugins: `custom-payloads`, `slack-notifier`

**Redis Infrastructure** (Day 11)
- Background job queue for long-running scans
- Distributed rate limiting backed by Redis
- Response caching for expensive LLM calls

**mTLS for MCP Servers** (Day 12)
- Mutual TLS between backend and all MCP tool servers
- Certificate management with auto-renewal

---

### 🟢 Phase 3: Reports & Campaigns (Days 13–18)

**PDF/HTML Report Engine** (Day 13)
- Executive, Technical, and Compliance report templates
- Charts: vulnerability distribution, severity timeline, CVSS breakdown
- PDF generation with `weasyprint`

**Report Builder UI** (Day 14)
- Drag-and-drop section editor
- Live preview, template selection, one-click PDF download

**Campaign Engine** (Day 15)
- Multi-target scanning with parallel execution (up to 10 targets)
- Campaign scheduling, progress tracking, result aggregation

**Campaign Dashboard UI** (Day 16)
- Campaign wizard (3-step: targets → tools → schedule)
- Real-time progress dashboard with per-target status

**AutoChain v2 Templates** (Day 17)
- 5 new automated attack templates: Web App Full Audit, API Security Audit,
  Cloud Misconfiguration Scan, Container Security Audit, Compliance Check

**Findings Management** (Day 18)
- Finding triage: status (open/in-review/resolved/wont-fix), severity, assignee
- Deduplication engine, false-positive marking, evidence attachment

---

### 🔵 Phase 4: Cloud & Compliance (Days 19–24)

**AWS Security Scanner** (Day 19)
- 6 tools: S3 bucket exposure, IAM privilege escalation, Security Group misconfiguration,
  CloudTrail gaps, RDS public access, Lambda public function detection
- New MCP server: `aws-security-server` (port 8007)

**Azure & GCP Scanners** (Day 20)
- 7 tools: Azure Storage public blobs, ARM policy gaps, GCP public buckets,
  IAM binding analysis, Compute firewall rules, GKE misconfiguration

**Container & Kubernetes Security** (Day 21)
- 6 tools: privileged container detection, host namespace sharing,
  K8s RBAC analysis, pod security policy audit, secrets in env vars

**Compliance Mapping** (Day 22)
- 4 frameworks: OWASP Top 10, PCI-DSS 4.0, NIST 800-53, CIS Controls v8
- Automated pass/fail scoring with remediation recommendations
- REST API: `/api/compliance/*`

**SIEM Integration** (Day 23)
- 5 integrations: Splunk HEC, Elasticsearch, Microsoft Sentinel, Sumo Logic, Datadog
- Finding export in CEF, LEEF, and JSON-LD formats

**Integration & Notification UI** (Day 24)
- Integration configuration dashboard
- Slack/Teams/PagerDuty webhook setup
- Jira/ServiceNow ticket creation from findings

---

### 🟡 Phase 5: Premium UX & Production (Days 25–30)

**Cyberpunk Design System Overhaul** (Day 25)
- Custom colour palette: cyber-green, neon-blue, threat-red, matrix-cyan
- 12 new UI components: Button, Card, Badge, Modal, Tooltip, Input, Select,
  Checkbox, Progress, Skeleton, Alert, Breadcrumb
- Framer Motion animations throughout
- Dark mode (default) + light mode toggle

**Dashboard Redesign** (Day 26)
- Command Palette (Ctrl+K) for quick navigation
- StatsGrid with animated counters
- ActivityFeed, ScanTimeline, VulnSeverityChart (Recharts)
- AttackSurfaceMap (interactive force graph)

**Premium Chat & Graph Interface** (Day 27)
- ChatSidebar with conversation history and bookmarks
- ToolExecutionCard: real-time tool execution status
- ApprovalDialog: human-in-the-loop exploit confirmation
- AgentThinking indicator with streaming thought display
- GraphControls: zoom, filter, cluster, node highlighting
- NodeDetail panel: asset details, vulnerability list, relationships

**E2E Testing & Performance** (Day 28)
- 54 Playwright E2E tests across all pages
- 2 k6 performance scripts: WebSocket streaming, concurrent scans
- Service Worker + PWA manifest for offline-capable frontend
- Next.js security headers and build optimizations

**Security Hardening** (Day 29)
- Nginx reverse proxy: TLS 1.2/1.3, HTTP/2, security headers, WebSocket proxy
- TOTP 2FA for all user accounts
- Account lockout: 5 failures → 15-minute lockout
- Admin IP allow-listing
- 62 security tests
- Secret rotation script
- Database backup script with retention policy

**Documentation & v2.0 Release** (Day 30)
- Complete architecture documentation (multi-agent, plugin, cloud, report)
- Full API reference (55+ endpoints)
- Plugin Development Guide
- Cloud Security Guide (AWS/Azure/GCP)
- Compliance Guide (OWASP/PCI-DSS/NIST/CIS)
- v1 → v2 Migration Guide
- Updated User Manual

---

## 📊 v2.0 Statistics

| Metric | v1.0 | v2.0 | Δ |
|--------|------|------|---|
| **Agent Tools** | 37 | 72+ | +35 |
| **MCP Servers** | 8 | 12 | +4 |
| **AutoChain Templates** | 2 | 7 | +5 |
| **Backend Tests** | 1,624 | 3,200+ | +1,576 |
| **Frontend Tests** | 87 | 200+ | +113 |
| **E2E Tests** | ~10 | 54+ | +44 |
| **API Endpoints** | 30 | 55+ | +25 |
| **Docker Services** | 8 | 11 | +3 |
| **Neo4j Node Types** | 17 | 20+ | +3 |
| **Frontend Pages** | 5 | 12+ | +7 |
| **Documentation Files** | 19 | 28+ | +9 |
| **Lines of Code (est.)** | 21,000 | 55,000+ | +34,000 |

---

## 🔧 Bug Fixes

- Fixed asyncio event loop issues in Python 3.12 test helpers
- Fixed FastAPI DELETE routes returning incorrect response models
- Fixed ChromaDB connection timeout on cold start
- Fixed Neo4j APOC query timeout during large graph operations
- Fixed JWT refresh token race condition under concurrent requests
- Fixed campaign progress percentage calculation for skipped targets
- Fixed PDF report generation memory leak on large finding sets
- Fixed WebSocket disconnect handling during agent streaming

---

## ⚠️ Breaking Changes

See [MIGRATION_v1_to_v2.md](MIGRATION_v1_to_v2.md) for full details.

| Change | Impact |
|--------|--------|
| Redis now required | Add `REDIS_URL` to `.env` |
| Nginx required in production | Deploy `docker/production/nginx/nginx.conf` |
| Rate limiting on by default | Review `RATE_LIMIT_ENABLED` |
| Access token lifetime: 60m → 30m | Clients must handle token refresh |

---

## 🔒 Security Improvements

- TOTP 2FA support (RFC 6238)
- Account lockout after 5 failed attempts
- Admin endpoint IP allow-listing
- TLS 1.2/1.3 only in Nginx (no legacy protocols)
- OCSP stapling enabled
- HTTP/2 push for frontend assets
- WAF enhanced with additional attack signatures
- Container images scanned with Trivy in CI
- Secret rotation automation (`scripts/rotate-secrets.sh`)

---

## 📦 Dependency Updates

### Backend

```
pyotp==2.9.0                  (new — TOTP 2FA)
weasyprint==62.1              (updated — PDF generation)
chromadb-client==0.4.24       (new — RAG vector store)
redis==5.0.1                  (updated)
celery==5.3.6                 (updated — background jobs)
```

### Frontend

```
framer-motion==11.0.6         (new — UI animations)
recharts==2.12.1              (updated — data visualization)
@radix-ui/react-dialog==1.0.5 (updated)
playwright==1.42.1            (new — E2E testing)
```

---

## 🙏 Acknowledgments

UniVex v2.0 is an independent open-source project by **BitR1FT**.  
No sponsor. No team. Just relentless engineering. 🚀

---

## 📋 Upgrade

```bash
# 1. Read the migration guide
cat MIGRATION_v1_to_v2.md

# 2. Backup
./scripts/backup-databases.sh

# 3. Upgrade
git fetch && git checkout v2.0.0
docker compose pull
docker compose up -d

# 4. Verify
./scripts/health-check.sh
```

---

*UniVex v2.0.0 "Supernova" — The Full-Stack Web Pentesting Agent*  
*Released by BitR1FT on 2026-03-21*
