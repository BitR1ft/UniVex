# UniVex v2.0 — Full-Stack Web Pentesting Agent Improvement Plan

**Author:** BitR1FT  
**Created:** March 17, 2026  
**Baseline:** UniVex v1.0.2 ("Multiverse")  
**Goal:** Transform UniVex into the definitive **full-stack web application pentesting agent** — autonomous, comprehensive, and production-grade.

---

## Executive Summary

UniVex v1.0 delivers a solid kill-chain from recon to flag capture, primarily targeting CTF/HTB-style infrastructure. **v2.0 elevates the platform into a true full-stack web pentesting agent** by adding:

1. **Deep web application attack modules** (XSS, CSRF, SSRF, IDOR, auth bypass, API security, GraphQL, JWT attacks)
2. **Professional PDF/HTML report generation** with executive summaries
3. **Multi-target campaign engine** for enterprise-scale engagements
4. **Cloud security scanning** (AWS, Azure, GCP misconfigurations)
5. **Advanced AI reasoning** (multi-agent orchestration, RAG-based knowledge, chain-of-thought planning)
6. **Premium frontend overhaul** (real-time dashboards, report builder, campaign management)
7. **Redis-backed infrastructure** (caching, rate limiting, job queues)
8. **mTLS for MCP** (production-grade tool server security)
9. **Plugin architecture** (community-extensible tool ecosystem)
10. **SIEM & compliance integration** (PCI-DSS, OWASP Top 10 mapping)

### Scope & Assumptions

- **AI-paced days:** Each "day" represents the output of ≈10 skilled human-equivalents working a full day. AI can parallelize, has zero context-switch cost, and can code/test/debug simultaneously.
- **Timeline:** 30 working days (≈ 6 calendar weeks), divided into 5 phases.
- **Testing:** Every day includes tests for that day's work. No "testing phase" at the end — quality is continuous.
- **No breaking changes** to the v1.0 API unless marked. All new features are additive.

---

## Current State (v1.0.2) — What We Have

| Area | Status |
|------|--------|
| Backend (FastAPI + Prisma) | ✅ 12,500+ lines, 30+ API endpoints |
| Frontend (Next.js 14 + Tailwind) | ✅ 5,000+ lines, 5 dashboard pages |
| AI Agent (LangGraph ReAct) | ✅ GPT-4/Claude/Gemini/Groq/OpenRouter |
| 37+ Agent Tools | ✅ Recon, exploitation, post-exploitation, AD |
| 8 MCP Tool Servers | ✅ Naabu, Curl, Nuclei, Metasploit, ffuf, SQLMap, HashCracker, Nikto |
| AutoChain Pipeline | ✅ htb_easy, htb_medium templates |
| Neo4j Attack Graph | ✅ 17+ node types, 20+ relationships |
| Observability (Prometheus/Grafana/OTEL) | ✅ Metrics, dashboards, tracing |
| Security (JWT, RBAC, WAF, rate limiting) | ✅ Production-grade auth |
| Tests | ✅ 1624+ backend, 87 frontend, E2E (Playwright) |
| CI/CD | ✅ 6 GitHub Actions workflows |

### What's Missing for Full-Stack Web Pentesting

| Gap | Impact |
|-----|--------|
| No dedicated XSS/CSRF/SSRF/IDOR tools | Can't autonomously find web-app logic flaws |
| No API security testing (REST/GraphQL/gRPC) | Misses modern API attack surfaces |
| No JWT/OAuth/session attack tools | Limited auth bypass capability |
| No report generation (PDF/HTML) | Can't deliver professional pentest reports |
| No multi-target campaign engine | Can't handle enterprise engagements |
| No cloud security scanning | Ignores cloud misconfigurations |
| No plugin/extension system | Hard for community to extend |
| No Redis infrastructure | Rate limiting is in-memory, no job queues |
| No mTLS on MCP channels | Tool traffic is unencrypted |
| Basic frontend UX | No real-time dashboards, report builder, campaign view |
| No SIEM/compliance integration | Can't export to Splunk/ELK, no compliance mapping |
| No advanced AI features | No multi-agent, no RAG knowledge base, no planning |

---

## Phase 1: Web Application Attack Arsenal (Days 1–6)

> **Objective:** Build the missing web-app-specific attack tools and MCP servers that make UniVex a true web pentesting agent.

---

### Day 1 — XSS Detection & Exploitation Engine

**Files:**
- `[NEW] backend/app/agent/tools/xss_tools.py`
- `[NEW] backend/app/mcp/servers/xss_server.py`
- `[MODIFY] backend/app/agent/tools/__init__.py`
- `[MODIFY] backend/app/agent/tools/tool_registry.py`
- `[NEW] backend/tests/agent/test_xss_tools.py`

**Tasks:**
- [ ] Build `ReflectedXSSTool` — payload injection into URL params, detection of reflection in response body
- [ ] Build `StoredXSSTool` — payload submission to forms/APIs, delayed detection via secondary request
- [ ] Build `DOMXSSTool` — DOM sink/source analysis using headless browser (Playwright integration)
- [ ] Build `XSSMCPServer` (:8008) — wrapper for Dalfox/XSStrike via subprocess, JSON-RPC 2.0 interface
- [ ] Implement polyglot payload engine (HTML context, attribute context, JS context, URL context)
- [ ] Add severity classification (reflected vs stored vs DOM, same-origin impact)
- [ ] Register all XSS tools in `ToolRegistry` with `web_app_attack` phase gating
- [ ] Write 60+ unit tests covering payload generation, detection, false-positive filtering
- [ ] Update Docker Kali image to include Dalfox and XSStrike

**Deliverables:** 3 new agent tools, 1 new MCP server, 60+ tests

---

### Day 2 — CSRF, SSRF & Request Forgery Toolkit

**Files:**
- `[NEW] backend/app/agent/tools/csrf_tools.py`
- `[NEW] backend/app/agent/tools/ssrf_tools.py`
- `[MODIFY] backend/app/mcp/servers/curl_server.py` (enhance for SSRF probing)
- `[NEW] backend/tests/agent/test_csrf_tools.py`
- `[NEW] backend/tests/agent/test_ssrf_tools.py`

**Tasks:**
- [ ] Build `CSRFDetectTool` — detect missing/weak CSRF tokens, analyze SameSite cookie attributes, detect token reuse
- [ ] Build `CSRFExploitTool` — generate PoC HTML forms for confirmed CSRF endpoints
- [ ] Build `SSRFProbeTool` — internal IP scanning via SSRF vectors (http, gopher, file, dict protocols)
- [ ] Build `SSRFBlindTool` — out-of-band SSRF detection using Interactsh/Burp Collaborator callbacks
- [ ] Build `OpenRedirectTool` — detect and chain open redirects for OAuth flows
- [ ] Enhance `CurlServer` to support SSRF-specific options (follow_redirects control, protocol restrictions, timeout patterns)
- [ ] Add OWASP Top 10 tagging to all findings (A01–A10 mapping)
- [ ] Write 50+ tests per tool category
- [ ] Add Neo4j node type `WebVulnerability` with relationship `HAS_WEB_VULN`

**Deliverables:** 5 new agent tools, 100+ tests, enhanced curl MCP server

---

### Day 3 — IDOR & Access Control Testing Suite ✅ COMPLETE

**Files:**
- `[NEW] backend/app/agent/tools/idor_tools.py` ✅
- `[NEW] backend/app/agent/tools/auth_bypass_tools.py` ✅
- `[NEW] backend/tests/agent/test_idor_tools.py` ✅
- `[NEW] backend/tests/agent/test_auth_bypass_tools.py` ✅

**Tasks:**
- [x] Build `IDORDetectTool` — detect Insecure Direct Object References by parameter enumeration (sequential IDs, UUIDs)
- [x] Build `IDORExploitTool` — automatic exploitation with cross-user resource access verification
- [x] Build `PrivilegeEscalationWebTool` — test horizontal/vertical privilege escalation via role manipulation
- [x] Build `AuthBypassTool` — test common auth bypass patterns (path traversal, HTTP verb tampering, header injection: X-Forwarded-For, X-Original-URL)
- [x] Build `SessionPuzzlingTool` — test session fixation, session puzzling, concurrent session attacks
- [x] Build `RateLimitBypassTool` — test rate limiting bypass via IP rotation headers, parameter pollution
- [x] Write 80+ tests with mock HTTP servers (137 tests written)
- [x] Register all Day 3 tools in `ToolRegistry` and `AttackPathRouter`
- [x] OWASP A01:2021 tags on all findings

**Deliverables:** 6 new agent tools, 137+ tests

---

### Day 4 — JWT, OAuth & Token Attack Suite ✅ COMPLETE

**Files:**
- `[NEW] backend/app/agent/tools/jwt_tools.py` ✅
- `[NEW] backend/app/agent/tools/oauth_tools.py` ✅
- `[NEW] backend/tests/agent/test_jwt_tools.py` ✅
- `[NEW] backend/tests/agent/test_oauth_tools.py` ✅

**Tasks:**
- [x] Build `JWTAnalyzeTool` — decode JWT, identify algorithm, check for `alg:none` vulnerability, key confusion (RS256→HS256)
- [x] Build `JWTBruteForceTool` — brute-force weak HMAC secrets using common wordlists
- [x] Build `JWTForgeTool` — forge tokens with modified claims (role escalation, user impersonation)
- [x] Build `OAuthFlowTool` — test OAuth 2.0 flows for redirect_uri manipulation, scope escalation, PKCE bypass
- [x] Build `OAuthTokenLeakTool` — detect token leakage via referer headers, browser history, open redirects
- [x] Build `APIKeyLeakTool` — detect API keys in responses, JS files, error messages, git history
- [x] Write 70+ tests covering all JWT algorithms and OAuth flows (139 tests written)
- [x] Register all Day 4 tools in `ToolRegistry` and `AttackPathRouter`
- [x] OWASP A02:2021 tags on all JWT/token findings

**Deliverables:** 6 new agent tools, 139+ tests

---

### Day 5 — API Security Testing (REST, GraphQL, gRPC) ✅ COMPLETE

**Files:**
- `[DONE] backend/app/agent/tools/api_security_tools.py`
- `[DONE] backend/app/agent/tools/graphql_tools.py`
- `[DONE] backend/app/mcp/servers/api_security_server.py`
- `[DONE] backend/tests/agent/test_api_security_tools.py`
- `[DONE] backend/tests/agent/test_graphql_tools.py`

**Tasks:**
- [x] Build `OpenAPIParserTool` — parse Swagger/OpenAPI specs, enumerate all endpoints automatically
- [x] Build `APIFuzzTool` — fuzz API parameters with type-aware mutations (string overflows, negative ints, null injection)
- [x] Build `MassAssignmentTool` — detect mass assignment vulnerabilities by injecting unexpected fields
- [x] Build `GraphQLIntrospectionTool` — detect enabled GraphQL introspection, enumerate types/queries/mutations
- [x] Build `GraphQLInjectionTool` — test for GraphQL-specific injection (query batching, nested query DoS, field suggestion leak)
- [x] Build `GraphQLIDORTool` — test IDOR via GraphQL query variable manipulation
- [x] Build `APIRateLimitTool` — test API rate limiting effectiveness and bypass techniques
- [x] Build `CORSMisconfigTool` — detect permissive CORS configurations (wildcard origins, credential exposure)
- [x] Create `APISecurityMCPServer` (:8009) — lightweight API fuzzing proxy
- [x] Write 90+ tests (207 in test_api_security_tools.py + 49 in test_graphql_tools.py = 256 tests)

**Deliverables:** 8 new agent tools, 1 new MCP server, 256 tests

---

### Day 6 — Advanced Web Injection (NoSQL, SSTI, LDAP, XXE, Command Injection) ✅ COMPLETE

**Files:**
- `[DONE] backend/app/agent/tools/injection_tools.py`
- `[DONE] backend/app/mcp/servers/injection_server.py`
- `[DONE] backend/tests/agent/test_injection_tools.py`

**Tasks:**
- [x] Build `NoSQLInjectionTool` — MongoDB/CouchDB operator injection ($gt, $ne, $regex), auth bypass
- [x] Build `SSTIDetectTool` — Server-Side Template Injection detection (Jinja2, Twig, Freemarker, Mako, Pebble)
- [x] Build `SSTIExploitTool` — automatic payload generation per template engine for RCE
- [x] Build `LDAPInjectionTool` — LDAP filter injection for auth bypass and data extraction
- [x] Build `XXETool` — XML External Entity injection (file read, SSRF, DoS via billion laughs)
- [x] Build `CommandInjectionTool` — OS command injection via various separators (;, |, &&, $(), backticks)
- [x] Build `HeaderInjectionTool` — HTTP header injection / response splitting / CRLF injection
- [x] Build `InjectionMCPServer` (:8010) — unified injection testing harness via MCP
- [x] Add `InjectionVulnerability` findings structure with `engine`, `payload`, `impact` properties
- [x] Write 100+ tests (254 tests in test_injection_tools.py)

**Deliverables:** 7 new agent tools, 1 new MCP server, 254 tests

---

### Phase 1 Totals

| Metric | Count |
|--------|-------|
| New Agent Tools | **35** |
| New MCP Servers | **3** (XSS :8008, API :8009, Injection :8010) |
| New Tests | **460+** |
| New Neo4j Node Types | 3 (WebVulnerability, TokenVulnerability, InjectionVulnerability) |
| Total Agent Tools (cumulative) | **72+** |
| Total MCP Servers (cumulative) | **11** |

---

## Phase 2: AI Brain Upgrade & Plugin Architecture (Days 7–12)

> **Objective:** Upgrade the AI agent from single-agent ReAct to multi-agent orchestration with RAG knowledge, and build a plugin system for community extensibility.

---

### Day 7 — Multi-Agent Orchestration Framework

**Files:**
- `[NEW] backend/app/agent/orchestrator.py`
- `[NEW] backend/app/agent/agents/recon_agent.py`
- `[NEW] backend/app/agent/agents/exploit_agent.py`
- `[NEW] backend/app/agent/agents/web_agent.py`
- `[NEW] backend/app/agent/agents/report_agent.py`
- `[MODIFY] backend/app/agent/core/`
- `[NEW] backend/tests/agent/test_orchestrator.py`

**Tasks:**
- [ ] Design multi-agent architecture: **Orchestrator Agent** delegates to specialized sub-agents
- [ ] Build `OrchestratorAgent` — top-level planner that decomposes targets into parallel workstreams
- [ ] Build `ReconAgent` — specialized for reconnaissance with optimized tool selection
- [ ] Build `WebAppAgent` — specialized for web application attacks (all Phase 1 tools)
- [ ] Build `ExploitAgent` — specialized for exploitation and post-exploitation
- [ ] Build `ReportAgent` — specialized for report generation and finding summarization
- [ ] Implement inter-agent communication via shared `AgentState` with LangGraph subgraphs
- [ ] Add agent-level task queue for parallel execution of independent phases
- [ ] Write 80+ tests for orchestration patterns

**Deliverables:** Multi-agent orchestration framework, 4 specialized agents, 80+ tests

---

### Day 8 — RAG Knowledge Base & Exploit Intelligence

**Files:**
- `[NEW] backend/app/agent/knowledge/`
- `[NEW] backend/app/agent/knowledge/rag_engine.py`
- `[NEW] backend/app/agent/knowledge/embeddings.py`
- `[NEW] backend/app/agent/knowledge/document_loader.py`
- `[MODIFY] backend/requirements.txt` (add chromadb, langchain-chroma)
- `[NEW] docker/chroma/` (ChromaDB service)
- `[MODIFY] docker-compose.yml`
- `[NEW] backend/tests/agent/test_rag_engine.py`

**Tasks:**
- [ ] Deploy ChromaDB vector store as new Docker service
- [ ] Build document ingestion pipeline: security advisories, CVE descriptions, exploit writeups, tool docs
- [ ] Build `RAGEngine` — retrieve relevant context from knowledge base for agent decision-making
- [ ] Integrate RAG context into agent prompts (inject top-K relevant excerpts before tool selection)
- [ ] Build auto-ingest pipeline: new CVEs from NVD feed → embeddings → ChromaDB
- [ ] Build tool documentation embedder: all 72+ tools documented and searchable
- [ ] Build historical attack pattern retriever: learn from past engagement results
- [ ] Write 60+ tests

**Deliverables:** RAG knowledge engine, ChromaDB integration, auto-ingest pipeline, 60+ tests

---

### Day 9 — Advanced AI Planning & Chain-of-Thought

**Files:**
- `[MODIFY] backend/app/agent/core/`
- `[NEW] backend/app/agent/planning/`
- `[NEW] backend/app/agent/planning/attack_planner.py`
- `[NEW] backend/app/agent/planning/dependency_graph.py`
- `[NEW] backend/app/agent/planning/backtrack_engine.py`
- `[NEW] backend/tests/agent/test_planning.py`

**Tasks:**
- [ ] Build `AttackPlanner` — generates structured attack plans with dependency graphs before execution
- [ ] Implement tree-of-thought reasoning: explore multiple attack paths, prune unlikely branches
- [ ] Build backtracking engine: when an attack path fails, automatically try alternatives
- [ ] Implement cost-benefit analysis for tool selection (time, risk, likelihood of success)
- [ ] Add "attack strategy" mode: agent explains plan before executing, user can modify
- [ ] Implement plan visualization (Mermaid diagram generation for attack plan)
- [ ] Add plan persistence to PostgreSQL (resume plans across sessions)
- [ ] Write 70+ tests

**Deliverables:** Attack planning engine, tree-of-thought reasoning, backtracking, 70+ tests

---

### Day 10 — Plugin / Extension Architecture

**Files:**
- `[NEW] backend/app/plugins/`
- `[NEW] backend/app/plugins/plugin_manager.py`
- `[NEW] backend/app/plugins/plugin_loader.py`
- `[NEW] backend/app/plugins/plugin_registry.py`
- `[NEW] backend/app/plugins/base_plugin.py`
- `[NEW] backend/app/plugins/sandboxed_runner.py`
- `[NEW] backend/app/api/plugins.py`
- `[NEW] backend/tests/test_plugin_system.py`
- `[NEW] docs/PLUGIN_GUIDE.md`

**Tasks:**
- [ ] Design plugin interface: `BasePlugin` with `register_tools()`, `register_mcp_servers()`, `register_api_routes()`
- [ ] Build `PluginManager` — discover, load, validate, enable/disable plugins at runtime
- [ ] Build `PluginLoader` — load plugins from `plugins/` directory (Python packages with `plugin.yaml` manifest)
- [ ] Build `SandboxedRunner` — execute community plugins with restricted permissions (no filesystem write, no network except target)
- [ ] Create REST API: `GET /api/plugins`, `POST /api/plugins/install`, `DELETE /api/plugins/{id}`
- [ ] Build example plugins: `example_shodan_plugin`, `example_censys_plugin`
- [ ] Write comprehensive `PLUGIN_GUIDE.md` for community developers
- [ ] Write 50+ tests

**Deliverables:** Full plugin system, 2 example plugins, documentation, 50+ tests

---

### Day 11 — Redis Infrastructure & Job Queue

**Files:**
- `[NEW] backend/app/core/redis_client.py`
- `[NEW] backend/app/core/cache.py`
- `[NEW] backend/app/core/job_queue.py`
- `[MODIFY] backend/app/middleware/rate_limiter.py` (switch to Redis-backed)
- `[MODIFY] docker-compose.yml` (add Redis service)
- `[NEW] docker/redis/redis.conf`
- `[NEW] backend/tests/test_redis_integration.py`

**Tasks:**
- [ ] Add Redis 7 as Docker service with persistence (AOF + RDB)
- [ ] Build `RedisClient` wrapper with connection pooling, automatic reconnection
- [ ] Build `CacheManager` — TTL-based caching for CVE lookups, NVD data, scan results
- [ ] Build `JobQueue` — distributed job queue for long-running scans (replaces asyncio tasks)
- [ ] Migrate rate limiter from in-memory dict to Redis sliding window (distributed-friendly)
- [ ] Add Redis-backed session storage for WebSocket connections
- [ ] Implement pub/sub for real-time events (replace some SSE polling)
- [ ] Build cache invalidation strategy for multi-instance deployments
- [ ] Write 60+ tests

**Deliverables:** Redis infrastructure, distributed job queue, Redis-backed rate limiting, 60+ tests

---

### Day 12 — mTLS for MCP Tool Servers

**Files:**
- `[NEW] backend/app/mcp/tls/`
- `[NEW] backend/app/mcp/tls/cert_manager.py`
- `[NEW] backend/app/mcp/tls/mtls_client.py`
- `[MODIFY] backend/app/mcp/base_server.py`
- `[MODIFY] docker/kali/Dockerfile`
- `[NEW] scripts/generate-certs.sh`
- `[NEW] backend/tests/mcp/test_mtls.py`

**Tasks:**
- [ ] Build certificate generation script (CA → server cert → client cert per MCP server)
- [ ] Build `CertManager` — manages cert lifecycle (generation, rotation, revocation)
- [ ] Modify `MCPClient` to use mTLS (verify server cert, present client cert)
- [ ] Modify all MCP servers to require client certificate authentication
- [ ] Add cert volume mount in Docker Compose (shared CA trust store)
- [ ] Support cert rotation without downtime (graceful reload)
- [ ] Add cert expiry monitoring to Prometheus metrics
- [ ] Write 40+ tests

**Deliverables:** mTLS for all MCP channels, cert management, 40+ tests

---

### Phase 2 Totals

| Metric | Count |
|--------|-------|
| New Major Systems | 5 (Multi-agent, RAG, Planning, Plugins, Redis) |
| New Docker Services | 2 (ChromaDB, Redis) |
| Infrastructure Upgrades | 2 (mTLS, Redis rate limiter) |
| New Tests | **360+** |

---

## Phase 3: Report Generation & Campaign Engine (Days 13–18)

> **Objective:** Build professional report generation and multi-target campaign management.

---

### Day 13 — PDF/HTML Report Generation Engine

**Files:**
- `[NEW] backend/app/reports/`
- `[NEW] backend/app/reports/report_engine.py`
- `[NEW] backend/app/reports/templates/`
- `[NEW] backend/app/reports/templates/executive_summary.html`
- `[NEW] backend/app/reports/templates/technical_report.html`
- `[NEW] backend/app/reports/templates/finding_card.html`
- `[NEW] backend/app/reports/pdf_generator.py`
- `[NEW] backend/app/reports/chart_generator.py`
- `[NEW] backend/app/api/reports.py`
- `[NEW] backend/tests/test_reports.py`

**Tasks:**
- [ ] Build HTML report engine using Jinja2 templates
- [ ] Build PDF generation using WeasyPrint (CSS-based PDF from HTML)
- [ ] Design 3 report templates:
  - **Executive Summary** — non-technical, risk heatmap, key findings, business impact
  - **Technical Report** — full details, CVE references, reproduction steps, evidence screenshots
  - **Compliance Report** — OWASP Top 10 / PCI-DSS / NIST 800-53 mapping
- [ ] Build chart generator (matplotlib/plotly): risk distribution pie, severity bar chart, CVSS histogram, attack timeline
- [ ] Build finding deduplication and ranking engine
- [ ] API endpoints: `POST /api/reports/generate`, `GET /api/reports/{id}/download`
- [ ] Add report scheduling (auto-generate on scan completion)
- [ ] Write 60+ tests

**Deliverables:** Report engine, 3 templates, PDF generation, 60+ tests

---

### Day 14 — Report Builder UI (Frontend)

**Files:**
- `[NEW] frontend/app/(dashboard)/reports/page.tsx`
- `[NEW] frontend/app/(dashboard)/reports/[id]/page.tsx`
- `[NEW] frontend/components/reports/ReportBuilder.tsx`
- `[NEW] frontend/components/reports/ReportPreview.tsx`
- `[NEW] frontend/components/reports/FindingsTable.tsx`
- `[NEW] frontend/components/reports/RiskHeatmap.tsx`
- `[NEW] frontend/components/reports/CoverageMatrix.tsx`
- `[NEW] frontend/hooks/useReports.ts`

**Tasks:**
- [ ] Build Report Builder page — select project, choose template, customize sections
- [ ] Build drag-and-drop section reordering
- [ ] Build inline finding editor — modify titles, severity, descriptions before generating
- [ ] Build real-time report preview (live preview as user customizes)
- [ ] Build risk heatmap component (severity × likelihood matrix)
- [ ] Build OWASP Top 10 coverage matrix visualization
- [ ] Build findings table with sorting, filtering, bulk operations
- [ ] Build PDF download button with generation progress indicator
- [ ] Write 20+ frontend tests

**Deliverables:** Full Report Builder UI, 8 new components, 20+ tests

---

### Day 15 — Multi-Target Campaign Engine (Backend)

**Files:**
- `[NEW] backend/app/campaigns/`
- `[NEW] backend/app/campaigns/campaign_engine.py`
- `[NEW] backend/app/campaigns/target_manager.py`
- `[NEW] backend/app/campaigns/scheduler.py`
- `[NEW] backend/app/campaigns/aggregator.py`
- `[NEW] backend/app/api/campaigns.py`
- `[MODIFY] backend/prisma/schema.prisma` (add Campaign, CampaignTarget models)
- `[NEW] backend/tests/test_campaigns.py`

**Tasks:**
- [ ] Build `CampaignEngine` — manage multi-target pentest campaigns
- [ ] Build `TargetManager` — import targets from CSV/JSON, CIDR expansion, scope validation
- [ ] Build `CampaignScheduler` — schedule scans across targets with concurrency limits
- [ ] Build `CampaignAggregator` — aggregate findings across targets, cross-target correlation
- [ ] Add database models: `Campaign`, `CampaignTarget`, `CampaignFinding`
- [ ] API endpoints: `POST /api/campaigns`, `GET /api/campaigns/{id}`, `POST /api/campaigns/{id}/targets/import`
- [ ] Implement campaign-level risk scoring (weighted average across targets)
- [ ] Build cross-target vulnerability correlation (same CVE on multiple hosts)
- [ ] Write 70+ tests

**Deliverables:** Campaign engine, scheduler, aggregator, 70+ tests

---

### Day 16 — Campaign Dashboard UI (Frontend)

**Files:**
- `[NEW] frontend/app/(dashboard)/campaigns/page.tsx`
- `[NEW] frontend/app/(dashboard)/campaigns/[id]/page.tsx`
- `[NEW] frontend/components/campaigns/CampaignWizard.tsx`
- `[NEW] frontend/components/campaigns/TargetGrid.tsx`
- `[NEW] frontend/components/campaigns/CampaignProgress.tsx`
- `[NEW] frontend/components/campaigns/AggregatedFindings.tsx`
- `[NEW] frontend/hooks/useCampaigns.ts`

**Tasks:**
- [ ] Build Campaign creation wizard (multi-step: name → targets → config → schedule → launch)
- [ ] Build target grid with status indicators (pending/scanning/complete/failed per target)
- [ ] Build campaign progress dashboard (overall completion %, per-target breakdown)
- [ ] Build aggregated findings view (cross-target deduplication, severity trends)
- [ ] Build campaign comparison view (compare results across campaigns)
- [ ] Build CSV/JSON target import with validation UI
- [ ] Implement real-time campaign status via WebSocket
- [ ] Write 20+ frontend tests

**Deliverables:** Full Campaign Dashboard, 6 new components, 20+ tests

---

### Day 17 — AutoChain v2: Web Application Templates

**Files:**
- `[MODIFY] backend/app/autochain/`
- `[NEW] backend/app/autochain/templates/web_app_full.py`
- `[NEW] backend/app/autochain/templates/api_pentest.py`
- `[NEW] backend/app/autochain/templates/owasp_top10.py`
- `[NEW] backend/app/autochain/templates/wordpress_full.py`
- `[NEW] backend/app/autochain/templates/cloud_assessment.py`
- `[NEW] backend/tests/agent/test_web_templates.py`

**Tasks:**
- [ ] Build `web_app_full` template — comprehensive web app pentest chain:
  - Recon → Tech detection → Spider/crawl → XSS scan → SQLi scan → CSRF check → SSRF probe → IDOR test → Auth bypass → Report
- [ ] Build `api_pentest` template — REST/GraphQL API testing:
  - OpenAPI discovery → Endpoint enum → Auth testing → Injection → Mass assignment → Rate limit → Report
- [ ] Build `owasp_top10` template — systematic OWASP Top 10 verification:
  - One phase per OWASP category (A01–A10), checklist-based
- [ ] Build `wordpress_full` template — comprehensive WordPress assessment:
  - WPScan → Plugin enum → Theme vuln → User enum → xmlrpc attacks → REST API → Report
- [ ] Build `cloud_assessment` template — cloud misconfiguration scan:
  - S3 bucket enum → IAM analysis → Security group audit → Public exposure check
- [ ] Write 80+ tests per template

**Deliverables:** 5 new AutoChain templates, 80+ tests

---

### Day 18 — Findings Management & Triage System

**Files:**
- `[NEW] backend/app/findings/`
- `[NEW] backend/app/findings/finding_manager.py`
- `[NEW] backend/app/findings/deduplicator.py`
- `[NEW] backend/app/findings/severity_calculator.py`
- `[NEW] backend/app/api/findings.py`
- `[MODIFY] backend/prisma/schema.prisma` (add Finding, Evidence models)
- `[NEW] frontend/app/(dashboard)/findings/page.tsx`
- `[NEW] frontend/components/findings/FindingDetail.tsx`
- `[NEW] frontend/components/findings/FindingTriage.tsx`
- `[NEW] backend/tests/test_findings.py`

**Tasks:**
- [ ] Build `FindingManager` — centralized finding storage with status tracking (open/confirmed/false-positive/resolved)
- [ ] Build `Deduplicator` — intelligent dedup across tools (same vuln found by Nuclei + manual scan)
- [ ] Build `SeverityCalculator` — CVSS 3.1 calculator with environmental score adjustments
- [ ] Build finding triage workflow: assign, annotate, change severity, mark false positive
- [ ] Build evidence attachment system (screenshots, request/response pairs, tool output)
- [ ] API endpoints: CRUD `/api/findings`, `PATCH /api/findings/{id}/triage`
- [ ] Build Findings dashboard with kanban-style triage view
- [ ] Build finding detail page with evidence viewer
- [ ] Write 60+ tests

**Deliverables:** Full findings management system, triage UI, 60+ tests

---

### Phase 3 Totals

| Metric | Count |
|--------|-------|
| New Major Features | 4 (Reports, Campaigns, Web Templates, Findings) |
| New Frontend Pages | 5 |
| New Components | 20+ |
| New AutoChain Templates | 5 (total: 7) |
| New Tests | **310+** |

---

## Phase 4: Cloud Security & Compliance (Days 19–24)

> **Objective:** Add cloud security scanning and compliance/SIEM integration.

---

### Day 19 — AWS Security Scanner

**Files:**
- `[NEW] backend/app/agent/tools/cloud/`
- `[NEW] backend/app/agent/tools/cloud/aws_tools.py`
- `[NEW] backend/app/mcp/servers/cloud_server.py`
- `[NEW] backend/tests/agent/test_aws_tools.py`

**Tasks:**
- [ ] Build `S3BucketEnumTool` — discover public/misconfigured S3 buckets
- [ ] Build `IAMAuditTool` — analyze IAM policies for over-permissive roles
- [ ] Build `SecurityGroupAuditTool` — check for overly permissive inbound rules (0.0.0.0/0)
- [ ] Build `LambdaScanner` — check Lambda functions for vulnerable dependencies and env var leaks
- [ ] Build `EC2MetadataTool` — test SSRF to EC2 metadata endpoint (169.254.169.254)
- [ ] Build `CloudTrailAnalyzer` — check for CloudTrail logging gaps
- [ ] Create `CloudMCPServer` (:8011) — wrapper for Prowler/ScoutSuite
- [ ] Write 60+ tests with mocked AWS responses (moto library)

**Deliverables:** 6 AWS tools, 1 cloud MCP server, 60+ tests

---

### Day 20 — Azure & GCP Security Scanners

**Files:**
- `[NEW] backend/app/agent/tools/cloud/azure_tools.py`
- `[NEW] backend/app/agent/tools/cloud/gcp_tools.py`
- `[NEW] backend/tests/agent/test_azure_tools.py`
- `[NEW] backend/tests/agent/test_gcp_tools.py`

**Tasks:**
- [ ] Build `AzureBlobEnumTool` — discover public Azure Blob Storage containers
- [ ] Build `AzureADTool` — enumerate Azure AD users, groups, applications
- [ ] Build `AzureNSGAuditTool` — check Network Security Groups for misconfigurations
- [ ] Build `GCSBucketEnumTool` — discover public/misconfigured GCS buckets
- [ ] Build `GCPIAMTool` — analyze GCP IAM bindings for privilege escalation paths
- [ ] Build `GCPFirewallAuditTool` — check VPC firewall rules
- [ ] Build unified `CloudSummaryTool` — cross-cloud risk summary and comparison
- [ ] Write 60+ tests

**Deliverables:** 7 cloud tools, 60+ tests

---

### Day 21 — Container & Kubernetes Security

**Files:**
- `[NEW] backend/app/agent/tools/cloud/container_tools.py`
- `[NEW] backend/app/agent/tools/cloud/k8s_tools.py`
- `[NEW] backend/tests/agent/test_container_tools.py`

**Tasks:**
- [ ] Build `DockerImageScanTool` — scan Docker images for CVEs (Trivy integration)
- [ ] Build `DockerfileLintTool` — audit Dockerfiles for security best practices
- [ ] Build `K8sAuditTool` — check Kubernetes RBAC, pod security standards, network policies
- [ ] Build `K8sSecretScanTool` — detect secrets mounted in pods, check etcd encryption
- [ ] Build `ContainerEscapeTool` — test container escape vectors (privileged mode, host PID/network)
- [ ] Build `HelmChartAuditTool` — scan Helm charts for security misconfigurations
- [ ] Write 50+ tests

**Deliverables:** 6 container/K8s tools, 50+ tests

---

### Day 22 — OWASP Top 10 & Compliance Mapping Engine

**Files:**
- `[NEW] backend/app/compliance/`
- `[NEW] backend/app/compliance/mapper.py`
- `[NEW] backend/app/compliance/frameworks/owasp_top10.py`
- `[NEW] backend/app/compliance/frameworks/pci_dss.py`
- `[NEW] backend/app/compliance/frameworks/nist_800_53.py`
- `[NEW] backend/app/compliance/frameworks/cis_benchmarks.py`
- `[NEW] backend/app/api/compliance.py`
- `[NEW] backend/tests/test_compliance.py`

**Tasks:**
- [ ] Build `ComplianceMapper` — map findings to compliance framework controls
- [ ] Implement OWASP Top 10 (2021) mapping: A01 Broken Access Control → A10 SSRF
- [ ] Implement PCI-DSS v4.0 mapping: Requirements 1–12
- [ ] Implement NIST 800-53 mapping: AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, RA, SA, SC, SI
- [ ] Implement CIS Benchmarks mapping for common platforms
- [ ] Build compliance gap analysis (tested vs. untested controls)
- [ ] API endpoints: `GET /api/compliance/report/{framework}`, `GET /api/compliance/gaps`
- [ ] Write 50+ tests

**Deliverables:** Compliance engine with 4 frameworks, 50+ tests

---

### Day 23 — SIEM Integration & Event Export

**Files:**
- `[NEW] backend/app/integrations/`
- `[NEW] backend/app/integrations/siem_exporter.py`
- `[NEW] backend/app/integrations/syslog_forwarder.py`
- `[NEW] backend/app/integrations/webhook_manager.py`
- `[NEW] backend/app/api/integrations.py`
- `[NEW] backend/tests/test_integrations.py`

**Tasks:**
- [ ] Build `SIEMExporter` — export findings in CEF, LEEF, and JSON formats
- [ ] Build Splunk integration (HEC — HTTP Event Collector)
- [ ] Build ELK integration (Elasticsearch bulk API)
- [ ] Build `SyslogForwarder` — RFC 5424 syslog output (UDP/TCP/TLS)
- [ ] Build `WebhookManager` — configurable webhooks for scan events (Slack, Teams, Discord, PagerDuty)
- [ ] Build Jira integration — auto-create tickets for findings above severity threshold
- [ ] API endpoints: `POST /api/integrations/configure`, `GET /api/integrations/test`
- [ ] Write 50+ tests

**Deliverables:** SIEM/webhook integration system, 50+ tests

---

### Day 24 — Integration Dashboard & Notification Center (Frontend)

**Files:**
- `[NEW] frontend/app/(dashboard)/integrations/page.tsx`
- `[NEW] frontend/app/(dashboard)/compliance/page.tsx`
- `[NEW] frontend/components/integrations/IntegrationCard.tsx`
- `[NEW] frontend/components/integrations/WebhookBuilder.tsx`
- `[NEW] frontend/components/compliance/ComplianceMatrix.tsx`
- `[NEW] frontend/components/compliance/GapAnalysis.tsx`
- `[NEW] frontend/components/notifications/NotificationCenter.tsx`
- `[NEW] frontend/hooks/useNotifications.ts`

**Tasks:**
- [ ] Build Integrations page — card-based UI for each integration (SIEM, webhook, Jira)
- [ ] Build webhook builder — visual webhook configuration with payload preview
- [ ] Build Compliance dashboard — framework selector, coverage matrix, gap analysis chart
- [ ] Build notification center — in-app notification bell with scan events, completion alerts, approval requests
- [ ] Build notification preferences page (per-event-type channel selection)
- [ ] Real-time notification delivery via WebSocket
- [ ] Write 25+ frontend tests

**Deliverables:** 3 new frontend pages, 7 new components, 25+ tests

---

### Phase 4 Totals

| Metric | Count |
|--------|-------|
| Cloud Security Tools | **19** |
| Compliance Frameworks | 4 |
| Integration Systems | 5 (Splunk, ELK, syslog, webhooks, Jira) |
| MCP Servers Added | 1 (Cloud :8011) |
| New Tests | **295+** |

---

## Phase 5: Premium Frontend & Production Hardening (Days 25–30)

> **Objective:** Deliver a stunning, premium frontend experience and harden everything for production.

---

### Day 25 — Frontend Design System Overhaul

**Files:**
- `[MODIFY] frontend/app/globals.css` (redesign)
- `[MODIFY] frontend/tailwind.config.js` (new design tokens)
- `[NEW] frontend/components/ui/ThemeProvider.tsx`
- `[NEW] frontend/components/ui/AnimatedCard.tsx`
- `[NEW] frontend/components/ui/GlassPanel.tsx`
- `[NEW] frontend/components/ui/Skeleton.tsx`
- `[NEW] frontend/components/ui/Badge.tsx`
- `[NEW] frontend/components/ui/Tabs.tsx`
- `[NEW] frontend/components/ui/Modal.tsx`
- `[NEW] frontend/components/ui/DropdownMenu.tsx`
- `[NEW] frontend/components/ui/DataTable.tsx`
- `[NEW] frontend/components/ui/Charts.tsx`

**Tasks:**
- [ ] Design premium dark-mode-first color palette (cyberpunk/hacker aesthetic):
  - Background: deep navy/charcoal gradients
  - Accents: electric cyan, neon green, warning amber
  - Glass effects: frosted glass panels with backdrop-blur
- [ ] Implement design token system (CSS custom properties for all colors, shadows, borders, radii)
- [ ] Build ThemeProvider with dark/light mode toggle + system preference detection
- [ ] Build AnimatedCard with hover micro-animations (scale, glow, border shimmer)
- [ ] Build GlassPanel for glassmorphism containers
- [ ] Build skeleton loading states for all data components
- [ ] Build reusable DataTable with sorting, filtering, pagination, and row actions
- [ ] Build Chart components (line, bar, pie, donut, area) using Recharts
- [ ] Add smooth page transitions (framer-motion)
- [ ] Write 15+ component tests

**Deliverables:** Complete design system, 12 new UI components, 15+ tests

---

### Day 26 — Dashboard & Scan Interface Redesign

**Files:**
- `[MODIFY] frontend/app/(dashboard)/dashboard/page.tsx` (complete redesign)
- `[NEW] frontend/components/dashboard/StatsGrid.tsx`
- `[NEW] frontend/components/dashboard/ActivityFeed.tsx`
- `[NEW] frontend/components/dashboard/ScanTimeline.tsx`
- `[NEW] frontend/components/dashboard/VulnSeverityChart.tsx`
- `[NEW] frontend/components/dashboard/AttackSurfaceMap.tsx`
- `[MODIFY] frontend/components/projects/` (redesign all project cards/views)

**Tasks:**
- [ ] Build premium dashboard home with:
  - Stats grid (animated counters: total targets, active scans, vulns found, flags captured)
  - Live activity feed (real-time scan events with auto-scroll)
  - Scan timeline (horizontal timeline showing scan phases with duration)
  - Vulnerability severity donut chart (critical/high/medium/low/info)
  - Attack surface map (world map with target geolocations, animated connections)
- [ ] Redesign project cards with progress rings, status badges, and quick-action overlays
- [ ] Add project detail page redesign with tabbed interface (Overview | Findings | Graph | Report | Settings)
- [ ] Implement responsive layouts for tablet and mobile
- [ ] Add keyboard shortcuts for power users (Ctrl+K command palette)
- [ ] Write 15+ tests

**Deliverables:** Premium dashboard, 5 new dashboard widgets, 15+ tests

---

### Day 27 — AI Chat Interface & Graph Visualization Upgrade

**Files:**
- `[MODIFY] frontend/components/chat/` (complete redesign)
- `[NEW] frontend/components/chat/ChatSidebar.tsx`
- `[NEW] frontend/components/chat/MessageBubble.tsx`
- `[NEW] frontend/components/chat/ToolExecutionCard.tsx`
- `[NEW] frontend/components/chat/ApprovalDialog.tsx`
- `[NEW] frontend/components/chat/AgentThinking.tsx`
- `[MODIFY] frontend/components/graph/` (3D graph upgrade)
- `[NEW] frontend/components/graph/GraphControls.tsx`
- `[NEW] frontend/components/graph/NodeDetail.tsx`

**Tasks:**
- [ ] Redesign AI chat interface:
  - Split-pane layout (chat left, context/tools right)
  - Markdown rendering in messages (code blocks, tables, links)
  - Tool execution cards showing running/completed/failed status with collapsible output
  - "Agent thinking" animation (pulsing brain icon with streaming thought text)
  - Approval dialog with risk assessment details and evidence
  - Chat history sidebar with search and session management
- [ ] Upgrade graph visualization:
  - 3D force-directed graph with WebGL rendering (three-forcegraph)
  - Node type color coding with legend
  - Click-to-expand node detail panel
  - Graph filtering by node type, severity, attack phase
  - Animated edge highlighting for attack paths
  - Export graph as PNG/SVG
- [ ] Write 20+ tests

**Deliverables:** Premium AI chat UI, 3D graph visualization, 20+ tests

---

### Day 28 — E2E Testing & Performance Optimization

**Files:**
- `[MODIFY] e2e/` (comprehensive E2E test suite)
- `[NEW] e2e/auth.spec.ts`
- `[NEW] e2e/dashboard.spec.ts`
- `[NEW] e2e/reports.spec.ts`
- `[NEW] e2e/campaigns.spec.ts`
- `[NEW] e2e/chat.spec.ts`
- `[NEW] e2e/graph.spec.ts`
- `[MODIFY] performance/k6-api.js`
- `[NEW] performance/k6-websocket.js`
- `[NEW] performance/k6-concurrent-scans.js`

**Tasks:**
- [ ] Write comprehensive E2E test suite (Playwright):
  - Auth flow (register → login → refresh → logout)
  - Project lifecycle (create → configure → scan → view results)
  - AI chat interaction (send message → receive response → approve tool)
  - Report generation (create → preview → download PDF)
  - Campaign management (create → import targets → launch → monitor → results)
  - Graph visualization (load → interact → filter → export)
- [ ] Performance testing (k6):
  - API load test: 100 concurrent users, p99 < 500ms
  - WebSocket load test: 50 concurrent agent sessions
  - Concurrent scan test: 10 simultaneous scans
  - Database query performance (PostgreSQL + Neo4j)
- [ ] Frontend performance audit:
  - Lighthouse score > 90 (Performance, Accessibility, SEO)
  - Bundle analysis and code splitting optimization
  - Image optimization (WebP, lazy loading)
  - Service worker for offline dashboard access
- [ ] Write 30+ E2E tests, 5 k6 scripts

**Deliverables:** E2E test suite, performance benchmarks, optimization, 30+ tests

---

### Day 29 — Security Hardening & Production Readiness

**Files:**
- `[MODIFY] docker/production/docker-compose.production.yml`
- `[NEW] docker/production/nginx/nginx.conf` (reverse proxy)
- `[NEW] scripts/health-check.sh`
- `[NEW] scripts/backup-databases.sh`
- `[NEW] scripts/rotate-secrets.sh`
- `[MODIFY] .github/workflows/` (update all CI workflows for v2.0)
- `[NEW] backend/tests/security/test_v2_security.py`
- `[MODIFY] docs/SECURITY.md`
- `[MODIFY] docs/OPERATIONS_RUNBOOK.md`

**Tasks:**
- [ ] Add Nginx reverse proxy with:
  - TLS termination (Let's Encrypt auto-renewal)
  - HTTP/2 support
  - Security headers (HSTS, CSP, X-Content-Type-Options)
  - Request size limits (protect against large payload attacks)
  - WebSocket proxy pass
- [ ] Security hardening:
  - Implement API key rotation mechanism
  - Add IP allow-listing for admin endpoints
  - Implement account lockout after failed attempts
  - Add 2FA support (TOTP) for admin accounts
  - Run Bandit + Safety security scan, fix all findings
  - Run Trivy on all Docker images, fix CRITICAL/HIGH CVEs
- [ ] Production readiness:
  - Health check scripts for all services
  - Database backup scripts (PostgreSQL pg_dump, Neo4j export)
  - Secret rotation automation
  - Graceful shutdown handling for all services
  - Multi-instance backend support (horizontal scaling validation)
- [ ] Update CI/CD:
  - Add v2.0 tests to CI pipeline
  - Add performance regression test gate
  - Add container security scan for new images
- [ ] Write 40+ security tests

**Deliverables:** Production-grade deployment, Nginx reverse proxy, security hardening, 40+ tests

---

### Day 30 — Documentation, Migration Guide & v2.0 Release

**Files:**
- `[MODIFY] README.md` (v2.0 update)
- `[NEW] MIGRATION_v1_to_v2.md`
- `[NEW] RELEASE_NOTES_v2.md`
- `[MODIFY] docs/ARCHITECTURE.md` (v2.0 architecture diagrams)
- `[MODIFY] docs/API_REFERENCE.md` (new endpoints)
- `[MODIFY] docs/USER_MANUAL.md` (new features)
- `[NEW] docs/PLUGIN_GUIDE.md`
- `[NEW] docs/CLOUD_SECURITY_GUIDE.md`
- `[NEW] docs/COMPLIANCE_GUIDE.md`
- `[MODIFY] CONTRIBUTING.md`

**Tasks:**
- [ ] Update README with v2.0 feature matrix, architecture diagram, tool inventory (72+ tools)
- [ ] Write v1 → v2 migration guide:
  - Database schema migration script
  - Docker Compose migration (new services: Redis, ChromaDB)
  - Environment variable changes
  - Breaking API changes (if any)
- [ ] Write v2.0 Release Notes with full changelog
- [ ] Update architecture documentation with:
  - Multi-agent orchestration diagram
  - Plugin system architecture
  - Cloud scanning data flow
  - Report generation pipeline
  - Campaign engine architecture
- [ ] Update API reference with all new endpoints (reports, campaigns, findings, compliance, integrations, plugins)
- [ ] Write Plugin Development Guide with examples
- [ ] Write Cloud Security Guide (AWS/Azure/GCP configuration)
- [ ] Write Compliance Guide (OWASP/PCI-DSS/NIST/CIS)
- [ ] Update User Manual with v2.0 workflows
- [ ] Final integration test run — all 2700+ tests pass ✅
- [ ] Tag release: `v2.0.0`

**Deliverables:** Complete documentation update, migration guide, v2.0 release

---

### Phase 5 Totals

| Metric | Count |
|--------|-------|
| Frontend Components (new/redesigned) | **30+** |
| E2E Tests | **30+** |
| Performance Scripts | 5 |
| Security Tests | **40+** |
| Documentation Files | **10+** (new/updated) |
| New Tests | **120+** |

---

## Cumulative v2.0 Stats

| Metric | v1.0 | v2.0 | Delta |
|--------|------|------|-------|
| **Agent Tools** | 37 | **72+** | +35 |
| **MCP Servers** | 8 | **12** | +4 |
| **AutoChain Templates** | 2 | **7** | +5 |
| **Backend Tests** | 1,624 | **3,200+** | +1,576 |
| **Frontend Tests** | 87 | **200+** | +113 |
| **E2E Tests** | ~10 | **40+** | +30 |
| **API Endpoints** | 30 | **55+** | +25 |
| **Docker Services** | 8 | **11** | +3 (Redis, ChromaDB, Nginx) |
| **Neo4j Node Types** | 17 | **20+** | +3 |
| **Frontend Pages** | 5 | **12+** | +7 |
| **Documentation Files** | 19 | **25+** | +6 |
| **Lines of Code (est.)** | 21,000 | **55,000+** | +34,000 |

---

## Day-by-Day Summary Calendar

| Day | Phase | Focus | Key Deliverables |
|-----|-------|-------|------------------|
| **1** | 🔴 Web Arsenal | XSS Detection Engine | 3 tools, 1 MCP, 60+ tests |
| **2** | 🔴 Web Arsenal | CSRF/SSRF/Redirect | 5 tools, 100+ tests |
| **3** | 🔴 Web Arsenal | IDOR & Auth Bypass | 6 tools, 80+ tests |
| **4** | 🔴 Web Arsenal | JWT/OAuth Token Attacks | 6 tools, 70+ tests |
| **5** | 🔴 Web Arsenal | API Security (REST/GraphQL) | 8 tools, 1 MCP, 90+ tests |
| **6** | 🔴 Web Arsenal | Advanced Injections | 7 tools, 1 MCP, 100+ tests |
| **7** | 🟣 AI Brain | Multi-Agent Orchestration | 4 agents, 80+ tests |
| **8** | 🟣 AI Brain | RAG Knowledge Base | RAG engine, ChromaDB, 60+ tests |
| **9** | 🟣 AI Brain | Attack Planning & CoT | Planner, backtracking, 70+ tests |
| **10** | 🟣 AI Brain | Plugin Architecture | Plugin system, 2 examples, 50+ tests |
| **11** | 🟣 AI Brain | Redis Infrastructure | Job queue, cache, rate limiter, 60+ tests |
| **12** | 🟣 AI Brain | mTLS for MCP | Cert management, encrypted channels, 40+ tests |
| **13** | 🟢 Reports | PDF/HTML Report Engine | 3 templates, PDF gen, 60+ tests |
| **14** | 🟢 Reports | Report Builder UI | Full report UI, 20+ tests |
| **15** | 🟢 Campaigns | Campaign Engine | Multi-target engine, 70+ tests |
| **16** | 🟢 Campaigns | Campaign Dashboard UI | Campaign wizard & dashboard, 20+ tests |
| **17** | 🟢 Campaigns | AutoChain v2 Templates | 5 new templates, 80+ tests |
| **18** | 🟢 Campaigns | Findings Management | Finding triage system, 60+ tests |
| **19** | 🔵 Cloud | AWS Security Scanner | 6 AWS tools, 1 MCP, 60+ tests |
| **20** | 🔵 Cloud | Azure & GCP Scanners | 7 tools, 60+ tests |
| **21** | 🔵 Cloud | Container & K8s Security | 6 tools, 50+ tests |
| **22** | 🔵 Cloud | Compliance Mapping | 4 frameworks, 50+ tests |
| **23** | 🔵 Cloud | SIEM Integration | 5 integrations, 50+ tests |
| **24** | 🔵 Cloud | Integration & Notification UI | 3 pages, 7 components, 25+ tests |
| **25** | 🟡 Premium UX | Design System Overhaul | 12 UI components, 15+ tests |
| **26** | 🟡 Premium UX | Dashboard Redesign | 5 dashboard widgets, 15+ tests |
| **27** | 🟡 Premium UX | Chat & Graph Upgrade | Premium chat, 3D graph, 20+ tests |
| **28** | 🟡 Production | E2E Testing & Performance | 30+ E2E, 5 k6 scripts |
| **29** | 🟡 Production | Security Hardening | Nginx, 2FA, hardening, 40+ tests |
| **30** | 🟡 Production | Docs & v2.0 Release | Migration guide, release notes |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM API rate limits during multi-agent | High | Implement backoff, fallback to local models |
| ChromaDB memory pressure | Medium | Limit embedding scope, add resource limits |
| Plugin sandboxing escape | Critical | Use Docker-based sandboxing, restrict syscalls |
| mTLS cert rotation failures | High | Automated monitoring + alerting |
| Breaking API changes affect CI | Medium | Feature flags, v1 compat layer |
| Frontend bundle size explosion | Medium | Code splitting, tree shaking, lazy imports |

---

## Success Criteria

1. ✅ Complete OWASP Top 10 coverage — automated tests for each category
2. ✅ Professional PDF reports — executive + technical + compliance
3. ✅ Multi-target campaigns — scan 10+ targets in parallel
4. ✅ Cloud security — AWS/Azure/GCP misconfiguration detection
5. ✅ 3,200+ backend tests passing
6. ✅ E2E test suite covering all critical user flows
7. ✅ Performance: p99 API latency < 500ms under 100 concurrent users
8. ✅ Lighthouse score > 90 for all frontend pages
9. ✅ Zero CRITICAL/HIGH vulnerabilities in container scans
10. ✅ Plugin system with 2+ community-installable examples

---

*UniVex v2.0 — "Supernova" — The Full-Stack Web Pentesting Agent*  
*Designed by BitR1FT with AI-powered development velocity*
