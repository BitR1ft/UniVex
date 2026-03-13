# UniVex — Year 1 Gap Coverage Plan
Professional, end-to-end plan to fully cover identified gaps, deliver production-grade capabilities, and meet/exceed Year 1 goals. No strict time constraints; sequence is designed for safe, incremental, testable progress.

## 0) Overview
This plan focuses on:
- Completing database persistence with PostgreSQL + Prisma (replacing in-memory stores).
- Integrating professional reconnaissance and vulnerability tooling (Naabu, Nuclei, Katana, GAU, Kiterunner, Wappalyzer, Shodan, Interactsh).
- Solidifying Neo4j graph schema, ingestion pipelines, and querying.
- Building MCP tool servers and AI agent with secure approval flows and streaming.
- Delivering a polished Next.js frontend with 180+ parameter forms and interactive 2D/3D graph visualization.
- Establishing observability, security hardening, and CI/CD required for a production system.
- Achieving and maintaining robust test coverage (80%+ unit/integration, E2E where applicable).

## 1) Goals & Success Criteria
- Replace all in-memory state with PostgreSQL via Prisma.
- Integrate external tools and unify outputs with robust orchestration, error handling, deduplication, and rate-limiting.
- Propagate all data to Neo4j with complete nodes/relationships and documented schema.
- Implement agent/mcp tool servers with strong safety controls (approval/stop/resume) and auditable operations.
- Frontend delivers full UX: auth, project CRUD, multi-step forms (180+ params), real-time progress (SSE/WS), and interactive 2D/3D graph.
- Observability: logs, metrics, traces, dashboards, alerts.
- Security posture: secrets, RBAC, audit logs, rate limits, dependency hygiene.
- CI/CD pipelines and release processes in place.
- Documentation comprehensive and up-to-date.

---

## Phase A — Database Integration & Persistence (PostgreSQL + Prisma)
Replace in-memory dicts for users/projects with persistent storage. Update health and services to reflect DB status.

### Deliverables
- Prisma models finalized (User, Project, task tables for recon/scan execution).
- Repository/service layer in FastAPI.
- Migrations and seed scripts.
- Health endpoints reflect DB status; startup includes readiness checks.
- Backup/restore strategy (pg_dump, scheduled backups).

### Tasks
- [x] Finalize Prisma schema for Users, Projects, Tasks (recon, port-scan, http-probe), Sessions.
- [x] Implement DB repositories (users_repo, projects_repo, tasks_repo) with async Prisma client.
- [x] Refactor auth endpoints to use DB (register/login/me/refresh).
- [x] Refactor project CRUD to use DB.
- [x] Store background job metadata/results in DB (replace in-memory task dicts).
- [x] Add DB readiness/health in `/health` and startup event.
- [x] Create migration scripts and Dev/Stage/Prod configs for DATABASE_URL.
- [x] Create seed script (admin user, sample project).
- [x] Implement daily automated backups with retention (7/30 days).
- [x] Update docs: DB schema, migrations, seeding, backups.

### Acceptance Criteria
- Auth/Projects data persists across restarts.
- Health endpoint shows API=operational, DB=healthy.
- Background tasks visible in DB with status/result.
- All related unit/integration tests passing; coverage ≥80% for DB-backed endpoints.

---

## Phase B — External Recon Tools Integration
Professional integrations to match plan requirements and unify results.

### Tools & Integrations
- Port scanning: Naabu
- Vuln scanning: Nuclei (+ template updates, severity/tag filtering)
- Web crawling & URLs: Katana, GAU (multiple providers)
- API brute-forcing: Kiterunner
- Tech detection: Wappalyzer
- Passive intel: Shodan
- Blind vulns: Interactsh
- HTTP response fingerprinting: httpx (JARM, headers), mmh3 favicon hashing

### Deliverables
- Orchestrators per tool with common input/output schemas.
- Deduplication and merging logic for recon outputs.
- Rate limiting, retries, backoff; parallel execution where safe.
- Containerized tools with version pinning and auto-update routines where applicable.
- Configurable “active vs passive” modes.

### Tasks
- [x] Define canonical schemas for ReconResult, Endpoint, Technology, Finding.
- [x] Integrate Naabu: target validation, concurrent scanning, safe defaults.
- [x] Integrate Nuclei: severity/tag filters, output normalization, auto template updates.
- [x] Integrate Katana (JS rendering opt-in), GAU (4 providers), Kiterunner.
- [x] Integrate Wappalyzer and httpx (TLS, JARM, security headers).
- [x] Integrate Shodan (API), Interactsh for OOB detections.
- [x] Build merging/deduplication pipeline and confidence scoring.
- [x] Add structured logs and metrics for each tool.
- [x] Update API endpoints to kick off tool runs and fetch status/results.
- [x] Document usage, configuration, limits, and safety.

### Acceptance Criteria
- Each tool produces normalized outputs; orchestrators run concurrently without resource contention.
- Endpoints return consistent results; reproducible runs with fixed seeds/configs.
- Performance baseline documented (targets/min throughput, resource caps).

---

## Phase C — Vulnerability Enrichment & Mapping
Enhance findings with CVE, CWE, CAPEC, and exploit workflows.

### Deliverables
- CVE enrichment via NVD/Vulners.
- CWE/CAPEC mapping to vulnerabilities and technologies.
- Severity normalization; risk scoring (CVSS).
- Interactsh integration wired for blind vulns.
- Auto-update routines for vuln databases.

### Tasks
- [x] Implement enrichment service: NVD/Vulners lookup; cache results (Postgres).
- [x] Map vulnerabilities -> CWE -> CAPEC; attach to Neo4j nodes.
- [x] Normalize severity and compute risk scores.
- [x] Add scheduled job to refresh DBs (templates, CWE/CAPEC).
- [x] Extend REST endpoints for filtered queries (severity, tag, exploitability).

### Acceptance Criteria
- Vulnerabilities display enriched metadata in API/Neo4j.
- Graph queries return CWE/CAPEC chains.
- Scheduled data updates succeed with audit logs.

---

## Phase D — Graph Database Schema & Ingestion (Neo4j)
Complete graph model with nodes/relationships, constraints, ingestion, and queries.

### Deliverables
- 17+ node types, 20+ relationship types (Domains, Endpoints, Ports, Technologies, Vulnerabilities, Parameters, Payloads, Exploits, CAPEC, CWE, CVE).
- Constraints/indexes, multi-tenancy isolation by user/project.
- Ingestion pipelines per phase (domain discovery, port scan, http probe, resource enum, vuln scan, mitre).
- Query endpoints (attack surface, technologies with CVEs, vulnerabilities).
- Graph stats endpoints.

### Tasks
- [x] Finalize node/relationship schema and indexes.
- [x] Implement ingestion functions to populate full chains (Domain→Endpoint→Port→Tech→Vuln→CVE/CWE/CAPEC).
- [x] Add tenancy guards to queries and clear-project operations.
- [x] Build graph validation scripts (node counts, missing links).
- [x] Update graph docs and diagrams.

### Acceptance Criteria
- End-to-end ingestion produces expected nodes/edges for sample data.
- Graph queries return correct results with tenant isolation.
- Stats endpoints reflect accurate counts; constraints enforced.

---

## Phase E — AI Agent Foundation & Streaming
Agent with LangGraph, tools, memory, safety, realtime streaming.

### Deliverables
- ReAct-style LangGraph agent; MemorySaver; tool interface framework.
- SSE/WS streaming to frontend with progress events.
- Approval workflow for dangerous ops; stop/resume; session/thread mgmt.
- Logging and audit trails.

### Tasks
- [x] Define agent graph (phases, tools), system prompts per phase.
- [x] Implement tool adapters: recon, port scan, http probe, Nuclei, query_graph, web_search.
- [x] Add approval gating; stop/resume; session persistence.
- [x] Implement SSE/WS streaming channels and backpressure handling.
- [x] Document agent usage and safety model.

### Acceptance Criteria
- Agent can orchestrate end-to-end flow safely with approvals.
- Streaming responsive under load; no dropped events.
- Operations are auditable; dangerous actions require explicit approval.

---

## Phase F — MCP Tool Servers
Build MCP-compliant tool servers to expose capabilities.

### Deliverables
- MCP protocol implemented.
- 5+ tool servers: naabu_tool, nuclei_tool, curl_tool, metasploit_tool, query_graph, web_search (Tavily).
- Phase restrictions enforce safe usage.
- Tests and docs.

### Tasks
- [x] Implement MCP server skeleton (spec-compliant).
- [x] Wire tools with request/response contracts; error handling.
- [x] Add phase restriction and RBAC checks.
- [x] Unit/integration tests; load tests for concurrency.
- [x] Documentation and usage examples.

### Acceptance Criteria
- MCP servers respond per spec; tools operate correctly.
- Security controls validated; tests passing with coverage ≥80%.

---

## Phase G — Frontend (Next.js) UI
Professional UX with forms, graph visualization, and realtime updates.

### Deliverables
- Auth UI (register/login/refresh/me).
- Project CRUD UI.
- Multi-step project form handling 180+ parameters with validation and accessibility.
- 2D/3D graph visualization (react-force-graph / three-force-graph) with interactivity.
- Real-time updates via SSE/WS; node inspector; filtering; export.
- Responsive design; UI docs.

### Tasks
- [x] Auth pages and state mgmt (tokens, refresh).
- [x] Project list/detail/create/update/delete pages.
- [x] Multi-step form design, validation, error handling; autosave drafts.
- [x] Graph viewer with interactions (hover/click/filter/search), export PNG/JSON/GEXF.
- [x] SSE/WS clients for progress and agent streaming; toast/notification system.
- [x] Accessibility pass; responsive breakpoints; dark mode.
- [x] E2E tests (Playwright/Cypress) for critical flows.

### Acceptance Criteria
- Full UI flows work reliably; real-time updates visible.
- Graph interactions smooth at target node counts.
- Accessibility checks pass (WCAG AA); E2E tests green.

---

## Phase H — Observability & Security
Complete stack for operating safely.

### Deliverables
- Structured logging (JSON), log correlation IDs.
- Metrics: Prometheus; dashboards in Grafana.
- Tracing: OpenTelemetry (FastAPI + background tasks).
- Alerts on errors, high latency, job failures.
- Security: secrets mgmt, RBAC, audit logs, rate limiting, CORS/WAF, dependency scanning (SCA).

### Tasks
- [x] Add logging middleware; correlation IDs; request/response sampling.
- [x] Export metrics (latency, error rates, queue lengths, job durations).
- [x] Instrument traces across API and orchestrators.
- [x] Configure alerts (Slack/Email) for SLO violations.
- [x] Implement RBAC roles; audit log for sensitive operations.
- [x] Rate limiting per user/project; safe defaults for tool usage.
- [x] Set up Dependabot/Snyk; regular SCA runs; pinned versions.

### Acceptance Criteria
- Dashboards cover all critical components; alerts fire on SLO breaches.
- Security controls validated; audits retained per policy.

---

## Phase I — Testing & QA
Achieve high confidence.

### Deliverables
- Unit tests for repositories/services/utilities.
- Integration tests for APIs and ingestion.
- E2E tests for UI.
- Performance/load tests; chaos tests for resilience.
- Coverage ≥80% backend; ≥70% frontend.

### Tasks
- [x] Expand unit/integration test suites; cover DB and orchestrators.
- [x] Add contract tests for MCP servers and agent tools.
- [x] E2E scenarios for auth, projects, recon runs, graph viewing.
- [x] Performance tests: throughput/resource caps; regression baselines.
- [x] Chaos/resilience tests (fail neo4j/postgres/tool; verify graceful degradation).

### Acceptance Criteria
- Coverage thresholds met; CI gating passes.
- Performance and resilience baseline documented.

---

## Phase J — CI/CD & Releases
Automate pipelines and releases.

### Deliverables
- GitHub Actions workflows: lint, test, build, security scan.
- Docker multi-stage builds; pinned versions.
- Staging + production deploy flows; blue/green/canary options.
- Release notes and versioning policy; migration playbooks.

### Tasks
- [x] Create workflows (backend, frontend, infra).
- [x] Build/push images to registry; SBOM artifact.
- [x] Environment matrix (dev/stage/prod) with secrets mgmt.
- [x] Release automation (tags, notes); rollback procedures.

### Acceptance Criteria
- Pipelines reliable; deployments reproducible; artifacts traceable.
- Releases documented; rollbacks tested.

---

## Phase K — Documentation
Make it usable for devs and users.

### Deliverables
- API reference (OpenAPI), module docs.
- Runbooks (ops, backup/restore, migrations).
- Architecture diagrams (data flow, graph schema, agent/mcp topology).
- Threat model and security posture.
- User guides (frontend flows), developer guides (contributing, style).

### Tasks
- [x] Update OpenAPI; generate and publish docs.
- [x] Author runbooks and migration procedures.
- [x] Create diagrams; keep versioned in repo.
- [x] Write threat model; track risks and mitigations.
- [x] UI documentation for forms/graphs; a11y guidance.

### Acceptance Criteria
- New contributors can onboard within a day.
- Users can run full workflows with docs only.

---

## Risk & Mitigation
- Tool API limits and rate-limiting → configurable throttles and caching.
- Security risks of active scanning/exploitation → strict approval flows, RBAC, audit logs, default-safe configs.
- Data volume in Neo4j → indexing, batching ingestion, resource caps, archiving strategies.
- Vendor dependency changes → version pinning, SBOM, SCA alerts, scheduled updates.

## Dependencies
- Credentials for Shodan, Interactsh, Tavily, OpenAI/Anthropic.
- Infrastructure: Docker, Postgres, Neo4j; Prometheus/Grafana stack.
- Frontend libs: react-force-graph/three, SSE/WS client utilities.

---

## Definition of Done (Global)
- All previously “in-memory” services persisting to Postgres.
- Required external tools integrated with unified schemas and safe defaults.
- Graph DB ingestion complete with documented schema and constraints.
- Agent + MCP servers operating with approvals, streaming, and audit logs.
- Frontend realizes all listed UX deliverables; responsive and accessible.
- Observability and security controls in place; alerts configured.
- CI/CD pipelines green; coverage thresholds met; reproducible releases.
- Documentation comprehensive and current.

---

## Tracking Checklists (Roll-up)
- [x] Database persistence complete (Auth/Projects/Tasks).
- [x] Recon tool integrations (Naabu/Nuclei/Katana/GAU/Kiterunner/Wappalyzer/Shodan/Interactsh).
- [x] Enrichment (CVE/CWE/CAPEC) and scheduled updates.
- [x] Neo4j schema/ingestion; isolation and queries validated.
- [x] Agent (LangGraph) with streaming and approvals.
- [x] MCP tool servers implemented and tested.
- [x] Frontend UI (auth, CRUD, 180+ params, 2D/3D graph, real-time, responsive).
- [x] Observability (logs/metrics/traces/dashboards/alerts).
- [x] Security hardening (RBAC, audit, rate limits, SCA).
- [x] Testing (unit/integration/E2E/perf/chaos); coverage targets met.
- [x] CI/CD and release processes; rollback tested.
- [x] Documentation (API, runbooks, architecture, threat model, user/dev guides).
