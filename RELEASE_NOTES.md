# UniVex v1.0.0 Release Notes

**Release Date:** March 14, 2026  
**Status:** v1.0.0 — First Stable Release  
**Codename:** "Genesis"

---

## 🚀 Overview

UniVex v1.0.0 is the **first stable release** of the AI-powered, fully-autonomous penetration
testing platform. Given a single target IP or domain, UniVex autonomously executes the complete
offensive security kill chain — from reconnaissance through exploitation to flag capture — without
manual intervention.

This release represents 12 months of development and comprehensive security hardening.

---

## ✨ Features

### Autonomous AI Agent
- **LangGraph ReAct agent** with typed `AgentState` and multi-step tool-call loops
- **Multi-LLM provider support** — GPT-4 and Claude via pluggable adapters
- **Human-in-the-loop approval** for destructive operations (exploitation, privilege escalation)
- **Real-time streaming** of tool execution output with operator stop/resume controls
- **Live guidance injection** — redirect the agent mid-run without restarting

### Reconnaissance Pipeline (5 Phases)
- **Domain Discovery** — WHOIS, Certificate Transparency logs, DNS enumeration
- **Port Scanning** — Naabu and Nmap integration with configurable timing
- **HTTP Probing** — httpx, Wappalyzer tech detection, TLS inspection with cipher classification
- **Resource Enumeration** — Katana crawler, GAU URL harvesting, Kiterunner API discovery
- **Vulnerability Scanning** — Nuclei templates, CVE enrichment, MITRE ATT&CK mapping

### MCP Tool Servers (8 Servers)
| Server | Port | Capability |
|--------|------|-----------|
| Naabu | 8000 | Port scanning |
| Curl | 8001 | HTTP requests |
| Nuclei | 8002 | Vulnerability scanning |
| Metasploit | 8003 | Exploitation framework |
| ffuf | 8004 | Web fuzzing (directories, files, parameters) |
| SQLMap | 8005 | SQL injection testing |
| Hash Cracker | 8006 | Password hash cracking |
| Nikto | 8007 | Web server scanning |

### AutoChain Pipeline
- Declarative YAML-based automated pentest pipeline
- 42 HTB templates for Linux/Windows/AD scenarios
- Session upgrade pipeline (shell → meterpreter) with automatic retry
- Flag MD5 verification before submission
- REST API: `POST /api/autochain/run`, `GET /api/autochain/status/{id}`, `DELETE /api/autochain/{id}`

### Attack Graph Database
- **Neo4j** graph database with 17+ node types and 20+ relationship types
- Visual attack graph rendering in the browser via react-force-graph
- Full CRUD graph queries for hosts, services, vulnerabilities, and attack paths

### Web Interface
- **Next.js 14** frontend with TailwindCSS
- Real-time AI chat interface with WebSocket communication
- Interactive attack graph visualization
- Project management dashboard
- Authentication with JWT access/refresh tokens

### 37+ Agent Tools
- Port scanning, web fuzzing, SQL injection, vulnerability scanning
- Metasploit exploit execution, session management, privilege escalation
- SSH/FTP/SNMP enumeration, credential reuse pipeline
- Active Directory attacks (Kerbrute, CrackMapExec, Impacket suite)
- ML-powered intent classification (keyword, ML, LLM, and hybrid modes)

---

## 🛡️ Security

### Authentication & Authorisation
- **JWT access/refresh token pair** with configurable expiry (HS256)
- **Role-based access control (RBAC):** VIEWER → OPERATOR → ADMIN hierarchy
- **Audit logging:** structured JSON logs with actor, target, correlation ID, IP, and timestamp
- **Brute-force protection:** sliding window rate limiter with HTTP 429 and `Retry-After` header
- **Secrets validation on startup:** minimum length enforcement without leaking secret values

### Phase-Based Tool Gating
| Phase | Access Level |
|-------|-------------|
| `recon` | Naabu, Nuclei, Curl, GAU, Katana, Kiterunner, Graph Query |
| `scan` | All recon tools + web-app scanners |
| `exploit` | All scan tools + Metasploit (requires human approval) |
| `post` | All tools |

### Infrastructure Hardening
- **Database ports** bound to `127.0.0.1` only (not exposed to network)
- **Required passwords** — Docker Compose fails if secrets are not set in `.env`
- **Resource limits** on all Docker services (CPU and memory)
- **Network segmentation** — 4 isolated Docker networks (db, backend, frontend, tools)
- **Security headers** — CSP, X-Frame-Options, Referrer-Policy via middleware
- **CORS** restricted to configured allowed origins
- **Parameterised queries** throughout (Prisma ORM, no raw SQL interpolation)

### CI/CD Security
- **6 GitHub Actions workflows** — CI, Security Scan, Docker Build, Deploy, Blue-Green, Release
- **Enforcing linters** — ruff and mypy run without bypass
- **Dependency scanning** — pip-audit and npm audit fail the build on vulnerabilities
- **SAST** — Bandit and CodeQL analysis on every PR
- **Container scanning** — Trivy fails on CRITICAL/HIGH vulnerabilities
- **Secret scanning** — Gitleaks on every push
- **License compliance** — automated GPL-3.0 detection

---

## 📋 Test Results

```
Platform: Python 3.11+, pytest
Backend:  1624 passed ✅, 7 skipped ⏭️
Frontend: Jest + React Testing Library
E2E:      Playwright (Chromium, Firefox, WebKit)
```

---

## ⚙️ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/BitR1ft/UnderProgress.git
cd UnderProgress

# 2. Configure environment
cp .env.example .env
# Edit .env — set all required passwords and API keys

# 3. Start services
docker compose --profile dev up -d

# 4. Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API docs: http://localhost:8000/docs
```

### Required Environment Variables

```env
SECRET_KEY=<min 32 chars, cryptographically random>
POSTGRES_PASSWORD=<min 16 chars>
NEO4J_PASSWORD=<min 16 chars>
GRAFANA_PASSWORD=<min 16 chars>
OPENAI_API_KEY=sk-...          # or ANTHROPIC_API_KEY
```

Generate strong secrets:
```bash
openssl rand -hex 32    # For SECRET_KEY
openssl rand -base64 24 # For database passwords
```

---

## 📦 Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend API | FastAPI | 0.109+ |
| AI Agent | LangGraph + LangChain | 0.2+ / 0.3+ |
| Frontend | Next.js + React | 14 / 18 |
| Relational DB | PostgreSQL (Prisma ORM) | 16 |
| Graph DB | Neo4j | 5.15 |
| Styling | TailwindCSS | 3.4 |
| Monitoring | Prometheus + Grafana | 2.51 / 10.4 |
| Containers | Docker Compose | 3.8 |
| Security Tools | Kali Linux container | 2024.1 |

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [README](README.md) | Project overview and setup guide |
| [User Manual](docs/USER_MANUAL.md) | Step-by-step usage guide |
| [API Reference](docs/API_REFERENCE.md) | Full endpoint documentation |
| [Architecture](docs/ARCHITECTURE.md) | System design and data flows |
| [Installation Guide](docs/INSTALLATION_GUIDE.md) | Detailed setup instructions |
| [Quick Start](docs/QUICKSTART.md) | 5-minute start guide |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Contributing and extending |
| [MCP Guide](docs/MCP_GUIDE.md) | MCP server protocol docs |
| [Security](docs/SECURITY.md) | Security controls and disclosure |
| [Threat Model](docs/THREAT_MODEL.md) | STRIDE threat analysis |
| [Testing Guide](docs/TESTING_GUIDE.md) | Test strategy and coverage |

---

## 🗺️ Roadmap

| Version | Focus |
|---------|-------|
| v1.1 | PDF/HTML report generation, `htb_hard` template |
| v1.2 | Multi-target campaigns, SIEM integration |
| v2.0 | Cloud security (AWS/Azure/GCP), mTLS for MCP, Redis rate limiter |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. All contributions require
passing tests and CodeQL scans.

---

*UniVex v1.0.0 — Universal Vulnerability Execution*  
*Author: BitR1FT | Open-Source*
