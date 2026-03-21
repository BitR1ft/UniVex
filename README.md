# UniVex v2.0 — "Supernova"

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0.0-cyan?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-green?style=flat-square&logo=python">
  <img alt="Node" src="https://img.shields.io/badge/node-20+-green?style=flat-square&logo=nodedotjs">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.109-teal?style=flat-square&logo=fastapi">
  <img alt="Next.js" src="https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=nextdotjs">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker">
  <img alt="Tests" src="https://img.shields.io/badge/tests-3200%2B-brightgreen?style=flat-square">
  <img alt="Tools" src="https://img.shields.io/badge/agent_tools-72%2B-orange?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square">
</p>

> **AI-powered, fully-autonomous penetration testing platform — v2.0 "Supernova"**  
> **BitR1FT** — Founder & Lead Developer  
> One target → full kill chain: recon → exploitation → post-exploitation → compliance reporting.  
> 72+ agent tools · Multi-agent orchestration · Cloud security · Compliance mapping · Cyberpunk UI

---

## Table of Contents

1. [What Is UniVex?](#1-what-is-univex)
2. [Key Features](#2-key-features)
3. [System Requirements](#3-system-requirements)
4. [Quick Start — 5 Minutes with Docker](#4-quick-start--5-minutes-with-docker)
5. [Detailed Installation](#5-detailed-installation)
   - [5.1 Development Setup](#51-development-setup)
   - [5.2 Production Deployment](#52-production-deployment)
6. [Environment Variables Reference](#6-environment-variables-reference)
7. [Using the Application](#7-using-the-application)
   - [7.1 Web Interface](#71-web-interface)
   - [7.2 AI Agent Chat](#72-ai-agent-chat)
   - [7.3 AutoChain Automated Pipeline](#73-autochain-automated-pipeline)
   - [7.4 HTB Attack Templates](#74-htb-attack-templates)
8. [Full API Command Reference](#8-full-api-command-reference)
9. [Visual Architecture](#9-visual-architecture)
   - [9.1 High-Level System Diagram](#91-high-level-system-diagram)
   - [9.2 Network Segmentation](#92-network-segmentation)
   - [9.3 AI Agent Data Flow](#93-ai-agent-data-flow)
   - [9.4 AutoChain Pipeline Flow](#94-autochain-pipeline-flow)
10. [Build Architecture](#10-build-architecture)
    - [10.1 Docker Services](#101-docker-services)
    - [10.2 MCP Tool Servers](#102-mcp-tool-servers)
    - [10.3 Agent Tools Inventory](#103-agent-tools-inventory)
    - [10.4 Database Design](#104-database-design)
11. [Testing](#11-testing)
12. [CI/CD Pipeline](#12-cicd-pipeline)
13. [Observability & Monitoring](#13-observability--monitoring)
14. [Security & Ethics](#14-security--ethics)
15. [Project Status & Roadmap](#15-project-status--roadmap)
16. [Documentation Index](#16-documentation-index)
17. [Contributing](#17-contributing)
18. [Author & Acknowledgments](#18-author--acknowledgments)

---

## 1. What Is UniVex?

UniVex is a **full-stack, agentic penetration testing platform** — a professional open-source project developed by BitR1FT. Given a single target IP or domain, the platform autonomously executes the complete offensive security kill chain without manual intervention:

```
Target IP / Domain
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 1 · RECONNAISSANCE                               │
│  Subdomain enum · Port scan · HTTP probe · Tech detect  │
├─────────────────────────────────────────────────────────┤
│  Phase 2 · VULNERABILITY DISCOVERY                      │
│  Nuclei templates · CVE enrichment · MITRE mapping      │
├─────────────────────────────────────────────────────────┤
│  Phase 3 · EXPLOITATION                                 │
│  Metasploit auto-configure · Approval gate · Execute    │
├─────────────────────────────────────────────────────────┤
│  Phase 3.5 · SESSION UPGRADE                            │
│  Shell → Meterpreter · TTY stabilisation                │
├─────────────────────────────────────────────────────────┤
│  Phase 4 · POST-EXPLOITATION                            │
│  LinPEAS/WinPEAS · Hash crack · Credential reuse        │
├─────────────────────────────────────────────────────────┤
│  Phase 5 · FLAG CAPTURE                                 │
│  user.txt + root.txt · MD5 verification · Neo4j storage │
└─────────────────────────────────────────────────────────┘
       │
       ▼
Structured Report + Attack Graph (Neo4j)
```

The AI agent uses the **ReAct (Reasoning + Acting)** pattern powered by GPT-4 / Claude and communicates with 8 MCP (Model Context Protocol) tool servers running inside an isolated Kali Linux container.

---

## 2. Key Features

### 🎯 v2.0 Feature Matrix

| Category | Features | Status |
|----------|----------|--------|
| **Agent Tools** | 72+ tools across web, cloud, network, AD, containers | ✅ v2.0 |
| **Multi-Agent** | Planner, Recon, Exploit, Validator, Reporting agents | ✅ v2.0 |
| **RAG Knowledge Base** | ChromaDB vector store with CVE/OWASP embeddings | ✅ v2.0 |
| **Plugin System** | Python plugins with Docker sandbox isolation | ✅ v2.0 |
| **Cloud Security** | AWS/Azure/GCP misconfiguration detection (19 tools) | ✅ v2.0 |
| **Compliance** | OWASP Top 10, PCI-DSS 4.0, NIST 800-53, CIS v8 | ✅ v2.0 |
| **PDF Reports** | Executive, Technical, Compliance with charts | ✅ v2.0 |
| **Campaigns** | Multi-target parallel scanning (up to 10 targets) | ✅ v2.0 |
| **Findings** | Triage, deduplication, Jira/ServiceNow integration | ✅ v2.0 |
| **SIEM** | Splunk, Elastic, Sentinel, Datadog, Sumo Logic | ✅ v2.0 |
| **2FA / TOTP** | RFC 6238 TOTP with backup codes | ✅ v2.0 |
| **mTLS** | Mutual TLS between backend and all MCP servers | ✅ v2.0 |
| **Redis** | Job queue, distributed cache, rate limiting | ✅ v2.0 |
| **Nginx** | TLS 1.3, HTTP/2, security headers, WebSocket | ✅ v2.0 |
| **E2E Tests** | 54+ Playwright E2E tests | ✅ v2.0 |
| **Backend Tests** | 3,200+ pytest tests | ✅ v2.0 |
| **Cyberpunk UI** | Dark mode design system, animations, PWA | ✅ v2.0 |

---

### 🤖 AI Agent (LangGraph ReAct)
- GPT-4 / Claude-3 powered reasoning and planning
- Multi-turn conversation with project context memory
- Human-in-the-loop approval gates for dangerous operations
- Configurable `AUTO_APPROVE_RISK_LEVEL` (none → low → medium → high → critical)
- ML-based intent classification (Keyword / ML / LLM / Hybrid modes)
- Real-time streaming via Server-Sent Events (SSE) and WebSocket

### 🔍 Reconnaissance Pipeline (5 Phases)
- **Phase 1** — Domain Discovery: subfinder, amass, python-whois
- **Phase 2** — Port Scanning: Naabu (fast), Nmap (deep, service detection)
- **Phase 3** — HTTP Probing: httpx, technology fingerprinting
- **Phase 4** — Resource Enumeration: endpoint discovery, path brute-force
- **Phase 5** — CVE Enrichment: NVD API, MITRE ATT&CK / CWE / CAPEC mapping

### ⚔️ Exploitation Engine
- **Metasploit** auto-module selection and exploitation
- **ffuf** directory / file / parameter fuzzing (MCP port 8004)
- **SQLMap** injection detection and data extraction (MCP port 8005)
- **Nikto** web server scanner (MCP port 8007)
- **SearchSploit** offline exploit database search
- **WPScan** WordPress vulnerability scanner + CMS chain detection
- Retry logic with configurable back-off per phase

### 🏴 Post-Exploitation & Flag Capture
- **LinPEAS / WinPEAS** automated privilege escalation enumeration
- **Hash Cracker** (John the Ripper / Hashcat) with MCP server (port 8006)
- **Credential Reuse Pipeline** — extracted hashes → SSH / SMB / WinRM
- **SSH key extraction**, SSH login, anonymous FTP, SNMP enumeration
- **Reverse shell** generation (bash, Python, PowerShell, Perl, nc)
- **FlagCaptureTool** — reads standard CTF flag paths, MD5 verification

### 🪟 Active Directory Attack Suite
| Tool | Capability |
|------|-----------|
| `KerbrouteTool` | Username enumeration via Kerberos |
| `Enum4LinuxTool` | SMB / LDAP host enumeration |
| `ASREPRoastTool` | AS-REP roasting (Impacket GetNPUsers) |
| `KerberoastTool` | Kerberoasting (Impacket GetUserSPNs) |
| `PassTheHashTool` | PtH via CrackMapExec / Impacket |
| `LDAPEnumTool` | LDAP anonymous / authenticated dump |
| `CrackMapExecTool` | SMB spray, WinRM login, secrets dump |

### 🗂️ Attack Surface Graph (Neo4j)
- 17+ node types: Target, Domain, Subdomain, IP, Port, Technology, CVE, Exploit…
- 20+ relationship types: HAS_SUBDOMAIN, RUNS_SERVICE, HAS_VULNERABILITY…
- Interactive 2D/3D force-graph visualization in the browser
- Real-time updates as scans progress

### 📊 Observability Stack
- **Prometheus** metrics on `/metrics` (custom and FastAPI)
- **Grafana** dashboards (port 3001)
- **OpenTelemetry** distributed tracing (OTLP export)
- Structured JSON logging with request ID correlation

---

## 3. System Requirements

### Hardware

| Environment | CPU | RAM | Disk |
|-------------|-----|-----|------|
| Development | 2 cores | 8 GB | 20 GB |
| Staging | 4 cores | 16 GB | 50 GB |
| Production | 8+ cores | 32 GB | 200 GB+ |

### Software

| Dependency | Minimum | Notes |
|------------|---------|-------|
| Docker Engine | 24.0 | Required |
| Docker Compose | v2.20 | Compose V2 (plugin, not legacy standalone) |
| Python | 3.11 | Backend local dev only |
| Node.js | 20 LTS | Frontend local dev only |
| Git | 2.40+ | Any recent version |

### Required API Keys

**At least one LLM provider is required.** Free-tier options are available:

| Key | Purpose | Free? | Where to get |
|-----|---------|-------|-------------|
| `OPENAI_API_KEY` | GPT-4o AI agent | No | [platform.openai.com](https://platform.openai.com) |
| `ANTHROPIC_API_KEY` | Claude fallback | No | [console.anthropic.com](https://console.anthropic.com) |
| `GOOGLE_API_KEY` | Gemini (free tier) | ✅ Free | [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| `GROQ_API_KEY` | Llama 3.3 70B (fast, free) | ✅ Free | [console.groq.com](https://console.groq.com/keys) |
| `OPENROUTER_API_KEY` | 100+ models via one API | Varies | [openrouter.ai](https://openrouter.ai/keys) |
| `TAVILY_API_KEY` | OSINT web search (optional) | Partial | [app.tavily.com](https://app.tavily.com) |
| `NVD_API_KEY` | CVE enrichment (optional) | ✅ Free | [nvd.nist.gov](https://nvd.nist.gov/developers) |

---

## 4. Quick Start — 5 Minutes with Docker

```bash
# 1. Clone the repository
git clone https://github.com/BitR1ft/UnderProgress.git univex
cd univex

# 2. Create your environment file
cp .env.example .env

# 3. Set required secrets in .env  (minimum required values)
#    SECRET_KEY  → run: openssl rand -hex 32
#    At least one LLM provider: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY
#    GRAFANA_PASSWORD
#    All *_PASSWORD variables (change defaults)

# 4. Start the full stack
docker compose up -d

# 5. Wait ~60 s for services to initialise, then open:
#    Web app:     http://localhost:3000
#    API docs:    http://localhost:8000/docs
#    Neo4j:       http://localhost:7474
#    Grafana:     http://localhost:3001
```

Check everything is healthy:
```bash
docker compose ps                          # all services should be "healthy"
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected output:
```json
{
  "status": "healthy",
  "services": {
    "api": "operational",
    "database": "healthy",
    "neo4j": "healthy"
  }
}
```

---

## 5. Detailed Installation

### 5.1 Development Setup

**Clone and configure:**
```bash
git clone https://github.com/BitR1ft/UnderProgress.git univex
cd univex
cp .env.example .env
# edit .env — see Section 6 for full reference
```

**Start databases only (for local dev):**
```bash
docker compose up -d postgres neo4j
```

**Backend (Terminal 1):**
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate         # Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt   # dev extras (pytest, etc.)

# Apply database schema
prisma generate
prisma db push

# Start the API server with hot-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is available at http://localhost:8000  
Interactive docs: http://localhost:8000/docs

**Frontend (Terminal 2):**
```bash
cd frontend
npm install
npm run dev
```

The UI is available at http://localhost:3000

**Kali tool containers (Terminal 3, needed for real scans):**
```bash
# Start the Kali Linux tool sandbox and recon container
docker compose --profile tools up -d kali-tools recon-container

# Verify MCP servers are running inside the Kali container
docker exec univex-kali-tools python /app/mcp/servers/naabu_server.py &
# (All 8 MCP servers are started via start-mcp-servers.sh in the container)
```

---

### 5.2 Production Deployment

```bash
# 1. Generate strong secrets
export SECRET_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -base64 24)
export NEO4J_PASSWORD=$(openssl rand -base64 24)
export GRAFANA_PASSWORD=$(openssl rand -base64 24)

# 2. Create .env.production (never commit this file)
cp .env.example .env.production
# Edit .env.production and fill in all values

# 3. Build and deploy with the production compose file
export IMAGE_TAG=v1.0.0
docker compose \
  -f docker/production/docker-compose.production.yml \
  --env-file .env.production \
  up -d --build

# 4. Run database migrations
docker exec univex-prod-backend prisma migrate deploy

# 5. Verify readiness probe
curl -s http://localhost:8000/readiness | python3 -m json.tool
```

**Blue/Green deployment** (zero-downtime):
```bash
# See .github/workflows/blue-green.yml for the full automated flow
# Manual blue/green swap:
docker compose -f docker/production/docker-compose.production.yml \
  --env-file .env.production \
  up -d --no-deps backend      # rolling restart of backend replicas
```

---

## 6. Environment Variables Reference

Copy `.env.example` to `.env` and set the following variables:

### Core Application

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | `development`, `staging`, or `production` |
| `SECRET_KEY` | *(must change)* | JWT signing key — run `openssl rand -hex 32` |
| `DEBUG` | `false` | Enable debug mode (never use in production) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FORMAT` | `json` | `json` or `text` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://...` | Full PostgreSQL connection URL |
| `POSTGRES_USER` | `univex` | PostgreSQL username |
| `POSTGRES_PASSWORD` | *(must change)* | PostgreSQL password |
| `POSTGRES_DB` | `univex` | Database name |
| `NEO4J_URI` | `bolt://neo4j:7687` | Neo4j Bolt connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | *(must change)* | Neo4j password |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |

### AI Providers

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | One of these | OpenAI API key for GPT-4 |
| `ANTHROPIC_API_KEY` | One of these | Anthropic API key for Claude |
| `GOOGLE_API_KEY` | One of these | Google API key for Gemini (free tier available) |
| `GROQ_API_KEY` | One of these | Groq API key for Llama 3.3 70B (free tier) |
| `OPENROUTER_API_KEY` | One of these | OpenRouter API key (access 100+ models) |
| `OPENAI_MODEL` | No | Default: `gpt-4o` |
| `ANTHROPIC_MODEL` | No | Default: `claude-3-5-sonnet-20241022` |
| `GOOGLE_MODEL` | No | Default: `gemini-1.5-flash` |
| `GROQ_MODEL` | No | Default: `llama-3.3-70b-versatile` |
| `OPENROUTER_MODEL` | No | Default: `anthropic/claude-3.5-sonnet` |
| `LANGCHAIN_API_KEY` | No | LangSmith tracing (optional) |

### AutoChain Pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_APPROVE_RISK_LEVEL` | `none` | Auto-approve threshold: `none` / `low` / `medium` / `high` / `critical`. Use `critical` only in isolated lab environments. |
| `NAABU_MCP_URL` | `http://kali-tools:8000` | Naabu MCP server URL |
| `NUCLEI_MCP_URL` | `http://kali-tools:8002` | Nuclei MCP server URL |
| `MSF_MCP_URL` | `http://kali-tools:8003` | Metasploit MCP server URL |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAFANA_USER` | `admin` | Grafana admin username |
| `GRAFANA_PASSWORD` | *(must change)* | Grafana admin password |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | OpenTelemetry OTLP endpoint |

### Security Tools

| Variable | Description |
|----------|-------------|
| `NUCLEI_RATE_LIMIT` | Nuclei requests/second (default: 150) |
| `NMAP_TIMING_TEMPLATE` | Nmap -T template (default: 4) |
| `METASPLOIT_HOST` | MSF host (default: metasploit) |
| `NVD_API_KEY` | NVD API key for CVE data |
| `HTB_API_KEY` | HackTheBox API key (optional) |

---

## 7. Using the Application

### 7.1 Web Interface

1. **Open** http://localhost:3000
2. **Register** a new account or log in
3. **Create a Project**: click "New Project", enter target IP/domain and description
4. **Start Scan**: click "Start Scan" on the project card
5. **Watch Live Progress**: the scan panel streams real-time tool output
6. **Explore the Graph**: open the "Attack Graph" tab to view Neo4j visualization
7. **Chat with the Agent**: open the "AI Agent" tab for interactive Q&A

### 7.2 AI Agent Chat

The agent understands natural language instructions:

```
You: "What open ports did you find on 10.10.10.3?"
You: "Run a Nuclei scan on port 80"
You: "Search for exploits for Apache 2.4.49"
You: "Try to exploit CVE-2021-41773 — I approve"
You: "Run LinPEAS on the active session"
You: "Crack the hash 5f4dcc3b5aa765d61d8327deb882cf99"
```

For operations classified as `high` or `critical` risk, an approval modal
appears in the browser. Approve or reject before the agent proceeds.

### 7.3 AutoChain Automated Pipeline

AutoChain is a **fully deterministic, non-LLM** pipeline that runs the entire
pentest sequence using direct MCP tool calls. It is faster and more predictable
than the free-form AI agent.

**Via API (curl):**

```bash
# Start an automated chain against a target
curl -s -X POST http://localhost:8000/api/autochain/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "10.10.10.3",
    "auto_approve_risk_level": "high",
    "project_id": "optional-project-uuid"
  }' | python3 -m json.tool

# Response includes chain_id:
# { "chain_id": "abc123...", "status": "running", ... }

# Poll status
curl -s http://localhost:8000/api/autochain/abc123 | python3 -m json.tool

# Stream real-time progress via SSE
curl -N http://localhost:8000/api/autochain/abc123/stream

# Get captured flags
curl -s http://localhost:8000/api/autochain/abc123/flags | python3 -m json.tool

# Get all completed steps
curl -s http://localhost:8000/api/autochain/abc123/steps | python3 -m json.tool

# Stop a running chain
curl -X DELETE http://localhost:8000/api/autochain/abc123
```

### 7.4 HTB Attack Templates

Two pre-built templates are included for HackTheBox machines:

```bash
# List available templates
curl -s http://localhost:8000/api/autochain/templates | python3 -m json.tool

# Launch a chain from the htb_easy template
curl -s -X POST http://localhost:8000/api/autochain/start/template \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "template_id": "htb_easy",
    "target": "10.10.10.3"
  }' | python3 -m json.tool

# Launch with htb_medium template
curl -s -X POST http://localhost:8000/api/autochain/start/template \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "template_id": "htb_medium",
    "target": "10.10.10.4"
  }' | python3 -m json.tool
```

**From Python:**

```python
import asyncio
from backend.app.autochain import AutoChain

async def run():
    chain = AutoChain.from_template("htb_easy", target="10.10.10.3")
    async for event in chain.stream():
        print(event)

asyncio.run(run())
```

**Template phases (htb_easy):**

| Phase | Tool | Action |
|-------|------|--------|
| recon | naabu | TCP port scan — top 1000 |
| recon | ffuf | Directory/file brute-force |
| vuln_discovery | nuclei | CVE + web templates |
| exploitation | metasploit | Auto-configure + run exploit |
| post_exploitation | metasploit | Session upgrade → Meterpreter |
| post_exploitation | metasploit | sysinfo, whoami, ifconfig |
| post_exploitation | flag_capture | /root/root.txt, ~/user.txt, MD5 verify |

**htb_medium** adds: LDAP enumeration, SQLMap testing, CMS detection, lateral movement scan, retry logic.

---

## 8. Full API Command Reference

### Authentication

```bash
BASE=http://localhost:8000

# Register
curl -s -X POST $BASE/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@lab.local","password":"SecureP@ss1"}' \
  | python3 -m json.tool

# Login — save token
TOKEN=$(curl -s -X POST $BASE/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecureP@ss1"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"

# Refresh token
curl -s -X POST $BASE/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}" | python3 -m json.tool

# Get current user
curl -s $BASE/api/auth/me -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Change password
curl -s -X PUT $BASE/api/auth/me/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"SecureP@ss1","new_password":"NewP@ss2"}' \
  | python3 -m json.tool

# Logout
curl -s -X POST $BASE/api/auth/logout -H "Authorization: Bearer $TOKEN"
```

### Projects

```bash
# Create a project
curl -s -X POST $BASE/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HTB Lame",
    "target": "10.10.10.3",
    "description": "HackTheBox Lame machine",
    "enable_recon": true,
    "enable_exploitation": false
  }' | python3 -m json.tool

# List all projects
curl -s "$BASE/api/projects" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Get project by ID
curl -s "$BASE/api/projects/$PROJECT_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Update project
curl -s -X PUT "$BASE/api/projects/$PROJECT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description": "Updated description"}' | python3 -m json.tool

# Start scan
curl -s -X POST "$BASE/api/projects/$PROJECT_ID/start" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Stop scan
curl -s -X POST "$BASE/api/projects/$PROJECT_ID/stop" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# List project tasks
curl -s "$BASE/api/projects/$PROJECT_ID/tasks" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Delete project
curl -s -X DELETE "$BASE/api/projects/$PROJECT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### AI Agent

```bash
# Get agent status
curl -s $BASE/api/agent/status | python3 -m json.tool

# Chat with the agent
curl -s -X POST $BASE/api/agent/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What vulnerabilities did you find on the target?",
    "project_id": "'$PROJECT_ID'",
    "stream": false
  }' | python3 -m json.tool

# Approve a pending high-risk operation
curl -s -X POST $BASE/api/agent/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation_id": "'$OP_ID'", "approved": true}' | python3 -m json.tool

# Stop the agent
curl -s -X POST $BASE/api/agent/stop \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "'$SESSION_ID'"}' | python3 -m json.tool

# Resume a stopped agent
curl -s -X POST $BASE/api/agent/resume \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "'$SESSION_ID'"}' | python3 -m json.tool

# WebSocket agent stream (using wscat)
# npm install -g wscat
wscat -c "ws://localhost:8000/api/agent/ws/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Graph Database

```bash
# Query attack graph (Cypher)
curl -s -X POST $BASE/api/graph/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "MATCH (t:Target)-[:HAS_VULNERABILITY]->(v:CVE) RETURN t, v LIMIT 20"}' \
  | python3 -m json.tool

# Get graph for a project
curl -s "$BASE/api/graph/projects/$PROJECT_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Reconnaissance

```bash
# Start recon on a target
curl -s -X POST $BASE/api/recon/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "project_id": "'$PROJECT_ID'"}' \
  | python3 -m json.tool

# Get recon results
curl -s "$BASE/api/recon/$PROJECT_ID/results" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### CVE & CWE Enrichment

```bash
# Enrich a CVE
curl -s "$BASE/api/cve/enrich/CVE-2021-41773" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Get CWE details
curl -s "$BASE/api/enrichment/cwe/CWE-89" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Health & Metrics

```bash
# Basic health
curl -s $BASE/health | python3 -m json.tool

# Kubernetes-style readiness probe
curl -s $BASE/readiness | python3 -m json.tool

# Prometheus metrics
curl -s $BASE/metrics

# SSE live event stream
curl -N "$BASE/api/sse/events?project_id=$PROJECT_ID"
```

---

## 9. Visual Architecture

### 9.1 High-Level System Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                           USER BROWSER                                  │
│           Next.js 14 (TypeScript · Tailwind CSS · shadcn/ui)            │
│  Dashboard │ AI Chat │ Attack Graph │ Project Wizard │ Scan Progress    │
└────────────────────────────┬───────────────────────────────────────────┘
                             │  HTTP / WebSocket / SSE
                             │  (ws:// or wss:// in production)
┌────────────────────────────▼───────────────────────────────────────────┐
│                        FASTAPI BACKEND  :8000                           │
│                                                                          │
│   /api/auth          JWT auth, registration, token refresh               │
│   /api/projects      CRUD, start/stop scan, task list                    │
│   /api/agent         Chat, approve, stop, resume, WebSocket              │
│   /api/autochain     Start, status, flags, steps, SSE stream             │
│   /api/recon         Recon pipeline, results                             │
│   /api/graph         Cypher queries, project graph                       │
│   /api/cve           CVE enrichment, CWE/CAPEC lookup                    │
│   /metrics           Prometheus endpoint                                 │
│   /health  /readiness  Health probes                                     │
│                                                                          │
│   Middleware: JWT auth · WAF (SQLi/XSS/path-traversal) · Rate limiter   │
│   Async architecture · Prisma ORM · OpenTelemetry tracing                │
└────────┬───────────────────────┬──────────────────────┬─────────────────┘
         │                       │                      │
┌────────▼──────┐    ┌───────────▼──────────┐  ┌───────▼──────────────────┐
│  PostgreSQL   │    │       Neo4j 5.15      │  │    AI AGENT LAYER        │
│  :5432        │    │   :7474 (HTTP)        │  │                          │
│               │    │   :7687 (Bolt)        │  │  LangGraph ReAct Engine  │
│  Users        │    │                       │  │  GPT-4 / Claude-3        │
│  Projects     │    │  17+ Node types       │  │  IntentClassifier        │
│  Tasks        │    │  20+ Relationships    │  │  ToolRegistry (37+ tools)│
│  Scan results │    │  APOC plugin          │  │  37 BaseTool impls       │
│  Auth tokens  │    │  Cypher queries       │  │  Approval gate           │
└───────────────┘    └───────────────────────┘  └──────────┬───────────────┘
                                                            │  JSON-RPC 2.0 (MCP)
              ┌─────────────────────────────────────────────▼──────────────┐
              │                  KALI LINUX CONTAINER                       │
              │               (Isolated Tools Network)                      │
              │                                                              │
              │  MCP Server          Port   Security Tool                   │
              │  ─────────────────   ────   ───────────────────────────     │
              │  NaabuServer         8000   Naabu (fast port scanner)       │
              │  CurlServer          8001   curl (HTTP requests)            │
              │  NucleiServer        8002   Nuclei (vuln templates)         │
              │  MetasploitServer    8003   Metasploit Framework            │
              │  FfufServer          8004   ffuf (web fuzzing)              │
              │  SQLMapServer        8005   SQLMap (SQL injection)          │
              │  HashCrackerServer   8006   John / Hashcat                  │
              │  NiktoServer         8007   Nikto (web scanner)             │
              │                                                              │
              └──────────────────────────────────────────────────────────── ┘
              ┌──────────────────────────────────────────────────────────── ┐
              │               OBSERVABILITY STACK                           │
              │   Prometheus :9090  ←  FastAPI /metrics                    │
              │   Grafana    :3001  ←  Prometheus data source              │
              │   OpenTelemetry     →  OTLP endpoint (configurable)        │
              └──────────────────────────────────────────────────────────── ┘
```

### 9.2 Network Segmentation

```
Docker Networks (4 isolated segments)
══════════════════════════════════════════════════════════

  db-network  172.20.1.0/24  [INTERNAL — no host access]
  ┌────────────────────────────────────────────────────┐
  │  postgres ◄───────────────────────► neo4j          │
  │     ▲                                   ▲          │
  │     └──────────── backend ──────────────┘          │
  └────────────────────────────────────────────────────┘

  backend-network  172.20.2.0/24
  ┌────────────────────────────────────────────────────┐
  │  backend ◄──────────────────► prometheus           │
  └────────────────────────────────────────────────────┘

  frontend-network  172.20.3.0/24
  ┌────────────────────────────────────────────────────┐
  │  frontend ◄──────────────────► backend             │
  └────────────────────────────────────────────────────┘

  tools-network  172.20.4.0/24  [ISOLATED]
  ┌────────────────────────────────────────────────────┐
  │  kali-tools ◄────────────────► recon-container     │
  │       ▲                                            │
  │       └──────────── backend ───────────────────────┤
  └────────────────────────────────────────────────────┘
```

### 9.3 AI Agent Data Flow

```
User message → POST /api/agent/chat
                  │
                  ▼
          AgentSession load / create
                  │
                  ▼
       Build context (project + scan history + chat memory)
                  │
                  ▼
       IntentClassifier (Keyword / ML / LLM / Hybrid)
          ├─ web_app_attack  → suggest ffuf / sqlmap / nikto
          ├─ exploit         → suggest metasploit / searchsploit
          ├─ ad_attack       → suggest kerbrute / impacket
          └─ post_exploit    → suggest linpeas / hash_cracker
                  │
                  ▼
       LLM (GPT-4 / Claude) generates response + optional tool call
                  │
         ┌────────┴────────────────────┐
         │                             │
    No tool call                   Tool call
         │                             │
    Stream text               Check risk level
    to user (SSE)                     │
                         ┌────────────┴────────────┐
                         │                         │
                   Risk ≤ threshold           Risk > threshold
                 (AUTO_APPROVE)              (needs approval)
                         │                         │
                  Execute tool              Send approval_required
                  via MCP JSON-RPC         event to browser
                         │                         │
                  Stream result            User approves/rejects
                  + reasoning                       │
                         │                    (if approved)
                         └────────────────► Execute tool
                                                   │
                                            Stream result
```

### 9.4 AutoChain Pipeline Flow

```
POST /api/autochain/start
  target="10.10.10.3", auto_approve_risk_level="high"
             │
             ▼
    Create ChainResult + UUID
    Spawn background asyncio task
             │
             ▼
  ┌─────── Phase 1: RECON ──────────────────────────────────┐
  │  naabu port scan → top 1000 TCP                         │
  │  ↳ ffuf dir/file fuzz (if HTTP port found)              │
  │  ↳ nmap service/version detection                       │
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ┌─────── Phase 2: VULNERABILITY DISCOVERY ────────────────┐
  │  Nuclei templates (cve, sqli, xss, rce, lfi, ssrf)      │
  │  NVD CVE lookup for discovered service versions         │
  │  MITRE ATT&CK / CWE / CAPEC enrichment                  │
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ┌─────── Phase 3: EXPLOITATION ───────────────────────────┐
  │  ReconToExploitMapper ranks CVE candidates              │
  │  For each candidate (max_attempts=3, backoff=5s):       │
  │    ├─ Select Metasploit module                          │
  │    ├─ Configure RHOSTS, LPORT, PAYLOAD                  │
  │    ├─ Check risk vs. AUTO_APPROVE_RISK_LEVEL            │
  │    └─ Execute via MCP → MetasploitServer                │
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ┌─────── Phase 3.5: SESSION UPGRADE ──────────────────────┐
  │  post/multi/manage/shell_to_meterpreter                 │
  │  Fall-back: python3 -c 'import pty; pty.spawn("/bin/bash")'│
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ┌─────── Phase 4: POST-EXPLOITATION ──────────────────────┐
  │  sysinfo · getuid · id · whoami · hostname · ifconfig   │
  │  LinPEAS (Linux) / WinPEAS (Windows)                    │
  │  Hash extraction → Hash Cracker MCP                     │
  │  Credential reuse → SSH / SMB / WinRM                   │
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ┌─────── Phase 5: FLAG CAPTURE ───────────────────────────┐
  │  Read /root/root.txt, ~/user.txt, C:\...\root.txt       │
  │  Verify MD5 (hex32 flags)                               │
  │  Store flag nodes in Neo4j                              │
  └─────────────────────────────────────────────────────────┘
             │
             ▼
  ChainResult.status = COMPLETE
  GET /api/autochain/{id}/flags  →  flags with md5 field
```

Each phase streams `ChainStep` events via SSE on
`GET /api/autochain/{chain_id}/stream`.

---

## 10. Build Architecture

### 10.1 Docker Services

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| `frontend` | `./frontend/Dockerfile` | **3000** | Next.js web UI |
| `backend` | `./backend/Dockerfile` | **8000** | FastAPI REST + WS API |
| `postgres` | `postgres:16-alpine` | 5432 | Relational data store |
| `neo4j` | `neo4j:5.15-community` | 7474, 7687 | Attack surface graph |
| `kali-tools` | `./docker/kali/Dockerfile` | 8000-8007 | MCP tool servers |
| `recon-container` | `./docker/recon/Dockerfile` | — | Reconnaissance tools |
| `prometheus` | `prom/prometheus:v2.51.0` | 9090 | Metrics collection |
| `grafana` | `grafana/grafana:10.4.0` | **3001** | Metrics dashboards |

Resource limits (development):

| Service | CPU Limit | Memory Limit |
|---------|-----------|-------------|
| `backend` | 2 cores | 2 GB |
| `frontend` | 1 core | 1 GB |
| `postgres` | 2 cores | 2 GB |
| `neo4j` | 2 cores | 3 GB |
| `kali-tools` | 4 cores | 4 GB |
| `recon-container` | 2 cores | 2 GB |

### 10.2 MCP Tool Servers

All security tools communicate through the **Model Context Protocol (MCP)**
— a JSON-RPC 2.0 based interface that separates tool execution from agent
reasoning. Each server runs inside the isolated Kali container:

```
backend/app/mcp/
├── base_server.py        MCPClient + MCPServer base classes
├── protocol.py           JSON-RPC 2.0 message schemas
├── phase_control.py      Phase-based tool enable/disable
└── servers/
    ├── naabu_server.py   :8000  Fast TCP port scanner
    ├── curl_server.py    :8001  HTTP requests / probing
    ├── nuclei_server.py  :8002  Template-based vuln scanner
    ├── metasploit_server.py :8003  Metasploit Framework RPC
    ├── ffuf_server.py    :8004  Web fuzzing (dirs/files/params)
    ├── sqlmap_server.py  :8005  SQL injection testing
    ├── cracker_server.py :8006  Hash cracking (John/Hashcat)
    ├── nikto_server.py   :8007  Web server vulnerability scan
    ├── graph_server.py   :8004* Query Neo4j attack graph
    └── web_search_server.py    Tavily OSINT web search
```

### 10.3 Agent Tools Inventory

All 37+ tools extend `BaseTool` and are registered in `ToolRegistry`:

**Recon / Probe Tools**
| Tool | File | Capability |
|------|------|-----------|
| `DomainDiscoveryTool` | tool_adapters.py | Subdomain enumeration |
| `PortScanTool` | tool_adapters.py | TCP/UDP port scanning |
| `HttpProbeTool` | tool_adapters.py | HTTP service detection |
| `TechDetectionTool` | tool_adapters.py | Web technology fingerprinting |
| `EndpointEnumerationTool` | tool_adapters.py | URL/endpoint discovery |
| `NucleiTemplateSelectTool` | tool_adapters.py | Nuclei template selection |
| `NucleiScanTool` | tool_adapters.py | Nuclei vulnerability scan |
| `AttackSurfaceQueryTool` | tool_adapters.py | Query Neo4j attack graph |
| `VulnerabilityLookupTool` | tool_adapters.py | CVE/NVD lookup |
| `NaabuTool` | mcp_tools.py | Naabu via MCP |
| `CurlTool` | mcp_tools.py | HTTP requests via MCP |
| `NucleiTool` | mcp_tools.py | Nuclei via MCP |

**Web Application Attack Tools**
| Tool | File | Capability |
|------|------|-----------|
| `FfufFuzzDirsTool` | ffuf_tool.py | Directory brute-force |
| `FfufFuzzFilesTool` | ffuf_tool.py | File brute-force |
| `FfufFuzzParamsTool` | ffuf_tool.py | Parameter fuzzing |
| `WPScanTool` | cms_tools.py | WordPress scanning |
| `NiktoAgentTool` | cms_tools.py | Nikto web scanner |
| `SearchSploitTool` | searchsploit_tool.py | ExploitDB search |

**Exploitation Tools**
| Tool | File | Capability |
|------|------|-----------|
| `MetasploitTool` | mcp_tools.py | Metasploit via MCP |
| `ExploitExecuteTool` | exploitation_tools.py | Run exploit module |
| `BruteForceTool` | exploitation_tools.py | Credential brute-force |
| `SessionManagerTool` | exploitation_tools.py | Manage sessions |

**Post-Exploitation Tools**
| Tool | File | Capability |
|------|------|-----------|
| `LinPEASTool` | post_exploitation_extended.py | Linux priv-esc enum |
| `WinPEASTool` | post_exploitation_extended.py | Windows priv-esc enum |
| `HashCrackTool` | post_exploitation_extended.py | Hash cracking |
| `CredentialReuseTool` | post_exploitation_extended.py | Credential spraying |
| `FlagCaptureTool` | post_exploitation_extended.py | CTF flag capture + MD5 |

**Network Service Tools**
| Tool | File | Capability |
|------|------|-----------|
| `SSHLoginTool` | network_service_tools.py | SSH authentication |
| `SSHKeyExtractTool` | network_service_tools.py | SSH private key extraction |
| `ReverseShellTool` | network_service_tools.py | Reverse shell generation |
| `SNMPTool` | network_service_tools.py | SNMP enumeration |
| `AnonymousFTPTool` | network_service_tools.py | Anonymous FTP access |

**Active Directory Tools**
| Tool | File | Capability |
|------|------|-----------|
| `KerbrouteTool` | active_directory_tools.py | Username enumeration |
| `Enum4LinuxTool` | active_directory_tools.py | SMB/LDAP enumeration |
| `ASREPRoastTool` | active_directory_tools.py | AS-REP roasting |
| `KerberoastTool` | active_directory_tools.py | Kerberoasting |
| `PassTheHashTool` | active_directory_tools.py | Pass-the-Hash |
| `LDAPEnumTool` | active_directory_tools.py | LDAP enumeration |
| `CrackMapExecTool` | active_directory_tools.py | CrackMapExec |

**Utility Tools**
| Tool | File | Capability |
|------|------|-----------|
| `QueryGraphTool` | query_graph_tool.py | Direct Neo4j query |
| `WebSearchTool` | web_search_tool.py | Tavily OSINT search |
| `CalculatorTool` | calculator_tool.py | Safe expression eval |
| `EchoTool` | echo_tool.py | Debug / testing |

### 10.4 Database Design

**PostgreSQL (Prisma schema)**

| Table | Purpose |
|-------|---------|
| `User` | Authentication, profiles, roles |
| `Project` | Pentest engagements, target, status |
| `Task` | Individual scan tasks per project |
| `ScanResult` | Raw tool output, parsed findings |
| `RefreshToken` | JWT refresh token storage + revocation |

**Neo4j (Attack Graph)**

| Node Type | Properties | Example |
|-----------|-----------|---------|
| `Target` | ip, domain, os | `10.10.10.3` |
| `Domain` | name, registrar | `example.com` |
| `Subdomain` | name, ip | `dev.example.com` |
| `IPAddress` | value, asn, country | `1.2.3.4` |
| `Port` | number, protocol, state | `443/tcp open` |
| `Technology` | name, version | `Apache 2.4.49` |
| `CVE` | id, score, vector | `CVE-2021-41773` |
| `CWE` | id, name | `CWE-22 Path Traversal` |
| `CAPEC` | id, name | `CAPEC-126 Path Traversal` |
| `Exploit` | source, edb_id | `exploits/multi/http/…` |
| `Session` | type, user, os | `meterpreter/x64` |
| `Flag` | value, md5, path | `d3f4...a1b2 /root/root.txt` |
| `Credential` | username, hash, type | `Administrator:NTLM:…` |

---

## 11. Testing

### Backend Tests

```bash
cd backend

# Run the full test suite
pytest

# Run with coverage report
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/agent/test_week11_htb_templates.py -v

# Run a specific test
pytest tests/agent/test_autochain.py::TestAutoChainOrchestrator::test_from_template -v

# Fast run — exclude integration tests
pytest -m "not integration" -x

# Show output (don't capture)
pytest -s -v tests/test_week6_vuln_scanning.py
```

Test organisation:

| File | Tests | What it covers |
|------|-------|----------------|
| `test_auth.py` | 18 | JWT auth, registration, token refresh |
| `test_services.py` | 24 | Project / task CRUD |
| `test_repositories.py` | 19 | Database repository layer |
| `test_week3_api.py` | 14 | REST API endpoints |
| `test_week4_framework.py` | 16 | AI agent framework |
| `test_week5_port_scanning.py` | 21 | Naabu/Nmap tools |
| `test_week6_vuln_scanning.py` | 23 | Nuclei tool |
| `test_week7_url_discovery.py` | 18 | ffuf + endpoint enum |
| `test_week8_tech_detection.py` | 22 | Technology fingerprint |
| `test_week9_cve_enrichment.py` | 25 | CVE / NVD enrichment |
| `test_week10_cwe_capec.py` | 28 | CWE/CAPEC mapping |
| `test_week25_security.py` | 31 | Security middleware |
| `test_week26_contracts.py` | 27 | API contract tests |
| `tests/agent/test_autochain.py` | 106 | AutoChain orchestrator |
| `tests/agent/test_week11_htb_templates.py` | 42 | HTB templates + MD5 flags |
| … | … | (17 additional test files) |

**Total: 892+ backend test cases**

### Frontend Tests

```bash
cd frontend

# Run all tests
npm test

# Watch mode
npm test -- --watch

# Coverage
npm run test:coverage

# Specific test file
npm test -- __tests__/hooks/useSSE.test.ts
```

Frontend tests cover:

| Area | Tests |
|------|-------|
| Authentication (login, register, protected routes) | 14 |
| Hooks: useSSE, useWebSocket, useGraph | 21 |
| Hooks: useProjects, useFormAutosave, useMediaQuery | 16 |
| Lib: utils, validations | 23 |
| Components: ApprovalModal, ChatInput | 13 |

**Total: 87 frontend test cases**

### End-to-End Tests (Playwright)

```bash
# Run E2E tests (requires running stack)
npx playwright test

# Run specific spec
npx playwright test e2e/recon.spec.ts

# Open interactive UI
npx playwright test --ui
```

### Performance Tests (k6)

```bash
# Install k6: https://k6.io/docs/get-started/installation/
k6 run performance/k6-api.js \
  -e BASE_URL=http://localhost:8000 \
  -e TOKEN=$TOKEN
```

---

## 12. CI/CD Pipeline

GitHub Actions workflows (`.github/workflows/`):

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `ci.yml` | push/PR to main | Backend lint (flake8) + pytest; Frontend lint + jest; Integration tests |
| `docker-build.yml` | push to main | Build + push Docker images to registry |
| `deploy.yml` | Tag push `v*.*.*` | Deploy to staging then production |
| `blue-green.yml` | Manual / tag | Zero-downtime blue/green deployment |
| `release.yml` | Tag push `v*.*.*` | Create GitHub Release with changelog |
| `security.yml` | Schedule + PR | Bandit SAST, Trivy container scan, Dependabot |

**Branch strategy:**

```
main         ─── protected, requires CI pass + review
develop      ─── integration branch
feature/*    ─── feature branches (PR to develop)
release/*    ─── release preparation (PR to main)
hotfix/*     ─── critical fixes (PR to main + develop)
```

---

## 13. Observability & Monitoring

### Prometheus Metrics (`:9090`)

Custom metrics exposed on `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `autopentest_scans_total` | Counter | Total scans launched |
| `autopentest_scan_duration_seconds` | Histogram | Per-phase scan duration |
| `autopentest_vulnerabilities_found` | Gauge | Vulnerabilities found per project |
| `autopentest_exploits_attempted` | Counter | Exploit attempts (labelled by risk) |
| `autopentest_flags_captured_total` | Counter | CTF flags captured |
| `autopentest_agent_tool_calls_total` | Counter | Tool calls per tool name |
| `http_requests_total` | Counter | HTTP request rate |
| `http_request_duration_seconds` | Histogram | Request latency |

### Grafana Dashboards (`:3001`)

Login: `admin` / `$GRAFANA_PASSWORD`

Pre-configured dashboards:
- **UniVex Overview** — scan rate, tool call rate, flags
- **FastAPI Performance** — latency, error rate, throughput
- **Container Resources** — CPU, memory, network per service
- **Database Health** — PostgreSQL connections, Neo4j page cache

### OpenTelemetry Tracing

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to send traces to Jaeger, Tempo, or any
OTLP-compatible backend:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317 \
OTEL_EXPORTER_OTLP_INSECURE=true \
docker compose up -d backend
```

---

## 14. Security & Ethics

### ⚠️ Authorised Use Only

This tool is designed exclusively for **authorised penetration testing** of
systems you own or have explicit written permission to test.  Unauthorised use
is illegal in virtually every jurisdiction (Computer Fraud and Abuse Act,
Computer Misuse Act, etc.).

### Built-in Safety Controls

| Control | Description |
|---------|-------------|
| **Scope enforcement** | Agent will not target IPs outside the defined project scope |
| **Approval gates** | Operations above `AUTO_APPROVE_RISK_LEVEL` pause for human confirmation |
| **Audit logging** | All tool calls and API requests are logged with user ID and timestamp |
| **JWT authentication** | Every API request requires a valid signed token |
| **Rate limiting** | Sliding window rate limiter (60 req/min, 1000 req/hr per user) |
| **WAF middleware** | Detects and blocks SQL injection, XSS, path traversal in API inputs |
| **Network isolation** | Security tools run in a network-isolated Docker container |
| **No outbound by default** | Tools network has no direct internet access |

### Responsible Disclosure

If you find a security vulnerability in this project, please report it via the
GitHub Security Advisory tab rather than opening a public issue.

---

## 15. Project Status & Roadmap

### Current: v1.0.0 — Release ✅

**12 Development Months:**

| Month | Deliverable |
|-------|------------|
| 1 | Foundation & Docker environment |
| 2 | Core API, PostgreSQL, JWT auth, WebSocket |
| 3 | Recon Phase 1 — Domain discovery |
| 4 | Recon Phase 2 — Port scanning (Naabu/Nmap) |
| 5 | Recon Phase 3 — HTTP probing & tech detection |
| 6 | Recon Phase 4 — Resource & endpoint enumeration |
| 7 | Vulnerability scanning — Nuclei + CVE enrichment + MITRE mapping |
| 8 | Neo4j graph database — 17 node types, 20+ relationships |
| 9 | Next.js frontend — dashboard, graph viz, 64 frontend tests |
| 10 | AI agent foundation — LangGraph, ReAct, tool binding |
| 11 | MCP tool servers — Naabu, Curl, Nuclei, Metasploit |
| 12 | Exploitation — attack paths, payload delivery, session management |

**Betterment Plan Weeks 1-12:**

| Week(s) | Enhancement |
|---------|------------|
| 1-2 | ffuf MCP server + 3 agent tool adapters |
| 3 | SQLMap MCP server + injection tools |
| 4 | LinPEAS/WinPEAS + Hash Cracker MCP + credential reuse pipeline |
| 5 | Multi-tenant QueryGraphTool fix + `AUTO_APPROVE_RISK_LEVEL` |
| 6 | SearchSploit + Nikto MCP + WPScan + CMS chain |
| 7 | SSH key extract + SSH login + reverse shell + FTP + SNMP |
| 8 | Full AD attack suite (7 tools, Kerbrute → CrackMapExec) |
| 9-10 | ML intent classifier — 4 classifier modes, confidence scoring |
| 11-12 | HTB templates (htb_easy / htb_medium), session upgrade, flag MD5 |

### v1.0 Statistics

| Metric | Value |
|--------|-------|
| Total files | 135+ |
| Lines of code | 21,000+ |
| Backend Python | 12,500+ lines |
| Frontend TypeScript | 5,000+ lines |
| Backend tests | 1624+ |
| Frontend tests | 87 |
| MCP servers | 8 |
| Agent tools | 37+ |
| Attack templates | 2 (htb_easy, htb_medium) |
| Neo4j node types | 17+ |
| API endpoints | 30+ |
| Docker services | 8 |
| CI/CD workflows | 6 |

### Year 2 Roadmap

| Quarter | Focus Areas |
|---------|------------|
| Q1 (Months 13-15) | `htb_hard` template, PDF/HTML report generation, API auth hardening |
| Q2 (Months 16-18) | Multi-target campaigns, dynamic payload generation, SIEM integration |
| Q3 (Months 19-21) | Compliance mapping (PCI-DSS, HIPAA, NIST), horizontal scaling |
| Q4 (Months 22-24) | Cloud security (AWS/Azure/GCP), container scanning, public SaaS launch |

---

## 16. Documentation Index

| Document | Location | Description |
|----------|----------|-------------|
| **This README** | `README.md` | Complete production-ready guide |
| **User Manual** | `docs/USER_MANUAL.md` | Step-by-step usage guide |
| **API Reference** | `docs/API_REFERENCE.md` | Full endpoint reference |
| **Architecture** | `docs/ARCHITECTURE.md` | System design + data flows |
| **Installation Guide** | `docs/INSTALLATION_GUIDE.md` | Detailed setup instructions |
| **Quick Start** | `docs/QUICKSTART.md` | 5-minute start guide |
| **Developer Guide** | `docs/DEVELOPER_GUIDE.md` | Contribution + extension guide |
| **MCP Guide** | `docs/MCP_GUIDE.md` | MCP server protocol docs |
| **Agent Architecture** | `docs/AGENT_ARCHITECTURE.md` | AI agent design |
| **Database Schema** | `docs/DATABASE_SCHEMA.md` | PostgreSQL + Neo4j schema |
| **Graph Schema** | `docs/GRAPH_SCHEMA.md` | Neo4j node/relationship guide |
| **Security** | `docs/SECURITY.md` | Security controls + disclosure |
| **Threat Model** | `docs/THREAT_MODEL.md` | STRIDE threat analysis |
| **Observability** | `docs/OBSERVABILITY.md` | Metrics, tracing, logging |
| **Operations Runbook** | `docs/OPERATIONS_RUNBOOK.md` | Deployment + incident response |
| **CI/CD Guide** | `docs/CI_CD_GUIDE.md` | GitHub Actions pipeline |
| **Testing Guide** | `docs/TESTING_GUIDE.md` | Test strategy + coverage |
| **Configuration Guide** | `docs/CONFIGURATION_GUIDE.md` | All config options |
| **HTB Results** | `docs/HTB_RESULTS.md` | AutoChain HTB machine data |
| **Release Notes** | `RELEASE_NOTES.md` | Full changelog |
| **Contributing** | `CONTRIBUTING.md` | How to contribute |

---

## 17. Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes following the existing code style
4. Add tests for new functionality
5. Run tests: `cd backend && pytest` / `cd frontend && npm test`
6. Open a Pull Request against `main`

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide including
code style, commit message format, and review process.

---

## 18. Author & Acknowledgments

**BitR1FT** — Founder & Lead Developer  
GitHub: [@BitR1ft](https://github.com/BitR1ft)  
Project: [UniVex](https://github.com/BitR1ft/UnderProgress) — open-source, professional offensive security platform

**Acknowledgments:**
- Built on industry-standard security tools (Metasploit, Nuclei, Naabu, etc.)
- Powered by LangGraph, LangChain, and OpenAI / Anthropic APIs
- Graph visualization via react-force-graph

---

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

> **⚠️ Legal Notice**: This tool is provided for authorised security testing and
> educational purposes only. The authors accept no liability for misuse.
> Always obtain written permission before testing any system.
