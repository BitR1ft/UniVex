# AutoPenTest AI v1.2

> **Version 1.2.0** — Betterment Plan Weeks 1-12 Complete ✅  
> HTB Attack Templates • Session Upgrade • Flag MD5 Verification

An agentic, fully-automated penetration testing framework that autonomously executes the entire penetration testing kill chain — from reconnaissance to exploitation to reporting.

## 🎯 Project Overview

AutoPenTest AI is a Linux-based, AI-powered offensive security framework that, given a single target, autonomously executes:
- **Reconnaissance**: Multi-phase discovery (5 phases), web/API detection, technology fingerprinting
- **Exploitation**: CVE-based attacks, web vulnerabilities, credential attacks with human-in-the-loop safety
- **Web Application Attacks**: SQLMap SQLi detection/exploitation, Nikto web scanning, WPScan CMS detection
- **Privilege Escalation**: Automated user and root flag acquisition with LinPEAS/WinPEAS enumeration
- **Post-Exploitation**: Hash cracking (John/Hashcat), credential reuse pipeline, SSH key extraction
- **Active Directory**: Kerbrute, enum4linux-ng, Impacket (ASREPRoast/Kerberoast), Pass-the-Hash, LDAP, CrackMapExec
- **Network Services**: SSH login, reverse shell generation, anonymous FTP, SNMP enumeration
- **ML-based Intent Classification**: Keyword/ML/LLM/Hybrid classifiers with confidence scoring
- **Report Generation**: Structured engagement summaries with remediation guidance

### Target Success Rates
- HTB Easy: 100%
- HTB Medium: ≥95%
- HTB Hard: 90-95%

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Next.js Frontend                          │
│           (TypeScript, Tailwind CSS, shadcn/ui)                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                    WebSocket/SSE (Real-time)
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                             │
│                  (Python, JWT Auth, REST API)                    │
└─────────────────────────────────────────────────────────────────┘
                    │                         │
        ┌───────────┴──────────┐    ┌────────┴─────────┐
        │                      │    │                  │
    PostgreSQL              Neo4j         AI Agent      │
  (Configuration)    (Attack Graph)   (LangGraph)      │
                                                        │
                                          ┌─────────────┴──────────┐
                                          │    Kali Tool Sandbox   │
                                          │  (Nmap, Nuclei, etc.)  │
                                          └────────────────────────┘
```

## 📚 Technology Stack

### Frontend
- **Framework**: Next.js 14+ (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **UI Components**: shadcn/ui
- **State Management**: TanStack Query
- **Visualization**: react-force-graph (2D/3D)

### Backend
- **Framework**: FastAPI
- **Language**: Python 3.11+
- **ORM**: Prisma (PostgreSQL)
- **Authentication**: JWT
- **Real-time**: WebSocket/SSE

### Databases
- **PostgreSQL**: Configuration, users, projects, settings
- **Neo4j**: Attack surface graph, relationships, findings

### AI & Tools
- **Agent Framework**: LangGraph/LangChain
- **LLM Providers**: OpenAI/Anthropic
- **Security Tools**: Nmap, Naabu, Nuclei, SQLMap, Metasploit, LinPEAS/WinPEAS, etc.

### Infrastructure
- **Containerization**: Docker & Docker Compose
- **CI/CD**: GitHub Actions
- **Testing**: pytest (Python), Jest (TypeScript)

## 🚀 Getting Started

### Prerequisites
- Docker Desktop (or Docker + Docker Compose)
- Node.js 22+
- Python 3.11+
- Git

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/BitR1ft/FYP.git
cd FYP
```

2. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start the services with Docker Compose**
```bash
docker-compose up -d
```

4. **Access the application**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Neo4j Browser: http://localhost:7474

### Development Setup

#### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

#### Frontend Development
```bash
cd frontend
npm install
npm run dev
```

## 📖 Documentation

- [User Manual](docs/USER_MANUAL.md) — Step-by-step guide to using AutoPenTest AI
- [Release Notes](RELEASE_NOTES.md) — v1.0.0 changelog and feature details
- [API Documentation](docs/API.md) — REST API reference
- [Architecture Guide](docs/ARCHITECTURE.md) — System architecture and design
- [Project Proposal](FYP%20-%20Proposal.md)
- [Year 1 Development Plan](FYP%20-%20YEAR%2001.md)
- [Year 1 Gap Coverage Plan](YEAR_01_GAP_COVERAGE_PLAN.md) — Day-by-day plan to fill all gaps (215 days)
- [Gap Coverage Quick Reference](GAP_COVERAGE_QUICK_REFERENCE.md) — Quick access guide and phase summaries
- [Progress Tracker](PROGRESS_TRACKER.md) — Daily progress tracking template
- [Gap Analysis](GAP.md) — Detailed gap analysis and requirements
- [Year 2 Roadmap](PHASE02.md) — Year 2 development plan
- [Contributing Guidelines](CONTRIBUTING.md)
- [Interactive API Docs](http://localhost:8000/docs) (when backend is running)

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 📋 Project Status

**Current Phase**: v1.2.0 Release — Betterment Plan Weeks 1-12 Complete ✅

**All 12 Development Months Complete**:
- ✅ Month 1: Foundation & Environment Setup
- ✅ Month 2: Core Infrastructure  
- ✅ Month 3: Reconnaissance Pipeline - Phase 1 (Domain Discovery)
- ✅ Month 4: Reconnaissance Pipeline - Phase 2 (Port Scanning)
- ✅ Month 5: Reconnaissance Pipeline - Phase 3 (HTTP Probing & Technology Detection)
- ✅ Month 6: Reconnaissance Pipeline - Phase 4 (Resource Enumeration)
- ✅ Month 7: Vulnerability Scanning (Nuclei Integration, CVE Enrichment & MITRE Mapping)
- ✅ Month 8: Neo4j Graph Database (17 Node Types, 20+ Relationships, 92% Test Coverage)
- ✅ Month 9: Web Application Frontend (Next.js Dashboard, Graph Visualization, 64 Tests)
- ✅ Month 10: AI Agent Foundation (LangGraph, ReAct Pattern, Tool Binding)
- ✅ Month 11: MCP Tool Servers (Naabu, Curl, Nuclei, Metasploit, Query Graph, Web Search)
- ✅ Month 12: AI Agent Exploitation (Attack Paths, Payload Delivery, Session Management)

**Betterment Plan v1.2 Enhancements**:
- ✅ Week 1-2: ffuf web fuzzing MCP server (port 8004) + agent adapters
- ✅ Week 3: SQLMap MCP server (port 8005) + agent adapters (detect/dump/tables/columns)
- ✅ Week 4: LinPEAS/WinPEAS tools + Hash Cracker MCP server (port 8006) + credential reuse pipeline
- ✅ Week 5: QueryGraphTool multi-tenancy fix + AUTO_APPROVE_RISK_LEVEL env var
- ✅ Week 6: SearchSploit + Nikto MCP server (port 8007) + WPScan + CMS detection chain
- ✅ Week 7: SSH key extraction + SSH login + reverse shell generation + FTP + SNMP tools
- ✅ Week 8: Active Directory tools (Kerbrute, enum4linux-ng, Impacket, PtH, LDAP, CrackMapExec)
- ✅ Week 9-10: ML-based intent classifier (KeywordClassifier, MLClassifier, LLMClassifier, HybridClassifier)
- ✅ Week 11-12: HTB attack templates (`htb_easy` / `htb_medium`), `AutoChain.from_template()`, session upgrade, flag MD5 verification

### v1.2 Statistics

| Metric | Value |
|--------|-------|
| Development Duration | 12 months + betterment |
| Total Files | 135+ |
| Lines of Code | 21,000+ |
| Backend (Python) | 12,500+ |
| Frontend (TypeScript) | 5,000+ |
| Documentation | 3,500+ |
| Backend Test Cases | 892+ |
| Frontend Test Cases | 87 |
| MCP Servers | 7 |
| Agent Tools | 37+ |
| Attack Templates | 2 (htb_easy, htb_medium) |
| Neo4j Node Types | 17+ |
| API Endpoints | 17+ |
| Docker Services | 6 |

See [Release Notes](RELEASE_NOTES.md) for detailed changelog.
See [User Manual](docs/USER_MANUAL.md) for usage instructions.
See [Betterment Plan](BETTERMENT_PLAN.md) for the full improvement roadmap.
See [HTB Results](docs/HTB_RESULTS.md) for AutoChain HTB machine performance data.

## 🔒 Security & Ethics

This framework is designed for authorized penetration testing only. Key safeguards:
- Strict scope enforcement
- Approval gates for destructive actions
- Complete audit logging
- Legal disclaimers and responsible use policy

**⚠️ Warning**: Unauthorized use of this tool against systems you don't own or have explicit permission to test is illegal and unethical.

## 📝 License

MIT License — See [LICENSE](LICENSE) for details.

## 🔮 Year 2 Roadmap

| Quarter | Focus |
|---------|-------|
| ~~Betterment Weeks 11-12~~ | ✅ HTB-specific attack templates (Easy/Medium), flag capture automation |
| Betterment Weeks 13-16 | Report generation (PDF/Markdown), performance tuning, security hardening |
| Q1 (Months 13–15) | API auth hardening, rate limiting, dynamic payload generation |
| Q2 (Months 16–18) | Multi-target campaigns, automated report generation (PDF/HTML) |
| Q3 (Months 19–21) | Compliance mapping (PCI-DSS, HIPAA, NIST), horizontal scaling |
| Q4 (Months 22–24) | Cloud security (AWS/Azure/GCP), container scanning |

## 👨‍💻 Author

**Muhammad Adeel Haider**
- Program: BSCYS-F24 A
- Supervisor: Sir Galib

## 🙏 Acknowledgments

- Inspired by RedAmon framework
- Built on top of industry-standard security tools
- Leveraging modern AI capabilities with LangGraph
