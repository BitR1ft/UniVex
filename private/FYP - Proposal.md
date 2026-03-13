# AutoPenTest AI: An Agentic, Fully-Automated Penetration Testing Framework

Student: Muhammad Adeel Haider
Program: BSCYS-F24 A
Supervisor: Sir Galib
Duration: 700 days (18–24 months)  
Start Date: [YYYY-MM-DD]  
Proposed Repository: BitR1ft/redamon (forked, inspiration only)

---

## 1. Executive Summary
AutoPenTest AI is a Linux-based, agentic, fully-automated offensive security framework that, given a single target, autonomously executes the entire penetration testing kill chain: reconnaissance, exploitation, privilege escalation (user and root flags), lateral movement (where applicable), post-exploitation, and professional report generation. The system leverages an AI agent (LangGraph/ReAct + Tree-of-Thought) that orchestrates 30+ industry tools (e.g., Nmap, Naabu, SQLMap, Metasploit, LinPEAS/WinPEAS) through a controlled sandbox, documenting every step with timestamps, commands, outputs, evidence, and remediation advice.

Target outcome: Achieve a 90–95% autonomous success rate on “Hard” difficulty HackTheBox (HTB) machines, with 100% on Easy and 95%+ on Medium, and produce professional PDF/HTML reports suitable for client delivery.

---

## 2. Problem Statement
Traditional penetration testing is labor-intensive, tool-fragmented, and reliant on expert intuition. This leads to:
- Slow assessments and inconsistent coverage
- High skill barriers and limited scalability
- Fragmented outputs and inconsistent reporting
- Inability to rapidly test multiple attack paths

This project addresses these gaps by building an autonomous, explainable system that reliably executes offensive workflows end-to-end and produces standardized, high-quality results and reports.

---

## 3. Objectives
Primary objectives:
- Build an agentic AI that, from a single “target” input, autonomously:
  - Performs multi-phase recon, web/API discovery, technology fingerprinting
  - Selects and executes exploitation strategies (CVE-based, web vulns, credential attacks)
  - Achieves user and root flags via automated privilege escalation (Linux/Windows)
  - Conducts post-exploitation tasks (enumeration, credential harvesting, evidence collection)
  - Generates a complete professional report (PDF/HTML/JSON) with all steps and remediation
- Implement multi-path exploration (Tree-of-Thought): attempt the best route, backtrack, try alternates end-to-end, and document each branch.
- Achieve target success rates: HTB Easy 100%, Medium ≥95%, Hard 90–95% autonomously.
- Ensure ethical safeguards: scope enforcement, approval gates for destructive actions, audit logging.

Secondary objectives:
- Neo4j attack-surface graph modeling and visualization (2D/3D)
- Machine learning enhancements for vulnerability prioritization, exploit prediction, and false-positive reduction
- Team collaboration features (RBAC, activity feed, notifications) and report templating

---

## 4. Scope
In-Scope:
- Linux-based CLI orchestration (Kali containerized toolchain)
- Web app dashboard (Next.js) for project setup, status, logs, graph, and report management
- Agentic AI orchestration of 30+ tools via MCP servers/SSE/JSON-RPC
- HTB (retired boxes) and lab VMs for evaluation
- Professional reporting (CVSS scoring, remediation guidance, evidence inclusion)

Out-of-Scope:
- Unauthorized real-world targets without explicit permission
- Non-ethical features (evasion beyond safe research labs)
- Cutting-edge zero-day research (focus on automation of known vectors)

---

## 5. Methodology
- System architecture: microservices via Docker Compose; FastAPI backend; Next.js frontend; PostgreSQL (settings); Neo4j (graph of assets/vulns); Kali tool sandbox; MCP tool servers (Naabu, Curl, Nuclei, Metasploit).
- Agent Design: LangGraph/ReAct for step-wise reasoning; Tree-of-Thought for branch exploration; MemorySaver for checkpointing; vector memory for learned strategies.
- Toolchain Integration: Nmap/Naabu, httpx, Katana/GAU/Kiterunner, Wappalyzer, Nuclei+DAST+Interactsh, SQLMap, Metasploit, LinPEAS/WinPEAS, Hashcat/John, CrackMapExec, BloodHound, Chisel/Ligolo, Kerbrute.
- Data Modeling: 25+ Neo4j node types (Domain, Subdomain, IP, Port, Service, BaseURL, Endpoint, Parameter, Technology, Vulnerability, CVE, CWE/CAPEC, Exploit, Credential, Persistence, etc.); 35+ relationships.
- Reporting: Jinja2 HTML + WeasyPrint/ReportLab PDF; CVSS v3.1; risk scoring; remediation; timelines; command transcripts; evidence (screenshots, outputs).
- Ethics & Safety: scope enforcement, opt-in approval gates, audit log, activity feed, legal disclaimers.

---

## 6. System Architecture (Overview)
- Frontend: Next.js (TypeScript), Tailwind, shadcn/ui; graph visualization (react-force-graph 2D/3D)
- Backend: FastAPI (Python), WebSocket/SSE streaming; TanStack Query
- Datastores: PostgreSQL (Prisma schema for config), Neo4j (attack surface, findings, exploits)
- Orchestration: Docker Compose; Kali sandbox with tools; MCP servers per tool; JSON-RPC/SSE
- AI Engine: LangGraph + OpenAI/Anthropic LLMs; prompts per phase; ToT branching; MemorySaver
- Security: JWT auth; RBAC; rate limiting; input sanitization; HTTPS; audit logging

---

## 7. Tools & Technologies
- Languages: Python (backend/agents), TypeScript (frontend), Cypher (Neo4j)
- Core Tools: Nmap, Naabu, httpx, Katana, GAU, Kiterunner, Wappalyzer, Nuclei, SQLMap, Metasploit, LinPEAS/WinPEAS, Hashcat, John, CrackMapExec, BloodHound, Chisel/Ligolo, Kerbrute
- Infra: Docker, FastAPI, Next.js, Prisma, PostgreSQL, Neo4j, WebSocket/SSE
- AI/ML: LangGraph/LangChain, OpenAI/Anthropic; scikit-learn (prioritization, anomaly detection)

---

## 8. Work Plan & Timeline (Brief)
Phased milestones (aligned to 700-day plan):
1. Days 1–120: Foundations (Docker, DBs, backend/frontend, auth, basic forms)
2. Days 121–240: Recon pipeline (domain discovery, port scanning, HTTP probing, resource enumeration)
3. Days 241–365: Agent v1.0 (ReAct loop, MCP servers, CVE + brute force workflows, basic post-exploitation, reporting scaffold)
4. Days 366–540: Advanced exploitation (web vulns, credential attacks, privilege escalation, lateral movement/AD chains); agentic ToT; v1.5 “Hard Mode”
5. Days 541–605: Professional reporting, polish, charts, CVSS, remediation
6. Days 606–665: Collaboration + ML enhancements (prioritization, exploit prediction, FP reduction)
7. Days 666–700: Final integration, HTB validation (≥30 Hard boxes), performance/security audits, FYP report & presentation, v2.0 release

---

## 9. Evaluation Plan
Quantitative:
- HTB success rates (retired boxes):
  - Easy: 100%
  - Medium: ≥95%
  - Hard: 90–95%
- Coverage: % of phases completed autonomously per machine
- Performance: median time to user flag/root flag vs human baseline
- Quality: report completeness (timelines, commands, evidence, remediation)
- Reliability: error recovery success; tool execution failures handled
- Code quality: ≥80% test coverage; CI checks; linting

Qualitative:
- Consistency of attack reasoning (explainability)
- Report usability for client stakeholders
- Ethical compliance (scope enforcement, approvals, audit trail)

---

## 10. Deliverables
- Full source code (Dockerized services; agent; MCP servers; UI)
- Professional reports (PDF/HTML/JSON) with evidence and remediation
- Documentation: User Manual, Developer Guide, API Reference, Architecture Diagrams
- FYP Report (30,000+ words), Presentation deck, Demo videos
- Validation dataset: test results on ≥100 HTB boxes (including ≥30 Hard)

---

## 11. Ethical, Legal, and Safety Considerations
- Strict scope enforcement: only lab targets/authorized assets
- Approval gates for destructive actions
- Audit logging of all commands
- Legal disclaimers and responsible use policy
- No storing or leaking sensitive client data beyond permitted reports
- Secure secret handling (no hardcoded keys; .env and vaults)

---

## 12. Risks & Mitigations
- Tool instability / updates: pin versions, nightly validation, fallbacks
- LLM variability: prompt tuning, deterministic modes, self-critique
- False positives: cross-validation via ML and multiple tools
- Privilege escalation variance: multi-path ToT with backtracking
- Performance bottlenecks: parallelization; caching; rate limiting
- Ethical concerns: lab-only validation; approval workflows

---

## 13. Expected Outcomes & Contributions
- A production-grade autonomous pentesting agent with near-expert performance on HTB Hard machines
- Standardized, high-quality reporting pipeline with full traceability
- A practical blueprint for agentic cybersecurity systems integrating LLMs with deterministic tooling
- Potential for academic publication and industry adoption (SaaS readiness)

---

## 14. Resource Requirements
- Hardware: Linux workstation capable of Docker; optional GPU for Hashcat
- Subscriptions/Access: HTB (retired boxes), vulnerability feeds (NVD/Vulners), Interactsh
- Software: Docker, FastAPI/Next.js toolchains, Neo4j Desktop/Server
- Time: 700 days (part-time), aligned to milestone plan

---

## 15. Conclusion
This project aims to transform penetration testing by automating the end-to-end workflow with an agentic AI that reliably executes multi-path exploit strategies, obtains user and root flags, and produces professional-grade reports. With rigorous engineering, ethical safeguards, and quantitative validation on HTB, AutoPenTest AI advances both academic research and practical offensive security.

---
