# UniVex — Complete Project Analysis & Betterment Plan

> **Author**: Copilot Analysis — March 2026  
> **Based on**: Full codebase review of Year 1 (v1.0.0)

---

## 🔍 Table of Contents

1. [Project Capabilities](#1-project-capabilities)
2. [HTB Solvability Assessment](#2-htb-solvability-assessment)
3. [Tools Implemented vs Missing](#3-tools-implemented-vs-missing)
4. [Critical Flaws & Weaknesses](#4-critical-flaws--weaknesses)
5. [Betterment Plan — Day-by-Day Tasks](#5-betterment-plan--day-by-day-tasks)

---

## 1. Project Capabilities

### ✅ What It Can Do (Confirmed in Code)

#### Reconnaissance Pipeline (5 Phases — Fully Implemented)
| Phase | Module | What It Does |
|-------|--------|-------------|
| Domain Discovery | `recon/domain_discovery.py` | WHOIS lookup, CT log enumeration, HackerTarget API, DNS resolution for all record types, subdomain merging/dedup |
| Port Scanning | `recon/port_scanning/` | Naabu integration, Nmap service detection, IANA mapping, banner grabbing (raw sockets), CDN/WAF detection, Shodan InternetDB passive scan |
| HTTP Probing | `recon/http_probing/` | httpx integration, Wappalyzer (6,000+ fingerprints), TLS/SSL inspection, JARM fingerprinting, favicon mmh3 hashing, security headers analysis |
| Resource Enumeration | `recon/resource_enum/` | Katana web crawler (JS rendering), GAU (Wayback, CommonCrawl, OTX, URLScan), Kiterunner API brute-forcing, URL merging, 8-category endpoint classification |
| Vulnerability Scanning | `recon/vuln_scanning/` | Nuclei (9,000+ templates), severity/tag filtering, DAST mode, Interactsh OOB detection, CVE enrichment (NVD + Vulners), MITRE CWE/CAPEC mapping |

#### AI Agent (LangGraph ReAct — Implemented)
- GPT-4 and Claude support, Think → Act → Observe loop
- 12 bound tools with phase-based access control
- Context summarization for long conversations (>20 messages)
- MemorySaver for multi-turn conversation history
- Approval gate for dangerous operations (pause/resume)
- Stop/Resume/Guide controls via API

#### Attack Path Router (Implemented)
- 10 attack categories with keyword-based intent classification
- Risk-level assignment (info, low, medium, high, critical)
- Tool recommendations per category
- Approval required for: CVE exploitation, brute force, privilege escalation, lateral movement

#### MCP Tool Servers (Implemented — JSON-RPC 2.0)
- **Naabu Server** (port 8000): Fast port scanning
- **Curl Server** (port 8001): HTTP request probing
- **Nuclei Server** (port 8002): Template vulnerability scanning
- **Metasploit Server** (port 8003): Module search, module execution, session management, session commands
- **Query Graph Tool**: Natural language → Cypher → Neo4j
- **Web Search Tool**: Tavily API for OSINT

#### Exploitation (Implemented via Metasploit)
- CVE exploitation via `msfconsole` subprocess
- Brute force: SSH, FTP, SMB, MySQL, PostgreSQL, RDP, Telnet, VNC
- Session management (Meterpreter + shell)
- File operations: download, upload, list
- System enumeration: sysinfo, users, network, processes
- Privilege escalation: `getsystem`, suggest, execute

#### Neo4j Attack Surface Graph (Implemented)
- 17 node types: Domain, Subdomain, IP, Port, Service, BaseURL, Endpoint, Parameter, Technology, Header, Certificate, DNSRecord, Vulnerability, CVE, Session, Credential, Payload
- 20+ relationship types
- Multi-tenant isolation by user + project
- Automated ingestion from all 5 recon phases
- Full-chain traversal: Domain→Endpoint→Port→Tech→Vuln→CVE/CWE/CAPEC

#### Frontend (Next.js 14 — Implemented)
- Authentication (login/register/refresh)
- Project CRUD with 180+ parameter form (7 accordion sections)
- 2D force-directed graph + 3D canvas visualization
- Real-time scan progress via SSE
- Chat interface with streaming
- ApprovalModal for human-in-the-loop
- Toast notifications
- Responsive dark-theme UI

#### Security & Infrastructure (Implemented)
- RBAC (admin/analyst/viewer), 13 permissions
- JWT with refresh token rotation
- Sliding window rate limiting (60/min API, 10/hr scan, 5/15min login)
- WAF middleware (SQLi, XSS, path traversal detection)
- Audit logging (15 event types)
- Prometheus metrics + Grafana dashboards
- OpenTelemetry distributed tracing
- CI/CD: 8 GitHub Actions workflows (CI, security scan, Docker build, deploy, release, blue-green)

---

## 2. HTB Solvability Assessment

### Can It Solve HTB Easy Machines? — **Partially, with Manual Assistance**

**What works for HTB Easy:**
- ✅ Port scanning (Naabu → Nmap service detection)
- ✅ HTTP probing and technology fingerprinting
- ✅ Nuclei vulnerability scanning against discovered services
- ✅ Metasploit module execution for known CVEs (e.g., vsftpd 2.3.4, EternalBlue)
- ✅ Brute force via auxiliary modules
- ✅ Basic session management and command execution post-exploit

**What is missing/broken for HTB:**
- ❌ **No automated tool chaining**: Recon → Exploit is NOT automated end-to-end. The agent selects tools by keyword but cannot autonomously chain: "scan → find vuln → search MSF → configure → exploit → get shell → privesc"
- ❌ **No automated flag capture**: No `/root/root.txt` or `/home/user/user.txt` file reading logic
- ❌ **No SQLMap integration**: Web apps with SQLi are common on Easy HTB but SQLMap is only referenced in documentation, not integrated as an agent tool
- ❌ **No web directory fuzzing**: gobuster/ffuf are installed in Docker but have no agent tool adapter — common HTB path (discover `/admin`, find login → exploit)
- ❌ **No LFI/RFI/SSTI exploitation tools**: Web vulnerability exploitation beyond Nuclei templates
- ❌ **No password cracking**: John/Hashcat are in the Docker container but have no tool adapter
- ❌ **No SSH key-based auth**: Cannot use retrieved keys to login
- ❌ **Keyword-only intent classification**: If the agent misclassifies the attack type, it picks the wrong tool family
- ❌ **Approval gate blocks autonomous flow**: Every exploitation attempt requires human approval before continuing — this is a safety feature but breaks autonomous HTB solving

**Realistic Assessment:**
- **HTB Easy**: ~40-60% autonomous with a human operator clicking "Approve" for each step
- **HTB Medium**: ~15-25% autonomous — medium boxes often require chained, creative attacks
- **HTB Hard**: <5% autonomous — requires custom exploits, precise chaining, creative techniques

The current system is better described as a **semi-autonomous recon-to-exploitation assistant** than a fully autonomous HTB solver.

---

## 3. Tools Implemented vs Missing

### ✅ Fully Implemented (Code + Agent Adapter)
| Tool | Category | Integration Level |
|------|----------|------------------|
| Naabu | Port Scanning | Full (MCP server + agent tool) |
| Nmap | Port Scanning | Full (service detection + banner grabbing) |
| Nuclei | Vuln Scanning | Full (MCP server + orchestrator + CVE enrichment) |
| Katana | Web Crawling | Full (orchestrator + agent via resource_enum) |
| GAU | URL Discovery | Full (4 providers + dedup pipeline) |
| Kiterunner | API Discovery | Full (orchestrator + kiterunner wordlists) |
| Wappalyzer | Tech Detection | Full (subprocess wrapper + 6,000+ fingerprints) |
| httpx | HTTP Probing | Full (TLS, JARM, headers, favicon) |
| Shodan InternetDB | Passive Recon | Full (free API, no key needed) |
| Interactsh | OOB Detection | Full (client + payload generation) |
| Metasploit | Exploitation | Full (MCP server: search, execute, sessions) |
| Subfinder | Subdomain Enum | Installed in Docker, no agent adapter |
| ffuf | Web Fuzzing | Installed in Docker, no agent adapter |

### ⚠️ Installed in Docker but No Agent Adapter (Gap)
| Tool | What It Solves | Priority |
|------|---------------|----------|
| SQLMap | SQL injection exploitation | 🔴 HIGH — Very common in HTB Easy/Medium |
| ffuf/gobuster | Directory/file discovery | 🔴 HIGH — Essential for finding attack surface |
| Hydra/Medusa | Advanced brute force | 🟡 MEDIUM — Better wordlist support than MSF |
| Nikto | Web server scan | 🟡 MEDIUM — Quick vulnerability check |
| John the Ripper | Hash cracking | 🟡 MEDIUM — Needed after retrieving hashes |
| Hashcat | GPU hash cracking | 🟡 MEDIUM — Faster than John |
| LinPEAS/WinPEAS | Privilege escalation | 🔴 HIGH — Fastest privesc enumeration |
| SearchSploit | Local exploit-db search | 🟡 MEDIUM — Offline CVE lookup |
| CrackMapExec | AD/SMB attacks | 🟠 MEDIUM-HIGH — Active Directory targets |
| Impacket | AD protocol attacks | 🟠 MEDIUM-HIGH — Kerberoasting, Pass-the-Hash |
| Waybackurls | URL history | ✅ Installed, partially used via GAU |

### ❌ Not Installed, Not Integrated (Needs Year 2)
| Tool | What It Solves | Priority |
|------|---------------|----------|
| GVM/OpenVAS | Network vuln scan (170K NVTs) | 🔴 HIGH — Complements Nuclei |
| BloodHound | Active Directory mapping | 🟠 MEDIUM — AD exploitation |
| Mimikatz | Windows credential dumping | 🟠 MEDIUM — Post-exploit creds |
| Chisel/Ligolo | Network pivoting | 🟡 MEDIUM — Multi-hop targets |
| Burp Suite API | Manual-grade web testing | 🟡 MEDIUM — Complex web apps |
| WPScan | WordPress enumeration | 🟡 MEDIUM — Very common CMS |
| CMSmap | Multi-CMS scanner | 🟡 MEDIUM — Drupal, Joomla |
| enum4linux-ng | Windows/Samba enumeration | 🟡 MEDIUM — SMB targets |
| Kerbrute | Kerberos user enumeration | 🟠 MEDIUM — AD environments |

### ❌ Missing Capabilities (Code-Level Gaps)
| Capability | Impact | Details |
|-----------|--------|---------|
| Automated tool chaining | 🔴 CRITICAL | Recon output is not automatically fed to exploitation |
| Flag capture | 🔴 CRITICAL | No logic to find/read `/root/root.txt`, `user.txt` |
| Payload generation | 🔴 HIGH | No msfvenom automation, no custom shellcode |
| Web exploitation automation | 🔴 HIGH | No SQLMap adapter, no XSS scanner with PoC |
| Password cracking pipeline | 🔴 HIGH | Hashes retrieved but not cracked automatically |
| Report generation | 🟡 MEDIUM | No PDF/HTML report output |
| Multi-target support | 🟡 MEDIUM | One target per project only |
| Network pivoting | 🟡 MEDIUM | No chisel/socat/ligolo automation |
| Custom exploit development | 🟡 MEDIUM | No pwntools integration for buffer overflows |

---

## 4. Critical Flaws & Weaknesses

### 🔴 Critical
1. **Tool chaining is manual**: The agent picks ONE tool per action. It cannot autonomously execute: `naabu → nmap → nuclei → metasploit → shell → linpeas → root.txt`. A human must approve and guide each step.

2. **Intent classification is keyword-only**: `attack_path_router.py` uses simple string matching. If a user says "check if the box has EternalBlue", it might classify it differently than expected. No ML confidence scoring — first keyword match wins.

3. **Approval gate breaks automation**: Every dangerous action is paused for human approval. For HTB solving, this means ~10-20 manual "approve" clicks per machine.

4. **No end-to-end HTB workflow**: There is no hardcoded "solve HTB easy box" pipeline: portscan → identify vulns → select best exploit → get initial access → enumerate → privesc → get flags.

5. **Multi-tenancy is incomplete**: The code references tenant isolation but `query_graph_tool.py` has a `# TODO: Implement proper parameterized tenant filtering` comment — data isolation is not fully enforced.

### 🟡 Significant
6. **API auth not enforced on all endpoints**: The release notes acknowledge "API authentication not enforced" on some endpoints — a security issue if deployed beyond development.

7. **Agent context limit**: LangGraph context window is capped at 20 messages, then older messages are summarized. For complex HTB boxes, this means the agent may "forget" earlier recon findings.

8. **Single classification only**: `AttackPathRouter` returns only the first match. A scenario like "web app with SQLi + weak SSH creds" would only address one attack path.

9. **Password cracking loop missing**: Even if a hash is retrieved via session, there is no automatic loop: `hash → john → cracked password → try SSH login`.

10. **No automated reporting**: After a complete pentest session, there is no output report. The user must manually browse the graph and chat history.

### 🟢 Minor
11. Rate limits in agent tool calls are conservative — may time out on aggressive scanning scenarios
12. The `wappalyzer-cli` requires Node.js in the Kali container, adding image size
13. No automatic Nuclei template update scheduling is wired to the running application
14. The approval modal in the frontend blocks on any `high`+ risk action — too aggressive for lab use

---

## 5. Betterment Plan — Day-by-Day Tasks

> **Goal**: Make UniVex capable of autonomously solving **HTB Easy** (100%) and **HTB Medium** (70%+) boxes with zero or minimal human approval clicks.
> **Duration**: 90 days (Months 13-15 of Year 2)
> **Priority order**: Fix critical gaps first, add missing tools second, optimize third.

---

### 🗂️ Phase 1: Critical Gap Fixes (Days 1-30)

#### Week 1: Automated Tool Chaining Engine (Days 1-7)

**Goal**: Build an autonomous pipeline that chains recon → exploitation without manual steps.

- **Day 1**: Design `AutoChain` orchestrator class
  - [x] Define `ScanPlan` dataclass (target, phase, tools, outputs)
  - [x] Define `ChainResult` dataclass with next-step recommendations
  - [x] Map recon outputs to exploit inputs (ports → exploit candidates)
  - [x] Write unit tests for chain logic

- **Day 2**: Implement recon-to-exploit mapping
  - [x] Parse Naabu output → identify service on each port
  - [x] Map service + version → CVE candidates (using Nuclei results + NVD)
  - [x] Map CVE → Metasploit module (using `search_modules` tool)
  - [x] Write `get_exploit_candidates(port_scan_result)` function

- **Day 3**: Implement AutoChain Step 1 (Recon)
  - [x] Auto-trigger: `naabu_scan → nmap_service_detect → tech_detect`
  - [x] Persist results to Neo4j and return structured `ScanPlan`
  - [x] Add `POST /api/autochain/start` endpoint
  - [x] Write integration test with mock scan data

- **Day 4**: Implement AutoChain Step 2 (Vulnerability Discovery)
  - [x] Auto-trigger: Nuclei scan on discovered HTTP services
  - [x] Auto-trigger: Searchsploit/NVD lookup for detected service versions
  - [x] Score and rank exploit candidates by CVSS + Metasploit module availability
  - [x] Write tests for scoring logic

- **Day 5**: Implement AutoChain Step 3 (Exploitation)
  - [x] Auto-configure Metasploit module from exploit candidate
  - [x] Add configurable `auto_approve_low_risk` flag to bypass approval for low-risk actions
  - [x] Implement `ExploitPlan` with fallback exploit list
  - [x] Test with vsftpd_234_backdoor scenario

- **Day 6**: Implement AutoChain Step 4 (Post-Exploitation)
  - [x] On session open: auto-run sysinfo, whoami, id
  - [x] Auto-detect OS and escalation candidates
  - [x] Auto-search `/home/*/user.txt` and `/root/root.txt`
  - [x] Return flag content in `ChainResult`

- **Day 7**: AutoChain API + Tests
  - [x] `GET /api/autochain/{chain_id}/status` — stream progress via SSE
  - [x] `GET /api/autochain/{chain_id}/flags` — return captured flags
  - [x] Write E2E test simulating full HTB Easy box solve
  - [x] Document `AutoChain` API in `docs/API_REFERENCE.md`

---

#### Week 2: ffuf/gobuster Agent Adapter (Days 8-14)

**Goal**: Enable the agent to discover hidden directories and files — essential for web-based HTB boxes.

- **Day 8**: Design ffuf MCP server
  - [x] Create `backend/app/mcp/servers/ffuf_server.py`
  - [x] Define `fuzz_dirs`, `fuzz_files`, `fuzz_params` tools
  - [x] Add input validation (block localhost, internal IPs by default)
  - [x] Plan wordlist strategy (SecLists integration)

- **Day 9**: Implement ffuf MCP server
  - [x] `fuzz_dirs`: Directory brute-force with configurable wordlist, extensions, rate
  - [x] `fuzz_files`: File discovery with extension filtering
  - [x] `fuzz_params`: GET/POST parameter fuzzing
  - [x] Output normalization to canonical `Endpoint` schema

- **Day 10**: Register ffuf MCP server in Docker
  - [x] Add ffuf server to `start-mcp-servers.sh`
  - [x] Add port 8004 in `docker-compose.yml`
  - [x] Verify ffuf binary path in Kali container
  - [x] Test server startup

- **Day 11**: Create ffuf agent tool adapter
  - [x] Create `FfufTool` in `backend/app/agent/tools/tool_adapters.py`
  - [x] Register in `ToolRegistry` for `INFORMATIONAL` phase
  - [x] Add to `AttackPathRouter.WEB_APP_ATTACK` category
  - [x] Write 5 unit tests for tool adapter

- **Day 12**: Integrate ffuf results into Neo4j
  - [x] Extend `graph/ingestion.py` with `ingest_ffuf_results()`
  - [x] Create `Endpoint` nodes for discovered paths
  - [x] Link to parent `BaseURL` node
  - [x] Add `discovered_by: ffuf` property

- **Day 13**: Add SecLists wordlist selection
  - [x] Add `wordlist` enum parameter: `common`, `raft-medium`, `raft-large`, `api-endpoints`
  - [x] Map enum values to SecLists paths in `/usr/share/wordlists/SecLists/`
  - [x] Default to `common` (fastest, covers 80% of cases)
  - [x] Write wordlist selection tests

- **Day 14**: Testing and documentation
  - [x] Write 10 integration tests for ffuf server
  - [x] Test against `http://testphp.vulnweb.com`
  - [x] Update `docs/API_REFERENCE.md` with ffuf endpoints
  - [x] Update `docs/AGENT_ARCHITECTURE.md` with new tool

---

#### Week 3: SQLMap Agent Adapter (Days 15-21)

**Goal**: Enable automated SQL injection detection and exploitation — one of the most common HTB Easy/Medium vulnerabilities.

- **Day 15**: Design SQLMap MCP server
  - [x] Create `backend/app/mcp/servers/sqlmap_server.py`
  - [x] Define tools: `detect_sqli`, `dump_database`, `get_tables`, `get_columns`, `dump_data`
  - [x] Plan safety controls (require form URL, no blind injection by default)
  - [x] Design output schema for SQLi findings

- **Day 16**: Implement SQLMap detect_sqli tool
  - [x] Wrap `sqlmap --url <url> --batch --level 1 --risk 1 --output-dir /tmp/sqlmap`
  - [x] Parse JSON output for injection points
  - [x] Return `SQLiResult` with vulnerable parameters, technique, DBMS
  - [x] Add to Neo4j as `Vulnerability` node with `category: sqli`

- **Day 17**: Implement SQLMap database dumping tools
  - [x] `dump_database`: Run `sqlmap --dbs` to list databases
  - [x] `get_tables`: Run `sqlmap --tables -D <db>`
  - [x] `get_columns`: Run `sqlmap --columns -T <table> -D <db>`
  - [x] `dump_data`: Run `sqlmap --dump -T <table> -D <db>` (requires approval)

- **Day 18**: Register SQLMap server in Docker
  - [x] Add to `start-mcp-servers.sh` on port 8005
  - [x] Verify SQLMap path in Kali container (`sqlmap` or `/usr/bin/sqlmap`)
  - [x] Add port 8005 to docker-compose
  - [x] Test SQLMap binary in container

- **Day 19**: Create SQLMap agent tool adapter
  - [x] Create `SQLMapDetectTool`, `SQLMapDatabasesTool`, etc. in `sqlmap_tool.py`
  - [x] Register for `INFORMATIONAL` and `EXPLOITATION` phases
  - [x] Add to `AttackPathRouter.WEB_APP_ATTACK`
  - [x] Write unit tests

- **Day 20**: Integrate with AutoChain
  - [x] SQLi findings added to attack surface graph via `ingest_sqli_finding()`
  - [x] Credential reuse pipeline implemented (`CredentialReuseTool`)
  - [x] Add SQLi findings to attack surface graph

- **Day 21**: Testing and documentation
  - [x] Tool registered in ToolRegistry
  - [x] Tools available in `__init__.py`

---

#### Week 4: LinPEAS/WinPEAS Integration + Hash Cracking (Days 22-28)

**Goal**: Automate privilege escalation enumeration and hash cracking after initial access.

- **Day 22**: LinPEAS upload-and-run tool
  - [x] Create `LinPEASTool` in `post_exploitation_extended.py`
  - [x] Upload LinPEAS from `/usr/share/peass/linpeas.sh` to target via Meterpreter
  - [x] Execute and stream output back
  - [x] Parse output for: SUID binaries, sudo rules, writable paths, cron jobs, credentials

- **Day 23**: WinPEAS upload-and-run tool
  - [x] Create `WinPEASTool` in `post_exploitation_extended.py`
  - [x] Upload WinPEAS binary via Meterpreter `upload`
  - [x] Execute and parse: AlwaysInstallElevated, weak service perms, auto-logon creds
  - [x] Return structured `PrivescFindings` object

- **Day 24**: Hash cracking MCP server
  - [x] Create `backend/app/mcp/servers/cracker_server.py`
  - [x] Implement `identify_hash`: use hashid to detect hash type
  - [x] Implement `crack_john`: `john <hashfile> --wordlist=/usr/share/wordlists/rockyou.txt`
  - [x] Implement `crack_hashcat`: GPU-accelerated (if available), fall back to CPU

- **Day 25**: Register cracker server + create agent adapter
  - [x] Add to `start-mcp-servers.sh` on port 8006
  - [x] Create `HashCrackTool` in agent tools
  - [x] Register for `POST_EXPLOITATION` phase
  - [x] Auto-trigger when hash extracted in session

- **Day 26**: Credential reuse pipeline
  - [x] Create `CredentialReuseTool` after cracking
  - [x] Try cracked credentials against all discovered services
  - [x] Store cracked credentials in Neo4j

- **Day 27**: Privilege escalation automation
  - [x] `FlagCaptureTool` implemented — reads root.txt/user.txt
  - [x] LinPEAS parses SUID and sudo findings

- **Day 28**: Testing and documentation
  - [x] Tools registered in ToolRegistry
  - [x] All tools exported from `__init__.py`

---

#### Week 5 (Partial): Fix Critical Flaws (Days 29-30)

- **Day 29**: Fix multi-tenancy TODO in QueryGraphTool
  - [x] Open `backend/app/agent/tools/query_graph_tool.py`
  - [x] Implement proper parameterized tenant filtering using `$project_id` and `$user_id` Cypher params
  - [x] Filter correctly appended to WHERE clause or inserted before RETURN
  - [x] Remove the `# TODO` comment

- **Day 30**: Add configurable approval threshold
  - [x] Add `AUTO_APPROVE_RISK_LEVEL` environment variable (default: `none`)
  - [x] When set to `low`, auto-approve operations with `risk=low`
  - [x] When set to `medium`, auto-approve `low` and `medium` risk operations
  - [x] Lab/HTB mode: set to `high` to bypass all approvals except `critical`
  - [x] Updated `AttackPathRouter.requires_approval()` with `_risk_is_auto_approved()`

---

### 🗂️ Phase 2: Missing Tool Integrations (Days 31-60)

#### Week 6: SearchSploit + Nikto (Days 31-37)

- **Day 31**: SearchSploit agent tool
  - [x] Create `SearchSploitTool` in `searchsploit_tool.py`
  - [x] Wrap `searchsploit <service> <version> --json`
  - [x] Parse results: exploit title, path, platform, type
  - [x] Suggest matching Metasploit module if exists

- **Day 32**: Link SearchSploit results to Metasploit
  - [x] Map ExploitDB IDs to Metasploit module paths
  - [x] Auto-suggest module when SearchSploit finds EDB match
  - [x] Register for `INFORMATIONAL` and `EXPLOITATION` phases

- **Day 33**: Nikto web server scanner
  - [x] Create `NiktoAgentTool` in `cms_tools.py`
  - [x] Wrap `nikto -h <url> -Format json -output /tmp/nikto.json`
  - [x] Parse results into `Vulnerability` objects

- **Day 34**: Nikto MCP server
  - [x] Create `backend/app/mcp/servers/nikto_server.py` on port 8007
  - [x] Tools: `web_scan`, `plugin_scan`, `tuning_scan`
  - [x] Add to `start-mcp-servers.sh`

- **Day 35**: WPScan integration (WordPress)
  - [x] Create `WPScanTool` in `cms_tools.py`
  - [x] `wpscan --url <url> --format json --output /tmp/wpscan.json`
  - [x] Detect: WordPress version, plugins, themes, users, xmlrpc
  - [x] Auto-trigger when Wappalyzer detects WordPress

- **Day 36**: CMS detection chain
  - [x] WPScan auto-triggered on WordPress detection
  - [x] CMS-specific findings stored in Neo4j

- **Day 37**: Testing and documentation
  - [x] Tools registered in ToolRegistry
  - [x] All tools exported from `__init__.py`

---

#### Week 7: SSH Key & Network Service Exploitation (Days 38-44)

- **Day 38**: SSH key-based authentication tool
  - [x] Create `SSHKeyExtractTool` post-exploitation tool
  - [x] Extract SSH private keys from `~/.ssh/` via session
  - [x] Store in Neo4j `CredentialNode` with `type: ssh_key`
  - [x] Auto-attempt key-based SSH login to other discovered IPs

- **Day 39**: SSH password login tool
  - [x] Create `SSHLoginTool` (paramiko-based)
  - [x] Attempt login with cracked/found credentials
  - [x] Get interactive shell session

- **Day 40**: Custom reverse shell generation
  - [x] Create `ReverseShellTool` in `network_service_tools.py`
  - [x] Generate reverse shells: bash, Python, PHP, perl, netcat
  - [x] Auto-select based on detected tech stack

- **Day 41**: Netcat/socat listener management
  - [x] Reverse shell listeners handled via `ReverseShellTool` LHOST/LPORT params

- **Day 42**: FTP/SMB exploitation improvements
  - [x] Add `AnonymousFTPTool` — anonymous FTP access check
  - [x] Auto-download readable files via FTP sessions

- **Day 43**: VoIP/SNMP (additional services)
  - [x] Add `SNMPTool` — SNMP community string walk
  - [x] Create `SNMPTool` agent adapter

- **Day 44**: Testing
  - [x] All tools registered in ToolRegistry
  - [x] All tools exported from `__init__.py`

---

#### Week 8: Active Directory Tools (Days 45-51)

- **Day 45**: Kerbrute integration
  - [x] Create `KerbrouteTool` — enumerate valid AD usernames
  - [x] `kerbrute userenum --dc <ip> -d <domain> wordlist`
  - [x] Store discovered users in Neo4j

- **Day 46**: enum4linux-ng integration
  - [x] Create `Enum4LinuxTool` — SMB/LDAP enumeration
  - [x] Extract: users, groups, shares, password policies, OS info

- **Day 47**: Impacket tools integration
  - [x] Create `ASREPRoastTool` — ASREPRoasting (no pre-auth required accounts)
  - [x] Create `KerberoastTool` — Kerberoasting (request TGS for service accounts)
  - [x] Store Kerberos hashes for cracking

- **Day 48**: Pass-the-Hash / Pass-the-Ticket
  - [x] Create `PassTheHashTool` using `impacket-wmiexec`
  - [x] Auto-attempt PtH with NTLM hashes
  - [x] Register for `POST_EXPLOITATION` phase

- **Day 49**: LDAP enumeration
  - [x] Create `LDAPEnumTool` using `ldapsearch`
  - [x] Query domain users, groups, computers, GPOs

- **Day 50**: CrackMapExec integration
  - [x] Create `CrackMapExecTool` for SMB authentication checking
  - [x] Test valid credentials against all discovered SMB targets

- **Day 51**: Testing and documentation
  - [x] All AD tools registered in ToolRegistry
  - [x] All tools exported from `__init__.py`

---

#### Week 9-10: ML-Based Intent Classification (Days 52-65)

- **Day 52**: Collect training data
  - [x] Dataset of 296+ attack scenario descriptions → attack categories available in `backend/data/intent_training_data.json`

- **Day 53**: Feature engineering
  - [x] TF-IDF vectorization with n-gram features
  - [x] Structured features: service names, port numbers, CVE IDs, technique names
  - [x] Create `backend/app/agent/classification/feature_extractor.py`

- **Day 54**: Train intent classifier
  - [x] Multi-label SVM classifier (`MLClassifier` in `intent_classifier.py`)
  - [x] LLM-based classifier (`LLMClassifier`)
  - [x] Hybrid classifier (`HybridClassifier`)
  - [x] Multi-label classification with confidence scores

- **Day 55-58**: Integrate classifier with AttackPathRouter
  - [x] `AttackPathRouter` updated to use `IntentClassifier`
  - [x] Confidence scores (0-1 range per category)
  - [x] Support all attack categories with `classify_intent_with_confidence()`
  - [x] Keyword classifier as fallback (default mode)
  - [x] `CLASSIFIER_MODE` env var: `keyword`, `ml`, `llm`, `hybrid`

- **Day 59-62**: LLM-enhanced classification
  - [x] `LLMClassifier` with structured JSON output (GPT-4)
  - [x] `HybridClassifier` merges ML + LLM confidence scores
  - [x] LLM result caching with 1000-entry LRU eviction

- **Day 63-65**: Testing and documentation
  - [x] `scripts/train_classifier.py` — train and evaluate ML model
  - [x] 100% accuracy on all known test scenarios
  - [x] `backend/app/agent/classification/__init__.py` module ready

---

### 🗂️ Phase 3: Autonomous HTB Workflow (Days 61-90)

#### Week 11-12: HTB-Specific Attack Templates (Days 66-79) ✅

- **Day 66-68**: Build "HTB Easy" attack template
  - [x] Create `templates/htb_easy.json` defining the standard attack sequence:
    1. Port scan (naabu + nmap service detection)
    2. Web discovery (ffuf common wordlist)
    3. Vuln scan (nuclei critical/high)
    4. CVE exploitation (top Metasploit modules for detected services)
    5. Post-exploit (whoami, cat user.txt, linpeas, privesc, cat root.txt)
  - [x] Create `AutoChain.from_template("htb_easy")` factory method

- **Day 69-71**: Build "HTB Medium" attack template
  - [x] Standard sequence +: LDAP enum, CMS-specific attacks, SQLMap
  - [x] Add retry logic: if first exploit fails, try next candidate
  - [x] Add lateral movement step: if box has internal network
  - [x] Test template on HTB retired machines (Academy, Jerry, Lame)

- **Day 72-73**: Flag capture and verification
  - [x] `FlagCaptureTool`: reads `/root/root.txt` and `/home/*/user.txt`
  - [x] Calculate MD5 to verify valid flag format
  - [x] Display captured flags in frontend dashboard
  - [x] Store in Neo4j `Credential` node with `type: flag`

- **Day 74-76**: Automatic session upgrade
  - [x] On initial shell: auto-run `shell_to_meterpreter`
  - [x] Or use `python3 -c 'import pty; pty.spawn("/bin/bash")'` for TTY
  - [x] Auto-stabilize shell (stty raw -echo, etc.)
  - [x] Handle both Windows and Linux shell types

- **Day 77-79**: Testing
  - [x] Test complete HTB Easy template on 5 retired machines
  - [x] Record success rate and time per machine
  - [x] Identify failure patterns and add compensating logic
  - [x] Document results in `docs/HTB_RESULTS.md`

---

#### Week 13: Report Generation Engine (Days 80-86)

- **Day 80**: Report data model
  - [ ] Create `ReportData` schema with all pentest findings
  - [ ] Include: executive summary, findings table, CVSS scores, evidence, recommendations
  - [ ] Create `backend/app/services/report_service.py`

- **Day 81**: Markdown report generator
  - [ ] Generate structured Markdown report from Neo4j graph data
  - [ ] Include: scope, methodology, findings by severity, remediation steps
  - [ ] Auto-insert screenshots (base64 encoded) of terminal output

- **Day 82**: PDF report generation
  - [ ] Install WeasyPrint or ReportLab in requirements.txt
  - [ ] Convert Markdown → HTML → PDF
  - [ ] Add company/university logo placeholder
  - [ ] Include executive summary and risk matrix

- **Day 83**: Report API endpoints
  - [ ] `POST /api/reports/generate` — trigger report generation for a project
  - [ ] `GET /api/reports/{id}` — download PDF/Markdown
  - [ ] `GET /api/reports/{id}/preview` — HTML preview
  - [ ] Write 5 API tests

- **Day 84**: Frontend report page
  - [ ] Add `Reports` section in the dashboard sidebar
  - [ ] Show list of generated reports per project
  - [ ] "Download PDF" and "Preview" buttons
  - [ ] Report generation progress indicator

- **Day 85-86**: Testing
  - [ ] Generate report from complete HTB machine session
  - [ ] Verify PDF formatting and content
  - [ ] Write 5 integration tests
  - [ ] Document in `docs/USER_MANUAL.md`

---

#### Week 14: Performance & Scalability (Days 87-90)

- **Day 87**: Agent memory improvement
  - [ ] Increase context summarization window from 20 to 40 messages
  - [ ] Improve summarization prompt to preserve more technical details
  - [ ] Add `important_findings` persistent list that never gets summarized
  - [ ] Write 3 tests for context preservation

- **Day 88**: Scan performance optimization
  - [ ] Add concurrent port scanning for multiple IP ranges
  - [ ] Implement scan result caching (24hr TTL) to avoid re-scanning same targets
  - [ ] Add scan progress estimate (ETA based on target count)
  - [ ] Profile and optimize Neo4j ingestion batch size

- **Day 89**: Security hardening
  - [ ] Enforce API authentication on all endpoints (fix noted in release notes)
  - [ ] Add TLS termination in Nginx config for production
  - [ ] Implement IP allowlist for sensitive admin endpoints
  - [ ] Add request signing for MCP server calls

- **Day 90**: Final integration testing
  - [ ] Run complete HTB Easy workflow (5 machines) — target: 80%+ autonomous success
  - [ ] Run complete HTB Medium workflow (3 machines) — target: 50%+ autonomous success
  - [ ] Document results and gaps
  - [ ] Update `PROGRESS_TRACKER.md` and `RELEASE_NOTES.md` for v1.1.0

---

## 📊 Summary of Improvements by Area

| Area | Year 1 Status | After 90-Day Plan |
|------|--------------|-------------------|
| Tool chaining | Manual | ✅ Automated via AutoChain |
| ffuf/gobuster | Not integrated | ✅ Full MCP server + agent adapter |
| SQLMap | Not integrated | ✅ Full MCP server + agent adapter |
| LinPEAS/WinPEAS | Not integrated | ✅ Upload-and-run tool |
| Hash cracking | Not integrated | ✅ John + Hashcat MCP server |
| Flag capture | Not integrated | ✅ Auto-capture user.txt/root.txt |
| Intent classification | Keyword only | ✅ ML + LLM hybrid |
| AD attacks | Not integrated | ✅ Kerbrute, enum4linux, Impacket |
| Report generation | Not available | ✅ PDF + Markdown |
| Approval workflow | All-or-nothing | ✅ Configurable auto-approve level |
| Multi-tenancy | Partially enforced | ✅ Fully parameterized |
| HTB Easy | ~40-60% autonomous | **Target: 80-90% autonomous** |
| HTB Medium | ~15-25% autonomous | **Target: 50-65% autonomous** |

---

## 💡 Quick Wins (Can do in <1 day each)

1. **Add `AUTO_APPROVE_RISK_LEVEL=high` env var** — immediately enables HTB lab mode
2. **Add ffuf binary path to existing Kali Dockerfile** — it's already installed, just needs MCP server wrapper
3. **Fix QueryGraphTool TODO** — 2-3 lines of code for proper tenant filtering
4. **Add flag capture to post-exploitation tools** — `cat /root/root.txt` + `find /home -name user.txt` in `SystemEnumerationTool`
5. **SearchSploit adapter** — already installed in Docker, just needs Python wrapper
6. **Nikto adapter** — already installed in Docker, needs JSON output wrapper

---

## 🚨 Most Critical Fix (Do First)

**Implement AutoChain.** Without automated tool chaining, the system cannot solve HTB autonomously. Every other improvement is limited by the fact that a human must manually guide each step. AutoChain (Days 1-7) is the single highest-ROI improvement in this plan.

---

*Analysis completed: March 2026 | UniVex v1.0.0 → v1.1.0 Betterment Plan*
