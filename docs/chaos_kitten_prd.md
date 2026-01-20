# Chaos Kitten - Product Requirements Document (PRD)

## Project Overview
**Project Name:** Chaos Kitten  
**Tagline:** The adorable AI agent that knocks things off your API tables  
**Category:** Cloud Native Security & API Testing  
**Target:** Aperture 3.0 by Resourcio Community  

---

## 1. Vision & Problem Statement

### The Problem
AI-powered "vibe coding" tools (Claude, Cursor, Windsurf) generate backend APIs at incredible speed, but they often skip critical security measures:
- Missing authentication/authorization
- No input validation
- Vulnerable to SQL injection, XSS, and other OWASP Top 10 attacks
- Logic flaws that allow unauthorized access

**Real-world example:** While building Bondhu (AI mental health startup), we discovered our AI-generated backend had ZERO authentication on critical endpoints. Anyone could access user data.

### The Solution
Chaos Kitten is an **agentic security testing tool** that acts like a mischievous cat—it explores your API, understands the business logic, and systematically tries to "break" things before malicious actors do.

Unlike traditional fuzzers (ZAP, Burp) that spray random payloads, Chaos Kitten **reasons** about your API structure and crafts intelligent attacks.

---

## 2. Core Features (MVP for Aperture 3.0)

### 2.1 The Brain (Agentic Orchestrator)
**Tech Stack:** Python, LangGraph/PydanticAI, OpenAI/Anthropic API (with local LLM fallback)

**Capabilities:**
- Parse OpenAPI/Swagger specifications
- Understand endpoint semantics (e.g., "This is a login endpoint, I should test for SQL injection and user enumeration")
- Plan multi-step attack chains using Chain-of-Thought reasoning
- Learn from responses and adapt strategies

**Example Reasoning:**
```
Field: "age" (integer)
Agent Thought: "I'll test negative numbers, zero, extremely large values, and strings"

Field: "price" (float)  
Agent Thought: "I'll test negative prices, zero, NaN, and inject SQL strings"
```

### 2.2 The Paws (Attack Executor)
**Tech Stack:** Python `httpx` (async), Playwright (for XSS validation)

**Capabilities:**
- Execute HTTP requests asynchronously
- Support for various authentication methods (Bearer, Basic, OAuth)
- Headless browser integration for client-side validation
- Rate limiting and politeness controls (respect target systems)

### 2.3 The Litterbox (Reporting Engine)
**Tech Stack:** Jinja2 templates, Markdown, HTML

**Capabilities:**
- Generate vulnerability reports with severity ratings
- Provide **Proof of Concept (PoC)** curl commands
- Include **remediation suggestions** (e.g., "Wrap this in a parameterized query")
- Playful language: "I knocked this vase over! 💥 (500 Error on negative age)"

### 2.4 The Toy Box (Attack Library)
**Structure:** `/toys/` folder with YAML/JSON files

**Examples:**
- `toys/sql_injection_basic.yaml`
- `toys/xss_reflected.yaml`
- `toys/idor_sequential.yaml`
- `toys/naughty_strings.json`

**Student-Friendly:** First-timers can contribute by just adding payloads to these files—no coding required.

---

## 3. Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     Chaos Kitten                         │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐      ┌──────────────┐                 │
│  │   The Brain  │──────│  The Paws    │                 │
│  │ (Orchestrator)│      │  (Executor)  │                 │
│  │              │      │              │                 │
│  │ - OpenAPI    │      │ - httpx      │                 │
│  │   Parser     │      │ - Playwright │                 │
│  │ - LLM Agent  │      │ - Async      │                 │
│  └──────┬───────┘      └──────┬───────┘                 │
│         │                     │                          │
│         └─────────┬───────────┘                          │
│                   │                                      │
│         ┌─────────▼─────────┐                            │
│         │   The Toy Box     │                            │
│         │  (Attack Library) │                            │
│         │                   │                            │
│         │ - SQL Injection   │                            │
│         │ - XSS Payloads    │                            │
│         │ - Naughty Strings │                            │
│         └─────────┬─────────┘                            │
│                   │                                      │
│         ┌─────────▼─────────┐                            │
│         │  The Litterbox    │                            │
│         │   (Reporter)      │                            │
│         │                   │                            │
│         │ - HTML Reports    │                            │
│         │ - PoC Scripts     │                            │
│         │ - Remediation     │                            │
│         └───────────────────┘                            │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Technical Specifications

### 4.1 Repository Structure
```
chaos-kitten/
├── README.md
├── LICENSE (MIT)
├── CONTRIBUTING.md
├── pyproject.toml
├── .env.example
├── chaos_kitten/
│   ├── __init__.py
│   ├── brain/
│   │   ├── __init__.py
│   │   ├── orchestrator.py      # Main agent logic
│   │   ├── openapi_parser.py    # Parse specs
│   │   └── attack_planner.py    # Chain-of-thought planning
│   ├── paws/
│   │   ├── __init__.py
│   │   ├── executor.py          # HTTP client
│   │   └── browser.py           # Playwright integration
│   ├── litterbox/
│   │   ├── __init__.py
│   │   ├── reporter.py          # Report generation
│   │   └── templates/
│   │       ├── report.html
│   │       └── report.md
│   └── utils/
│       ├── __init__.py
│       └── config.py
├── toys/
│   ├── sql_injection_basic.yaml
│   ├── xss_reflected.yaml
│   ├── idor.yaml
│   └── data/
│       └── naughty_strings.json
├── tests/
│   ├── test_brain.py
│   ├── test_paws.py
│   └── test_integration.py
├── examples/
│   ├── demo_api/              # Sample vulnerable API
│   └── sample_openapi.json
└── docs/
    ├── getting_started.md
    ├── architecture.md
    └── contributing_guide.md
```

### 4.2 Configuration File (`chaos-kitten.yaml`)
```yaml
target:
  base_url: "http://localhost:3000"
  openapi_spec: "./openapi.json"
  auth:
    type: "bearer"  # bearer, basic, oauth, none
    token: "${API_TOKEN}"

agent:
  llm_provider: "anthropic"  # anthropic, openai, ollama
  model: "claude-3-5-sonnet-20241022"
  temperature: 0.7
  max_iterations: 10

executor:
  concurrent_requests: 5
  timeout: 30
  rate_limit: 10  # requests per second

safety:
  allowed_domains:
    - "localhost"
    - "*.test.com"
  destructive_mode: false  # If true, allows DROP/DELETE operations

toys:
  enabled:
    - "sql_injection"
    - "xss"
    - "idor"
  disabled:
    - "dos"  # Disabled for safety

reporting:
  format: "html"  # html, markdown, json
  output_path: "./reports"
  include_poc: true
  include_remediation: true
```

### 4.3 Example Attack Profile (YAML)
```yaml
# toys/sql_injection_basic.yaml
name: "SQL Injection - Basic"
category: "injection"
severity: "critical"
description: "Tests for classic SQL injection vulnerabilities"

target_fields:
  - "username"
  - "email"
  - "login"
  - "search"
  - "id"

payloads:
  - "' OR '1'='1"
  - "' OR 1=1 --"
  - "admin' --"
  - "' UNION SELECT NULL--"
  - "1' AND 1=1--"

success_indicators:
  - "SQL syntax error"
  - "mysql_fetch"
  - "PostgreSQL error"
  - "SQLite error"
  - status_code: 500

remediation: |
  Use parameterized queries or prepared statements.

  Example (Python):
  # Bad
  query = f"SELECT * FROM users WHERE username='{username}'"

  # Good
  query = "SELECT * FROM users WHERE username=%s"
  cursor.execute(query, (username,))
```

---

## 5. User Workflows

### 5.1 Basic Usage
```bash
# Install
pip install chaos-kitten

# Initialize config
chaos-kitten init

# Run against local API
chaos-kitten scan --config chaos-kitten.yaml

# Output
🐱 Chaos Kitten v1.0.0
📋 Parsing OpenAPI spec...
🎯 Found 12 endpoints
🧠 Planning attack strategies...

🐾 Testing /api/login
   ⚠️  I knocked this vase over! (SQL Injection found)

🐾 Testing /api/users/{id}
   ⚠️  I played with this string! (IDOR vulnerability)

📊 Report saved to ./reports/chaos-kitten-2026-01-20.html
```

### 5.2 CI/CD Integration
```yaml
# .github/workflows/security-test.yml
name: Chaos Kitten Security Scan

on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start API
        run: docker-compose up -d
      - name: Run Chaos Kitten
        run: |
          pip install chaos-kitten
          chaos-kitten scan --fail-on-critical
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: ./reports/
```

---

## 6. Contribution Strategy (Hackathon-Ready)

### 6.1 First-Timer Issues (No Coding)
- **Add Naughty Strings:** Edit `toys/data/naughty_strings.json`
- **Add Common Passwords:** Edit `toys/data/common_passwords.txt`
- **Improve Docs:** Fix typos, add examples

### 6.2 Beginner Issues (Basic Python)
- **Create Attack Profile:** Write a new YAML file in `/toys`
- **Add Test Cases:** Write unit tests for specific payloads
- **CLI Improvements:** Add color to terminal output

### 6.3 Intermediate Issues (Agent Logic)
- **Implement New Attack:** Code a new attack strategy (e.g., JWT manipulation)
- **Improve Parser:** Add support for GraphQL schemas
- **Browser Automation:** Enhance XSS detection with Playwright

### 6.4 Advanced Issues (Core Features)
- **Multi-step Exploits:** Implement chained attacks (e.g., IDOR → privilege escalation)
- **LLM Optimization:** Improve prompt engineering for better reasoning
- **Kubernetes Operator:** Deploy as a K8s CronJob

---

## 7. CNCF Alignment & Future Roadmap

### Phase 1 (Aperture 3.0 - MVP)
- ✅ OpenAPI parsing
- ✅ Basic SQL injection, XSS, IDOR detection
- ✅ HTML/Markdown reporting
- ✅ CLI tool

### Phase 2 (Post-Hackathon)
- 🔄 GraphQL support
- 🔄 gRPC/Protobuf support
- 🔄 WebSocket testing
- 🔄 GitHub Action integration

### Phase 3 (CNCF Sandbox Application)
- 🚀 Kubernetes Operator
- 🚀 Service Mesh integration (Istio/Linkerd)
- 🚀 Real-time dashboard
- 🚀 Policy-as-Code (OPA integration)

### CNCF Category
**Cloud Native Security** (similar to Falco, Trivy, OPA)

**Differentiation:**  
While existing tools are *passive* (scan for known vulnerabilities), Chaos Kitten is *active* (attempts to exploit them like a real attacker).

---

## 8. Success Metrics (Aperture 3.0)

### Hackathon Goals
- 🎯 50+ contributors
- 🎯 100+ GitHub stars
- 🎯 20+ attack profiles in `/toys`
- 🎯 Working demo video
- 🎯 Clean documentation

### Technical Goals
- ✅ Successfully detect 5+ OWASP Top 10 vulnerabilities
- ✅ 80% test coverage
- ✅ Sub-5 minute scan for typical API (10-20 endpoints)
- ✅ Zero false positives on test suite

---

## 9. Safety & Ethics

### Built-in Safeguards
1. **Allowlist-Only:** Won't scan domains not in `allowed_domains`
2. **Rate Limiting:** Respects server resources
3. **Non-Destructive Default:** `destructive_mode: false` prevents DROP/DELETE
4. **Logging:** All actions logged for audit trail

### Legal Disclaimer (README)
```
⚖️ LEGAL NOTICE
Chaos Kitten is intended for testing YOUR OWN applications or systems 
where you have explicit permission. Unauthorized access to computer 
systems is illegal. Users are responsible for compliance with applicable 
laws. The developers assume no liability for misuse.
```

---

## 10. Marketing & Positioning

### Tagline Options
1. "The adorable AI agent that knocks things off your API tables"
2. "Breaking your code before hackers do"
3. "The Red Team for the Vibe Coding Era"

### Target Audience
- **Primary:** Indie developers, startups using AI code generation
- **Secondary:** DevSecOps teams, security researchers
- **Tertiary:** Students learning security testing

### Competitive Positioning
| Tool | Type | Agentic? | Beginner-Friendly? |
|------|------|----------|-------------------|
| OWASP ZAP | Manual/Automated | ❌ | ❌ |
| Burp Suite | Manual | ❌ | ❌ |
| Nuclei | Template-based | ❌ | ⚠️ |
| **Chaos Kitten** | **AI Agent** | **✅** | **✅** |

---

## 11. Open Questions & Decisions Needed

1. **LLM Provider:** Should we default to Anthropic Claude, OpenAI, or Ollama (local)?
2. **Pricing:** Free forever? Freemium with cloud version?
3. **Name:** Is "Chaos Kitten" too playful for enterprise adoption?
4. **License:** MIT vs Apache 2.0?

---

## Appendix A: Example Vulnerabilities to Detect

### OWASP Top 10 (MVP Coverage)
- ✅ A01: Broken Access Control (IDOR)
- ✅ A02: Cryptographic Failures (weak tokens)
- ✅ A03: Injection (SQL, NoSQL, Command)
- ✅ A04: Insecure Design (logic flaws)
- ⚠️ A05: Security Misconfiguration (partial)
- ❌ A06: Vulnerable Components (future)
- ❌ A07: Authentication Failures (future)
- ✅ A08: Data Integrity Failures (mass assignment)
- ⚠️ A09: Logging Failures (partial)
- ❌ A10: SSRF (future)

---

## Appendix B: Sample Report Output

```
🐱 Chaos Kitten Security Report
Generated: 2026-01-20 23:15:00 IST

📊 Summary
- Endpoints Tested: 12
- Vulnerabilities Found: 3 Critical, 2 High, 1 Medium
- Time Taken: 2m 34s

🚨 Critical Vulnerabilities

1. SQL Injection in /api/login
   Severity: CRITICAL

   I knocked this vase over! 💥

   The 'username' field accepts SQL metacharacters.

   Proof of Concept:
   curl -X POST http://localhost:3000/api/login      -d "username=admin' OR '1'='1&password=anything"

   Response: HTTP 200 (Authenticated as admin)

   🔧 Remediation:
   Use parameterized queries:
   cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
```

---

**Document Version:** 1.0  
**Last Updated:** January 20, 2026  
**Author:** [Your Name] - Bondhu Tech  
**Contact:** [Your Email]
