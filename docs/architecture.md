# Chaos Kitten Architecture 🏗️

This document explains the internal architecture of Chaos Kitten.

## Overview

Chaos Kitten is built with a modular architecture consisting of four main components:

```
┌─────────────────────────────────────────────────────────┐
│                     Chaos Kitten                         │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐      ┌──────────────┐                 │
│  │   The Brain  │──────│  The Paws    │                 │
│  │ (Orchestrator)│      │  (Executor)  │                 │
│  └──────┬───────┘      └──────┬───────┘                 │
│         │                     │                          │
│         └─────────┬───────────┘                          │
│                   │                                      │
│         ┌─────────▼─────────┐                            │
│         │   The Toy Box     │                            │
│         │  (Attack Library) │                            │
│         └─────────┬─────────┘                            │
│                   │                                      │
│         ┌─────────▼─────────┐                            │
│         │  The Litterbox    │                            │
│         │   (Reporter)      │                            │
│         └───────────────────┘                            │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

## Components

### The Brain (`chaos_kitten/brain/`)

The Brain is the AI-powered orchestrator that coordinates all security testing.

**Modules:**

- `orchestrator.py` - Main agent logic using LangGraph
- `recon.py` - Reconnaissance engine (subdomain enumeration, port scanning, fingerprinting)
- `openapi_parser.py` - Parse OpenAPI/Swagger specs
- `attack_planner.py` - Chain-of-Thought attack planning

**How it works:**

1. **Reconnaissance:** Discover subdomains, open ports, and technologies (optional)
2. Parse the OpenAPI spec to understand API structure
3. For each endpoint, reason about potential vulnerabilities
4. Select appropriate attack profiles from the Toy Box
5. Coordinate with the Paws to execute attacks
6. Analyze responses and adapt strategy

### The Paws (`chaos_kitten/paws/`)

The Paws execute the actual attack requests.

**Modules:**

- `executor.py` - Async HTTP client using httpx
- `browser.py` - Playwright integration for XSS testing

**Features:**

- Async/concurrent requests
- Rate limiting to avoid DoS
- Multiple authentication methods
- Response timing analysis

### The Toy Box (`toys/`)

YAML/JSON files containing attack payloads and profiles.

**Structure:**

```
toys/
├── sql_injection_basic.yaml
├── xss_reflected.yaml
├── idor.yaml
└── data/
    ├── naughty_strings.json
    └── common_passwords.txt
```

**Why YAML?**

- Easy for beginners to contribute
- Human-readable
- No coding required

### The Litterbox (`chaos_kitten/litterbox/`)

Generates beautiful security reports.

**Modules:**

- `reporter.py` - Report generation logic
- `templates/` - Jinja2 templates

**Output formats:**

- HTML (beautiful, shareable)
- Markdown (for docs/PRs)
- JSON (for CI/CD integration)

## Data Flow

```
1. User runs: chaos-kitten scan
           │
           ▼
2. Config loaded from chaos-kitten.yaml
           │
           ▼
3. OpenAPI spec parsed by Brain
           │
           ▼
4. Attack profiles loaded from Toy Box
           │
           ▼
5. For each endpoint:
   ├── Brain plans attacks
   ├── Paws executes requests
   ├── Brain analyzes responses
   └── Vulnerabilities recorded
           │
           ▼
6. Litterbox generates report
           │
           ▼
7. Report saved to ./reports/
```

## LLM Integration

Chaos Kitten uses LLMs for intelligent reasoning:

```python
# Example: Reasoning about a field
prompt = f"""
I'm testing an API endpoint with this field:
- Name: {field_name}
- Type: {field_type}
- Required: {is_required}

What security tests should I perform?
"""
```

**Supported providers:**

- Anthropic Claude (recommended)
- OpenAI GPT-4
- Ollama (local, free)

## Extension Points

Want to extend Chaos Kitten? Here's where:

1. **New attack types** → Add YAML in `toys/`
2. **New parsers** → Add to `brain/`
3. **New output formats** → Add to `litterbox/`
4. **New executors** → Add to `paws/`

## Technology Choices

| Component | Technology | Why |
|-----------|------------|-----|
| HTTP Client | httpx | Async, modern, Python 3 |
| Browser | Playwright | Cross-browser, reliable |
| Agent Framework | LangGraph | Stateful, flexible |
| CLI | Typer + Rich | Beautiful output |
| Templates | Jinja2 | Standard, powerful |
| Config | YAML | Human-readable |
