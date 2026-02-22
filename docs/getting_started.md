# Getting Started with Chaos Kitten 🐱

Welcome to Chaos Kitten! This guide will help you get up and running quickly.

## Prerequisites

- Python 3.10 or higher
- An API to test (preferably a local development server)
- An LLM API key (Anthropic or OpenAI)

## Installation

### Option 1: pip (Recommended)

```bash
pip install chaos-kitten
```

### Option 2: From Source

```bash
git clone https://github.com/mdhaarishussain/chaos-kitten.git
cd chaos-kitten
pip install -e .        # Standard install (no browser)
# Optional: browser exploit validation
pip install -e .[browser]
playwright install chromium
```

### Option 3: Docker (Recommended for Isolation)

To run Chaos Kitten in a containerized environment (ensuring all dependencies, including browsers for XSS testing, are isolated):

**Using Docker Compose (Easiest)**

This spins up both the scanner and a vulnerable demo API:

```bash
# Set your API key environment variable first
export ANTHROPIC_API_KEY=your_key_here
# OR
export OPENAI_API_KEY=your_key_here

# Start the demo environment
docker-compose up -d demo-api

# Run a scan against the demo API
docker-compose run chaos-kitten scan --demo
```

**Using Standalone Docker**

Build the image:
```bash
docker build -t chaos-kitten .
```

Run a scan (mounting your current directory for config and reports):
```bash
docker run --rm \
  -v $(pwd)/chaos-kitten.yaml:/app/chaos-kitten.yaml \
  -v $(pwd)/reports:/app/reports \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  chaos-kitten scan
```

## Quick Start

### 1. Initialize Configuration

```bash
chaos-kitten init
```

This creates a `chaos-kitten.yaml` configuration file.

### 2. Edit Configuration

Open `chaos-kitten.yaml` and update:

```yaml
target:
  base_url: "http://localhost:3000"  # Your API URL
  openapi_spec: "./openapi.json"      # Path to OpenAPI spec

agent:
  llm_provider: "anthropic"
  model: "claude-3-5-sonnet-20241022"
```

### 3. Set API Key

Create a `.env` file:

```bash
ANTHROPIC_API_KEY=your_key_here
```

### 4. Run a Scan

```bash
chaos-kitten scan
```

### 5. Use Natural Language Targeting (Optional)

The `--goal` flag lets you describe what you want to test in plain English. Chaos Kitten's LLM will automatically select relevant endpoints and attack profiles based on your goal.

**Example 1: Payment Security**
```bash
chaos-kitten scan --goal "find all endpoints that handle money or payments and check if prices can be manipulated"
```

**Example 2: Access Control**
```bash
chaos-kitten scan --goal "I want to check if admin endpoints are accessible to regular users"
```

**Example 3: Authentication Testing**
```bash
chaos-kitten scan --goal "test the authentication system for account takeover risks"
```

Without `--goal`, Chaos Kitten runs a full scan testing all endpoints. With `--goal`, the LLM prioritizes endpoints relevant to your security concern.

## Understanding Results

### Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| CRITICAL | 🔴 | Immediate action required |
| HIGH | 🟠 | Should be fixed soon |
| MEDIUM | 🟡 | Should be addressed |
| LOW | 🟢 | Minor issues |

### Sample Output

```
🐱 Chaos Kitten v1.0.0
📋 Parsing OpenAPI spec...
🎯 Found 12 endpoints

🐾 Testing /api/login
   ⚠️  I knocked this vase over! (SQL Injection)
   Severity: CRITICAL
```

## Next Steps

- [Architecture Overview](./architecture.md)
- [Configuration Reference](./configuration.md)
- [Contributing Guide](../CONTRIBUTING.md)

## Need Help?

- Open an [Issue](https://github.com/mdhaarishussain/chaos-kitten/issues)
- Join our [Discussions](https://github.com/mdhaarishussain/chaos-kitten/discussions)

## CI/CD Integration

Integrate Chaos Kitten into your CI/CD pipeline to catch vulnerabilities early.

### GitHub Actions

We provide a ready-to-use GitHub Actions workflow.

1. Create `.github/workflows/security-scan.yml`
2. Copy the content from `examples/github-actions-workflow.yml`
3. Configure secrets in your repository settings

### GitLab CI/CD

Add this job to your `.gitlab-ci.yml`:

```yaml
security_scan:
  image: python:3.12
  script:
    - pip install chaos-kitten
    - chaos-kitten scan --target $STAGING_URL --format junit --output reports --fail-on high --silent
  artifacts:
    reports:
      junit: reports/*.xml
```

### CLI Flags for CI

- `--format sarif`: Generates SARIF output for GitHub Advanced Security
- `--format junit`: Generates XML output for CI test parsers
- `--fail-on [medium|high|critical]`: Sets the exit code to 1 if vulnerabilities of this level or higher are found
- `--silent`: Suppresses non-error console output

