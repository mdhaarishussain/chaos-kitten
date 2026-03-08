# Business Logic Framework - Integration Guide

## For Developers

### Adding New Business Logic Attack Types

To extend the framework with new attack types:

1. **Define the Attack Type**

```python
# In business_logic_attacker.py
class BusinessLogicAttackType(Enum):
    """Types of business logic attacks."""
    
    RACE_CONDITION = "race-condition"
    WORKFLOW_BYPASS = "workflow-bypass"
    AUTHORIZATION_BYPASS = "authorization"
    PRICE_MANIPULATION = "payment"
    # ADD NEW TYPE HERE
    INVENTORY_MANIPULATION = "inventory"
```

2. **Create Attack Profile YAML**

```yaml
# toys/inventory_manipulation.yaml
name: "Inventory Manipulation"
category: "business-logic"
severity: "high"
description: "Tests for inventory over-selling or stock manipulation"
attack_type: "inventory"
requires_concurrency: true
concurrent_requests: 5

target_fields:
  - "quantity"
  - "stock"
  - "available"

payloads:
  - "-1000"
  - "999999"
  - "-1"
```

3. **Implement Detection Method**

```python
# In business_logic_attacker.py
async def test_inventory_manipulation(
    self, 
    endpoint: dict[str, Any], 
    profile: Any
) -> list[BusinessLogicVulnerability]:
    """Test for inventory manipulation vulnerabilities."""
    if not self.executor:
        return []
    
    vulnerabilities = []
    # Implementation here
    return vulnerabilities
```

4. **Wire into test_endpoint**

```python
async def test_endpoint(self, endpoint: dict[str, Any], profile: Any):
    """Test an endpoint for business logic vulnerabilities."""
    vulnerabilities = []
    attack_type = profile.attack_type.lower()
    
    if attack_type == "inventory":
        vulns = await self.test_inventory_manipulation(endpoint, profile)
        vulnerabilities.extend(vulns)
    # ... other types
```

5. **Add Test Coverage**

```python
# In tests/test_business_logic.py
class TestInventoryManipulation:
    """Test inventory manipulation detection."""
    
    @pytest.mark.asyncio
    async def test_inventory_depletion(
        self, business_logic_attacker, sample_endpoint, mock_inventory_profile
    ):
        """Test detection of inventory manipulation."""
        # Implementation
```

### Customizing Concurrent Request Behavior

The framework supports customizable concurrent request execution:

```python
# Modify concurrent request strategy
profile.concurrent_requests = 20  # Increase concurrency
profile.timing_sensitive = True   # Reduce delays
profile.concurrent_requests = 2   # Reduce for sensitive endpoints

# Custom timing in profiles
concurrent_execution:
  requests_count: 10
  delay_between_ms: 50
  timeout_seconds: 45
  burst_pattern: "all_at_once"  # or "staggered"
```

### Extending State Transition Validation

Add complex state machine validation:

```python
# In attack profile
state_transitions:
  - name: "complex_workflow"
    # Define allowed transitions
    transitions:
      "initial":
        - "step1"
        - "step2"
      "step1":
        - "step2"
        - "final"
      "step2":
        - "final"
    # Define invalid transitions
    blocked_transitions:
      "initial":
        - "final"  # Can't skip to final
      "step1":
        - "initial"  # Can't go backward
```

## Architecture Overview

### Data Flow

```
OpenAPI Spec
    ↓
  Parser
    ↓
  Endpoints ────────────────────┐
    ↓                           │
  Attack Planner                │
    ├─→ Standard attacks   ├────┤
    │                       │   │
    └─→ BL profiles    ─────┤   │
                            │   │
                    Executor ←──┤
                    (HTTP)      │
                        ↓       │
              Response Analysis │
                ├─→ Standard     │
                └─→ Business     │
                    Logic ←──────┘
                        ↓
                    Reporter
                        ↓
                Report (HTML/MD)
```

### Class Relationships

```
AttackProfile
├─ name, category, severity
├─ payloads, target_fields
├─ Standard fields
└─ Business Logic Extension
   ├─ attack_type
   ├─ requires_state
   ├─ concurrent_requests
   ├─ timing_sensitive
   └─ state_transitions

BusinessLogicAttacker
├─ executor: Executor
├─ vulnerabilities: list
├─ test_race_condition()
├─ test_workflow_bypass()
├─ test_authorization_bypass()
├─ test_price_manipulation()
└─ test_endpoint()

Orchestrator
├─ parse_openapi()
├─ plan_attacks()
├─ execute_and_analyze()
├─ test_business_logic()  ← NEW
└─ report_generation()
```

## Testing Strategy

### Unit Tests

Test individual components:

```python
# Test race condition detection
async def test_race_condition_with_conflict():
    # Mock concurrent requests
    # Verify vulnerability detection
    # Check vulnerability properties

# Test workflow bypass detection  
async def test_workflow_bypass_bypassed():
    # Mock endpoint that accepts bypass
    # Verify vulnerability detection

# Test authorization bypass
async def test_auth_bypass_with_privilege_escalation():
    # Mock authorization check bypass
    # Verify detection
```

### Integration Tests

Test interaction between components:

```python
# Test multiple vulnerability types
async def test_multiple_attack_types():
    # Use different profiles
    # Verify each detected correctly

# Test orchestrator integration
async def test_orchestrator_with_business_logic():
    # Run full scan
    # Verify business logic findings included
```

### End-to-End Tests

Test complete workflow:

```python
# Against mock API
# Against demo application
# Against vulnerable samples
```

## Performance Optimization

### Reducing Scan Time

```python
# Skip expensive tests
profile.skip_timing_sensitive = True

# Reduce concurrent requests
profile.concurrent_requests = 3  # Default 5

# Target specific endpoints
# Only test POST, PUT, DELETE (state-changing)
if method in ["POST", "PUT", "DELETE"]:
    await test_business_logic(endpoint)
```

### Handling Rate Limiting

```python
# Built into Executor
executor.rate_limiter = RateLimiter(
    requests_per_second=10,
    burst_size=5
)

# Or in profile
rate_limit:
  delay_between_requests_ms: 100
  max_requests_per_minute: 60
```

### Parallel Endpoint Testing

The orchestrator already parallelizes testing:

```
Endpoint 1 ─┬─ Plan ─ Execute ─ Analyze ─ Test BL
            │
Endpoint 2 ─┼─ Plan ─ Execute ─ Analyze ─ Test BL
            │
Endpoint 3 ─┴─ Plan ─ Execute ─ Analyze ─ Test BL
```

## Debugging & Troubleshooting

### Enable Debug Logging

```python
import logging

logging.getLogger("chaos_kitten.brain.business_logic_attacker").setLevel(logging.DEBUG)

# View detailed test output
```

### Inspecting Vulnerabilities

```python
attacker = BusinessLogicAttacker(executor)
vulnerabilities = await attacker.test_endpoint(endpoint, profile)

for vuln in vulnerabilities:
    print(f"Type: {vuln.attack_type}")
    print(f"Endpoint: {vuln.endpoint}")
    print(f"Evidence: {vuln.evidence}")
```

### Profile Validation

```python
# Validate profile before testing
profile = attack_profiles[0]

assert profile.attack_type in [
    "race-condition",
    "workflow-bypass", 
    "authorization",
    "payment"
]

if profile.requires_concurrency:
    assert profile.concurrent_requests > 1
```

## Common Issues & Solutions

### Issue: Race condition not detected

**Causes**:
- Endpoint too fast (no true concurrency)
- Application has locks/transactions
- Insufficient concurrent requests

**Solutions**:
```yaml
# Increase concurrency
concurrent_requests: 20

# Add timing sensitivity
timing_sensitive: true

# Add delays to expose race condition
delay_between_requests_ms: 1000
```

### Issue: Workflow validation too strict

**Causes**:
- Application properly validates state
- Payloads don't match expected values

**Solutions**:
- Adjust payloads in profile
- Add state-tracking to profile
- Test against actual API responses

### Issue: Authorization detection false positives

**Causes**:
- Endpoint returns 200 for legit reasons
- Insufficient authorization checks

**Solutions**:
- Verify actual authorization state
- Check response body (not just status)
- Add evidence validation

## API Reference

### BusinessLogicAttacker

```python
class BusinessLogicAttacker:
    def __init__(self, executor: Any = None) -> None:
        """Initialize attacker."""
    
    async def test_race_condition(
        self,
        endpoint: dict[str, Any],
        profile: Any,
        concurrent_requests: int = 5,
    ) -> list[BusinessLogicVulnerability]:
        """Test for race conditions."""
    
    async def test_workflow_bypass(
        self,
        endpoint: dict[str, Any],
        profile: Any,
    ) -> list[BusinessLogicVulnerability]:
        """Test for workflow bypass."""
    
    async def test_authorization_bypass(
        self,
        endpoint: dict[str, Any],
        profile: Any,
    ) -> list[BusinessLogicVulnerability]:
        """Test for authorization bypass."""
    
    async def test_price_manipulation(
        self,
        endpoint: dict[str, Any],
        profile: Any,
    ) -> list[BusinessLogicVulnerability]:
        """Test for price manipulation."""
    
    async def test_endpoint(
        self,
        endpoint: dict[str, Any],
        profile: Any,
    ) -> list[BusinessLogicVulnerability]:
        """Test endpoint with profile."""
    
    def get_vulnerabilities(
        self
    ) -> list[BusinessLogicVulnerability]:
        """Get all detected vulnerabilities."""
    
    def clear_vulnerabilities(self) -> None:
        """Clear vulnerability list."""
```

### BusinessLogicVulnerability

```python
@dataclass
class BusinessLogicVulnerability:
    attack_type: BusinessLogicAttackType
    endpoint: str
    method: str
    vulnerability_name: str
    description: str
    severity: str
    evidence: list[dict[str, Any]]
    remediation: str
    proof_of_concept: str
    timestamp: str
```

## Contributing

To contribute new business logic attack types:

1. Create pull request with:
   - New attack type in `BusinessLogicAttackType` enum
   - YAML profile in `toys/`
   - Detection method in `BusinessLogicAttacker`
   - Unit tests in `tests/test_business_logic.py`
   - Documentation in `docs/`

2. Ensure:
   - >80% test coverage
   - All tests pass
   - Documentation is complete
   - Code follows project style

3. Submit PR with detailed description

## References

- [Business Logic Framework Documentation](./business_logic_framework.md)
- [OWASP Business Logic Testing]https://owasp.org/
- [CWE - Weaknesses](https://cwe.mitre.org/)
