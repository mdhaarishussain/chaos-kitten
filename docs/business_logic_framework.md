# Business Logic Vulnerability Detection Framework

## Overview

The Business Logic Vulnerability Detection Framework is an advanced security testing module that detects flaws in application workflow validation, state transitions, and authorization checks. Unlike traditional vulnerability scanners that focus on injection attacks and authentication bypasses, this framework identifies logic flaws that allow attackers to bypass normal business constraints.

## Architecture

### Core Components

```
chaos_kitten/brain/
├── business_logic_attacker.py    # Main detection engine
├── attack_planner.py              # Extended with BL profile support
└── orchestrator.py                # Concurrent orchestration
```

### Attack Profile Enhancement

Attack profiles now support business logic specific fields:

```yaml
# Extended profile schema
name: "Attack Name"
category: "business-logic"
severity: "critical|high|medium|low"
description: "Description"
attack_type: "race-condition|workflow-bypass|authorization|payment"
requires_state: boolean
requires_concurrency: boolean
concurrent_requests: integer
timing_sensitive: boolean
state_transitions: 
  - name: "transition_name"
    steps:
      - action: "HTTP_METHOD"
        target: "/endpoint"
        payload: {}
        required_previous: "previous_state"
```

## Vulnerability Types & Patterns

### 1. Race Condition Detection

**Description**: Detects race conditions in concurrent state modifications where improper locking allows multiple requests to corrupt shared state.

**Attack Profile**: `race_condition.yaml`

**How It Works**:
- Sends multiple concurrent requests to the same endpoint (configurable count)
- Tracks state changes between concurrent executions
- Identifies inconsistent responses or unexpected state values
- Checks for conflict errors (409) indicating race conditions

**Vulnerable Pattern**:
```python
# VULNERABLE: No locking mechanism
def transfer(amount):
    balance = get_balance()  # [1] Read balance = 100
    # Context switch - another request reads balance = 100
    balance -= amount        # [2] Both threads deduct from same base
    save_balance(balance)    # Result: balance should be reduced by 2x amount
```

**Detection Indicators**:
- State changes after concurrent requests don't match sequential execution
- 409 Conflict responses
- Inconsistent response statuses across concurrent requests
- Final state exceeds or falls below expected values

**Remediation**:
- Implement database transaction isolation levels (SERIALIZABLE)
- Use pessimistic locking (SELECT FOR UPDATE)
- Implement optimistic locking with version numbers
- Use distributed locks for cross-service state
- Apply idempotency tokens for critical operations

**OWASP Reference**: CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization

### 2. Workflow Bypass Detection

**Description**: Detects ability to skip required workflow steps and reach final states without proper validation.

**Attack Profile**: `workflow_bypass.yaml`

**How It Works**:
- Analyzes defined state transition requirements
- Attempts to directly access final workflow states
- Tests each payload against workflow endpoints
- Identifies successful state transitions that bypass intermediate steps

**Vulnerable Pattern**:
```python
# VULNERABLE: No validation of previous steps
@app.post("/checkout/confirm")
def confirm_order(order_id: str, status: str):
    # Directly sets order status without checking payment
    order.status = status  # Allows "shipped" without "paid"
    order.save()
```

**Detection Indicators**:
- Successfully reach final workflow states with 200/201 responses
- No enforcement of intermediate steps
- State changes accepted without prior state verification
- Ability to complete transactions without required validation

**Example Scenarios**:
1. **E-commerce**: Skipping payment step in checkout workflow
2. **Banking**: Marking transfer as complete without approval
3. **Content Management**: Publishing content without review
4. **User Management**: Approving account without email verification

**Remediation**:
- Implement explicit state machines with allowed transitions
- Validate current state before allowing state changes
- Enforce sequential state requirements
- Log all state transitions with timestamps
- Require authorization for each step
- Use immutable audit trails

**OWASP Reference**: A04:2021 – Insecure Design (Business Logic Flaws)

### 3. Authorization Bypass Detection

**Description**: Detects authorization flaws allowing privilege escalation and unauthorized action execution.

**Attack Profile**: `authorization_bypass.yaml`

**How It Works**:
- Tests role/permission fields with escalation payloads
- Attempts privilege escalation through request parameters
- Verifies whether authorization is enforced server-side
- Identifies flaws in access control logic

**Vulnerable Pattern**:
```python
# VULNERABLE: Trusts client-provided authorization
@app.post("/api/user/{user_id}/delete")
def delete_user(user_id: str, is_admin: bool = False):
    # Authorization based on parameter, not session/token
    if is_admin:
        user = User.get(user_id)
        user.delete()
```

**Detection Indicators**:
- Successfully execute admin operations with privilege escalation payloads
- 200 responses to unauthorized operations
- Access to protected resources without proper credentials
- Ability to modify other users' data

**Authorization Vulnerability Types**:
1. **Parameter-based Authorization**: `is_admin=true` in request
2. **Role Spoofing**: Setting `role=admin` directly
3. **Direct Reference**: Accessing `/user/another_id/profile`
4. **Forced Browsing**: Directly accessing admin endpoints
5. **Function-level Authorization**: Skipping authorization checks

**Remediation**:
- Implement server-side authorization checks
- Use role-based access control (RBAC)
- Implement attribute-based access control (ABAC)
- Never trust client-provided authorization claims
- Use secure session management
- Implement authorization middleware
- Log all authorization attempts
- Maintain principle of least privilege

**OWASP Reference**: A01:2021 – Broken Access Control

### 4. Price/Discount Manipulation

**Description**: Detects pricing logic flaws allowing financial fraud through manipulation of prices and discounts.

**Attack Profile**: `price_manipulation.yaml`

**How It Works**:
- Attempts to manipulate price fields with invalid values
- Tests negative prices, zero amounts, and extreme values
- Verifies server-side price validation
- Identifies transactions processed with invalid pricing

**Vulnerable Pattern**:
```python
# VULNERABLE: Price calculated and stored from client input
@app.post("/order/checkout")
def create_order(cart_item: CartItem):
    order = Order(
        price=cart_item.price,  # Client controls price!
        quantity=cart_item.quantity
    )
    order.save()
```

**Detection Indicators**:
- Orders created with negative or zero prices
- Successful payment for manipulated amounts
- 200/201 responses with invalid pricing
- Discounts exceeding 100%
- Refunds larger than original amounts

**Price Manipulation Scenarios**:
1. **Negative Pricing**: Seller pays buyer for purchase
2. **Zero Pricing**: Free items from paid products
3. **Extreme Discounts**: Coupons enabling free shopping
4. **Quantity Manipulation**: Negative quantities for refunds
5. **Currency Manipulation**: Price in different currency
6. **Decimal Precision Abuse**: Price truncation tricks

**Remediation**:
- **Always** calculate prices server-side
- Validate prices against product catalog
- Enforce non-negative constraints in database
- Use database decimal/numeric types
- Log all price changes
- Implement price verification against base catalog
- Require manager approval for price adjustments
- Use cryptographic signatures for order prices
- Implement transaction reversal procedures
- Regular financial audits and reconciliation
- Monitor for suspicious pricing patterns

**OWASP Reference**: CWE-1025: Comparison Using Wrong Factors (Price Logic Flaw)

## Usage Guide

### Running Business Logic Tests

```python
from chaos_kitten.brain.business_logic_attacker import BusinessLogicAttacker
from chaos_kitten.paws.executor import Executor

# Initialize
executor = await Executor(base_url="https://api.example.com")
attacker = BusinessLogicAttacker(executor=executor)

# Test specific attack type
vulnerabilities = await attacker.test_race_condition(
    endpoint={"path": "/api/transfer", "method": "POST"},
    profile=race_condition_profile,
    concurrent_requests=5
)

# Or test with endpoint and profile discovery
vulnerabilities = await attacker.test_endpoint(endpoint, profile)
```

### Integration with Orchestrator

The orchestrator automatically includes business logic testing in the scan workflow:

```
1. Parse OpenAPI spec
2. Plan standard attacks
3. Execute standard attacks
4. Analyze standard results
5. Test business logic vulnerabilities  ← NEW
6. Generate combined report
```

### Configuration

Enable business logic testing in `chaos-kitten.yaml`:

```yaml
target:
  base_url: "https://api.example.com"

agent:
  test_business_logic: true
  concurrent_requests: 5
  
reporting:
  include_business_logic: true
```

## Test Coverage

The framework includes comprehensive test coverage (>80%):

### Test Categories

1. **Race Condition Tests**
   - State change detection
   - Conflict error detection
   - Concurrent request handling
   - No vulnerability scenarios

2. **Workflow Bypass Tests**
   - Step skipping detection
   - State validation verification
   - Successful bypass scenarios
   - Proper blocking scenarios

3. **Authorization Tests**
   - Privilege escalation detection
   - Access control verification
   - Admin operation attempts
   - Protected resource access

4. **Price Manipulation Tests**
   - Negative price detection
   - Zero price handling
   - Invalid value rejection
   - Server-side validation verification

5. **Integration Tests**
   - Multiple attack type detection
   - Vulnerability accumulation
   - Concurrent attack execution
   - Report generation

### Running Tests

```bash
# Run all business logic tests
pytest tests/test_business_logic.py -v

# Run specific test class
pytest tests/test_business_logic.py::TestRaceConditionDetection -v

# Run with coverage
pytest tests/test_business_logic.py --cov=chaos_kitten.brain.business_logic_attacker

# Run async tests
pytest tests/test_business_logic.py -v -s
```

## Custom Attack Profiles

Create custom business logic attack profiles by extending the schema:

```yaml
name: "Custom Business Logic Attack"
category: "business-logic"
severity: "high"
description: "Description of specific business logic flaw"
attack_type: "race-condition|workflow-bypass|authorization|payment"

# Timing configuration
requires_concurrency: true
concurrent_requests: 10
timing_sensitive: true

# State tracking
requires_state: true
state_transitions:
  - name: "critical_workflow"
    steps:
      - action: "POST"
        target: "/step1"
        payload: {}
      - action: "POST"
        target: "/step2"
        payload: {}

# Detection indicators
target_fields: ["field1", "field2"]
payloads: ["payload1", "payload2"]

success_indicators:
  status_codes: [200, 201, 409]
  response_contains: ["success", "error"]

remediation: "Steps to fix this vulnerability"
references:
  - "https://reference.url"
```

## Metrics & Reporting

The framework generates detailed reports including:

- **Vulnerability Count**: By type and severity
- **Affected Endpoints**: Full path and method
- **Evidence**: Proof of exploitation
- **Risk Assessment**: Impact on business logic
- **Remediation Steps**: Specific fixes
- **References**: OWASP/CWE citations

### Report Fields

```python
{
    "type": "business-logic",
    "attack_type": "race-condition",
    "title": "Race Condition in Balance Transfer",
    "description": "...",
    "severity": "high",
    "endpoint": "POST /api/transfer",
    "evidence": [
        {"type": "state_change", "initial": 100, "final": 107}
    ],
    "proof_of_concept": "Execute 5 concurrent requests",
    "remediation": "Implement database-level locking"
}
```

## Performance Considerations

### Concurrent Request Tuning

```python
# Default: 5 concurrent requests
profile.concurrent_requests = 5

# For heavy load testing
profile.concurrent_requests = 20

# For sensitive endpoints
profile.concurrent_requests = 2
```

### Timing Sensitivity

```yaml
# For timing-sensitive attacks
timing_sensitive: true
# Reduces delay between requests to increase race condition likelihood
```

### Endpoint Selection

Business logic attacks should focus on:
- Financial operations (payment, transfer, refund)
- State-changing operations (create, update, delete)
- Workflow-dependent operations (approve, publish)
- Resource-sharing operations (inventory, availability)

## Limitations & Considerations

1. **Executor Dependency**: Requires functional HTTP executor
2. **State Tracking**: Some attacks require ability to query current state
3. **Timing**: Race conditions may not reliably reproduce in all environments
4. **Authentication**: Requires proper session/token handling
5. **Rate Limiting**: May trigger rate limit protections
6. **Data Impact**: Testing may create or modify actual data

## Future Enhancements

- [ ] Machine learning for pattern detection
- [ ] Advanced timing analysis for micro-race conditions
- [ ] State machine graph visualization
- [ ] Custom action execution hooks
- [ ] Distributed race condition testing
- [ ] Financial impact assessment
- [ ] Workflow graph generation from API analysis
- [ ] Known CVE pattern matching

## References

### OWASP Top 10

- A01:2021 – Broken Access Control
- A04:2021 – Insecure Design (Business Logic)

### CWE

- CWE-362: Concurrent Execution using Shared Resource
- CWE-1025: Comparison Using Wrong Factors
- CWE-862: Missing Authorization

### Security Standards

- OWASP Testing Guide: Business Logic Testing
- NIST SP 800-4: Security Testing
- PCI DSS: Business Logic Security

### Additional Resources

- https://cheatsheetseries.owasp.org/
- https://owasp.org/www-community/attacks/Business_logic_attacks
- https://cwe.mitre.org/
