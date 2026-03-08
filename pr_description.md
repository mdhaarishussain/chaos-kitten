# [FEATURE] Multi-Step State Machine Agent for Business Logic Testing

 Description
This PR implements a Multi-Step State Machine Agent that detects business-logic vulnerabilities by mapping API endpoint dependencies, building state chains, and attempting to disrupt expected workflows.

 Changes

 New Files
- `chaos_kitten/brain/state_machine.py` — Core module with:
  - `RelationshipMapper`: Groups endpoints by resource, identifies CRUD lifecycles via path heuristics (`/api/v1/orders/{id}` → resource `orders`), and builds ordered state chains.
  - `StateMachineAgent`: Executes three categories of state-breaking tests:
    - Broken Flow: Skips required steps (e.g. calling `DELETE` without `POST`) and skips intermediate steps in ≥3-step chains.
    - Out-of-Order: Executes operations in reverse order on non-existent resources.
    - Cross-User IDOR: User A creates a resource → User B attempts to read it (requires `auth_token_b` config).
  - `StateFinding`: Data class for structured vulnerability findings with `to_dict()` for orchestrator compatibility.

- `tests/test_state_machine.py` — 26 tests covering:
  - Resource extraction and path parameterisation helpers
  - CRUD chain mapping and ordering
  - Broken-flow detection (success/failure paths)
  - Out-of-order detection
  - Cross-user IDOR detection and skipping without second token
  - ID extraction from various response formats (`id`, `order_id`, dict body)
  - Executor error handling and edge cases

 Modified Files
- `chaos_kitten/brain/orchestrator.py` — Integrated `StateMachineAgent` into `Orchestrator.run()`:
  - Runs after chaos testing phase when `state_machine.enabled: true`.
  - Passes parsed OpenAPI endpoints to the agent.
  - Merges findings into the main findings list.

 Configuration
```yaml
state_machine:
  enabled: true
  auth_token_b: "second_user_token"   Optional, enables IDOR tests
```

 Testing
```bash
pytest tests/test_state_machine.py -v
 26 passed in 0.62s
```

 Related Issue
Closes 237 (Multi-Step State Machine / Business Logic Testing)
