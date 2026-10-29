# RBACPerm Gate architecture

- **Canonical system ID:** QMOOSA-0980
- **Batch:** 196
- **Role:** TESTS
- **Current scope:** bounded offline policy decision, not an enforcement point

## Implemented

`rbac_gate.py` accepts one JSON policy/request on standard input. It validates exact top-level schemas; role names, assignments, inheritance edges and permission names; rejects duplicate JSON keys, unknown roles, inheritance cycles, malformed UTF-8, and inputs over 65,536 bytes. It resolves role inheritance, applies explicit deny precedence, and otherwise denies by default. No wildcard permissions are supported.

`tests/test_rbac_gate.py` exercises actual allow/deny and adversarial negative paths, including CLI behavior. `src/main.rs` fails closed with an unsupported exit. GitHub Actions runs Python regressions and Rust compilation; CodeQL analyzes Python.

## Not implemented / blocked

- Authenticated subject identity, trusted policy distribution, signed policy updates, audit persistence, and enforcement integration
- Cross-process policy version consistency, revocation, tenant isolation, and adversarial integration tests
- QuickNode RPC, x402 settlement, ML-KEM/ML-DSA, TLS, token issuance, live network or deployment
- Independent security approval and verified current-default-HEAD production acceptance

The original 100/100, FIPS and live-RPC claims were not backed by code or test evidence and must not be repeated. This diagnostic is not a production authorization service.
