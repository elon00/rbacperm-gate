# RBACPerm Gate — QMOOSA-0980

**Status: experimental offline policy diagnostic. Not production-ready or security-certified.**

This repository is the TESTS component of QMOOSA-1000 Batch 196. It now contains a bounded Python role-based access-control evaluator with deny-by-default decisions, explicit deny precedence, role inheritance, duplicate-key rejection, cycle rejection, strict schemas, and a 64 KiB input limit.

It **does not** authenticate a caller, bind subjects to verified identities, sign policy decisions, implement a network service, persist policies, implement multi-tenant isolation, use QuickNode, connect to a blockchain, or provide FIPS/PQC cryptography. The Rust executable fails closed rather than advertising nonexistent capabilities. No live funds or public deployments are used.

## Offline verification

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/reality_check_harness.py
python -m compileall -q rbac_gate.py tests
cargo fmt --all -- --check
cargo test --offline
```

To evaluate a JSON request: `python rbac_gate.py < policy.json`. Example input:

```json
{
  "roles": {
    "reader": {"allow": ["document.read"], "deny": [], "inherits": []},
    "editor": {"allow": ["document.write"], "deny": [], "inherits": ["reader"]}
  },
  "subjects": {"alice": ["editor"]},
  "request": {"subject": "alice", "permission": "document.read"}
}
```

Valid requests print `{"authorized":true}` or `{"authorized":false}` and exit 0. Invalid JSON or policies print a fail-closed error and exit 2. **Do not treat a true result as authenticated permission to perform a real-world action.** The caller supplies both the policy and the claimed subject.

## Acceptance status

CI and CodeQL results must be checked against the exact PR HEAD SHA. Passing offline tests does not establish real identity binding, authorization enforcement, cryptographic validation, regulatory compliance, or deployment readiness. Independent security review remains required. The legacy README's 100/100 and NIST badges were unsupported and removed.
