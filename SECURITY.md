# RBACPerm Gate security boundary

**SECURITY_APPROVED: NO. DEPLOYMENT_READY: NO. FIPS validation: NOT CLAIMED.**

This is an offline, user-supplied policy evaluator. It is not an identity provider, a policy enforcement point, a network service, or a blockchain bridge. The caller controls both the policy and the claimed subject; the decision cannot be used as authenticated authorization without a separate trusted enforcement and identity-binding design.

## Threat controls implemented

- Deny by default and explicit deny precedence
- Reject duplicate JSON keys, unknown roles, inheritance cycles, unsupported wildcards, malformed input, oversized documents, and invalid names
- Bounded policy sizes and deterministic local evaluation
- Fail-closed unsupported Rust executable
- Negative regression tests and Python CodeQL workflow

## Outstanding review

Review role inheritance semantics, denial precedence, policy provenance, trust anchors, authentication, policy versioning, revocation, isolation, auditability, parser limits, concurrency, and integration before any deployment. CI success alone does not establish security approval. No cryptographic module is certified or used here.

Report vulnerabilities privately through GitHub's security advisory mechanism when available. Do not post secrets or credentials in public issues.
