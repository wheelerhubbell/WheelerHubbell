# WHP Standing v1 — Build and execution report

**Fresh executable candidate: 1.0.0-candidate.1.** The first live, paid institutional WHP Standing Mark has not been issued. This report records the machinery actually built and the execution actually completed.

## Executed result

The full verification command finished at **2026-09-15T09:41:11.132Z**. It ran **83 automated tests: 83 passed, 0 failed, 0 skipped**. It also syntax-checked 27 JavaScript modules and 3 Python files, checked the published JSON Schemas, and ran the separately implemented Python verifier.

The autonomous buyer first fetched the public discovery contract, obtained a 402 quote, reserved its spending allowance, requested one simulated wallet authorization, and submitted the paid request over an actual localhost HTTP server. The service recorded **1 settlement call and 1 simulated transfer**, issued a signed TEST Mark, and exposed its signed registry record.

The buyer's independent Python verification succeeded. Authenticated retrieval returned the identical stored bytes without another wallet-signing call or settlement. After closing the HTTP server and database writer, a separate operating-system process recovered those same committed bytes from disk.

The Mark's Ed25519 signatures and embedded source/authority signatures are genuine signatures generated in the execution. The root identity, company authorization, EIP-1193 wallet signer, EVM signature and payment rail are **TEST fixtures**. **No real money moved; no live blockchain was contacted.** The included Mark is rejected as live unless the verifier is explicitly placed in test-verification mode.

## What the machinery does

The signed Mark binds the exact assessed object/version and complete submitted provenance graph to the named profile, root-admitted source and transition authorities, preserved qualifiers and unknowns, bounded decision, payment/quote identity, expiry and retrieval reference. The signature covers that complete envelope. A failed assessment produces a signed, paid, retrievable decision **without** a Standing Mark.

The first implemented profile is the explicitly identified **Structured Provenance and Passage Integrity 1.0.0 candidate**. It checks exact COPY and identity-preserving COMPOSE transformations, graph closure, source signatures, warrant authority, scope, jurisdiction, temporal bounds, unknowns and operation ceilings. It does not establish external-world truth, certify arbitrary natural-language inference, or certify the behavior of an external workflow. Continuity outside the submitted graph and external action-boundary controls remain NOT_ASSESSED.

The service persists preparation before settlement, preserves uncertain settlement as pending, reconciles the original on-chain authorization identity, and atomically commits the signed result with its first registry event. Stored retrieval does not settle again. Registry withdrawal/correction history appends without changing the original Mark. The buyer journal reserves its cumulative allowance before signing and recovers the same purchase without silently creating another spending authorization.

## Proof identity

Mark identifier:

```text
WHP-SM-dcbccc4085179af5fd863e1c79e55697929e83f316c3ca53dfbcda1b3fe749a1
```

SHA-256 of the exact included Mark bytes:

```text
931ed749f1dcec4c992f2ad51e102b8c0da868027ac0c24acdb70cb4cf59e6b7
```

The test root fingerprint is `22542374cc8d6f1fe228f21c309c2514a7f8b07307a052d796e50825b333dc45`. It is a test audit anchor, not an established WHP institutional root. The fixture clock is `2026-09-15T08:48:10.000Z`; the actual execution was recorded at `2026-09-15T09:41:08.803Z`. The saved registry status is historical and time-bounded, not a fresh present-time status assertion.

## What is not established

No production WHP root/profile ratification, production issuer key custody, public deployment, funded pre-authorized buyer, real EIP-3009 signature validation, real facilitator settlement or real finalized chain transaction was established in this build. The PostgreSQL adapter and Netlify wrapper are included but were not installed/integration-tested/deployed. No external security audit, production backup/disaster-recovery test, standalone chain-consensus proof, or automated refund rail is claimed.

The exact live completion boundary is therefore **OPEN**. The delivered object is working candidate machinery plus an executed test proof—not a substitute for the first real paid WHP Standing Mark.

## Artifacts in the package

`src/` contains the Mark/evaluator/authority/validation machinery, durable transaction store, payment rail, HTTP service and autonomous buyer. `verify/verify_mark.py` independently verifies and replays the result. `profiles/`, `schemas/` and `public/openapi.json` publish the candidate contract. `test/` contains the executed tests. `evidence/verification.json`, `evidence/tests.tap` and `evidence/demonstration/` contain the controlling execution records. Historical failed/intermediate runs remain separately identified under `evidence/development/`.

`README.md` and `docs/` explain the source hierarchy, exact completion object, wire contract, runtime configuration and remaining operational boundaries. `FILES.sha256` checks the packaged files. No private keys, live credentials, database files, upstream manuscripts or font files are shipped.

No existing DIP repository, branch, deployment or production setting was modified. No live payment was authorized or submitted.
