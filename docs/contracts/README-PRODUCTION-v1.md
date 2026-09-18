# WHP Standing v1

Clean production assembly for `https://whpstandingmark.netlify.app`, in `wheelerhubbell/WheelerHubbellPublishingStandingMark`. Source join and production execution state are recorded separately under `evidence/production-assembly/`. `wheelerhubbell/WHPStanding` remains untouched provenance.

WHP Standing provides machine-verifiable standing under explicit authority and bounds. A paid evaluation of an admitted structured provenance graph returns a durable signed assessment. Only an established assessment receives a WHP Standing Mark. Payment never supplies missing authority or guarantees a positive determination.

## First public cryptographic contract

This is the first public WHP Standing Mark v1, not v2. The exact contract is `docs/FIRST-PUBLIC-V1.md`, `public/contract.json`, `schemas/result.schema.json`, the full embedded Structured Passage 1.0.0 profile and the root-authorized standalone Python verifier. The public semantic envelope is closed; unknown fields and unknown profile/contract semantics fail closed. There is no candidate compatibility adapter or alternate public verifier.

The immutable Mark records what was established at issuance. A fresh, separately signed registry records current standing. A fresh, separately signed capability resolution supplies the current service and purchase contract. A migrated service can be resolved without changing a historical Mark. Root authorization binds the exact profile, schema contract and verifier source hashes; an issuer alone cannot redefine verification semantics.

## Execution evidence

`evidence/public-v1/verification.json` is the machine-readable completion record when the complete gate has passed. It is accompanied by `tests.tap`, `source-manifest.json`, `contract-commitments.json`, the real-localhost demonstration, the isolated PostgreSQL report, TEST-as-LIVE refusal, and `cold/` traces for A (Mark only), B (neutral need only) and C (recursive TEST join). Do not infer a passed execution from source code, this README, an old report, or the presence of links. The report's source hashes and GitHub run bind what actually executed.

The 129/107/83-test verification results are retained as recorded evidence, not rerun by production assembly or deployment. Only the new root-to-current-commitments, target/configuration/database and deployed public boundary relationships are checked.

Cold A receives only a completed TEST Mark. Cold B receives only an external object/action and vendor-neutral need interface with a generic catalog entrypoint. Cold C verifies one Mark before recognizing a new unsupported object/action, rediscovering a compatible provider and reaching a second payment boundary. Each consumer is a fresh process without injected provider configuration; downloaded independent replay executes in a networkless, read-only, least-privilege sandbox. None possesses a wallet key or signs the next payment. The bounded local catalog is not an assertion of public indexing or an external registration.

## Development provenance

Authoritative repository: `wheelerhubbell/WHPStanding`. The public-v1 transition starts from authoritative main `2004b4b6a738c13c3b6f5adaf46adf217de28ece` and preserves inspected discovery work through `1cc06944fc821dbb182ecdec826b85da949cabce`. The original candidate archive SHA-256 is `37f38a3799baafcbdd149aa29e9994fa6ae39230d108ef35f93b842bcdea2056`. Its original 83-test execution, recovery manifest, archive and historical reports remain development provenance. The original root `FILES.sha256` and `BUILD-REPORT.md` describe that candidate, not the new source tree. Current source identity is the new verification report and source manifest.

The prior 107-test carrier work and documentation remain under `evidence/development/propagation-107/` and associated development documents. Historical report directories remain unchanged. They are not proof of the new public cryptographic contract. Historical assembly workflows are retained as inert provenance rather than allowed to overwrite the new source.

## Production boundary

TEST verification and TEST PROPAGATION-PROVEN are not DEPLOYED, LIVE, SOLD or ISSUED. The standalone verifier requires an independently admitted root pin. A discovered embedded TEST root demonstrates internal cryptographic consistency, not legal institutional attribution. Deployment requires actual root/profile/issuer/discovery authority, current status publication, stable resolution, durable storage and facilitator/RPC configuration. A sale, LIVE Mark issuance and observed LIVE propagation are separate future observations, not deployment completion gates. No production credentials or database are used by the TEST proof.

Production payment recipient only: `0x1050eddd8282623b0c263ed6bdbd42370bbc28d3`. Network: Base `eip155:8453`. Asset: native USDC `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`. The recipient is not an issuer, root key, buyer wallet or protocol identity. No public source visibility or metadata implies a licensing grant or institutional endorsement.
