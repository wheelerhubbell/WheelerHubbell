# Security, custody and recovery boundaries

## Transaction state

`QUOTED → PREPARED → SETTLING → SETTLED → ISSUED` is the allowed successful path. Schema rejection and buyer authentication precede database and payment calls. Quote and request identity are fixed durably. Payment identity is unique across purchases. The evaluator runs against the frozen submission and admitted trust bundle before exposure to settlement. Signing availability and result-capacity checks occur before payment settlement.

PREPARED stores the original authorization, decision, quote, input and chain scan origin. SETTLING is committed before the external settlement call. A facilitator success response is only a transaction hint. No Mark is issued until matching finalized settlement evidence is durable. ISSUED commits the exact signed result bytes and first registry event in one database transaction. A response is returned afterward.

Unknown settlement remains pending, not failed-and-recharged and not optimistically successful. The recovery path first searches the original authorization's on-chain event and verifies the full matching transaction. If a settlement response is lost, the same authorized nonce is still the only allowed payment. Bounded retries may call settlement again using the same EIP-3009 authorization. Therefore “no second charge” means no second successful token transfer for the one authorization—not a claim that all crash scenarios make only one HTTP call to a facilitator. The test happy path actually makes one settlement call.

A worker lease and database compare-and-set fencing control concurrent issuers. Lease loss cannot overwrite another worker's completed record. Source/context/authority failure yields a paid negative assessment, not a Mark. Invalid structural requests do not reach the payment rail. A GET is never silently upgraded into settlement recovery.

## Durability

The executed SQLite path uses WAL, synchronous FULL, foreign keys, transactions and uniqueness constraints. Tests include connection reopen, lost HTTP response, crash-shaped injected faults, concurrency and uncertain settlement. The demonstration separately closes the writer and HTTP service, then reads the committed result from a different operating-system process.

This demonstrates persistence across those tested boundaries. It does not demonstrate disk survival after infrastructure destruction, configured backups, replicated durability, disaster recovery, or unbounded retention. The PostgreSQL adapter is written but was not installed or exercised against a database. Netlify must use the durable external database; no `/tmp` fallback is allowed.

Retain the issuer key needed for unresolved purchases. Rotation/migration of pending issuance across a changed authority epoch is not integration-proven. An expired quote, expired trust epoch, unavailable key, unavailable RPC, or unavailable database fails closed. They are operational dependencies, not permissions to fabricate a completed Mark. A known payment may remain recoverable but unfulfilled until the original authority/key/dependency is restored or a separately authorized correction/refund process exists. No automatic refund rail is implemented.

## Trust and verification

The root pin is an independently admitted trust anchor. The root name in a document or discovery response does not prove ownership by WHP. TEST roots are rejected by default for live verification. Real Ed25519 signatures in the demonstration establish integrity under generated test keys only.

The separately implemented Python verifier shares the public contract, not the producer evaluator implementation. It verifies source and transition signatures, grants, profile hash, graph semantics, identity/payment binding, Mark versus denial type, decision replay, signature and optional registry/chain evidence. It is not an independent external security audit, formal correctness proof, or standalone chain-consensus verifier.

A signed trust snapshot commits to the certificate/revocation inventory. Expiry bounds stale trust. The buyer journal retains the highest verified trust epoch and rejects a rollback it has already observed. A first-time verifier with only a root pin cannot know about an unseen newer signed epoch within an older snapshot's validity period. A public transparency witness, trusted timestamp authority and cryptographic chain inclusion proofs are not implemented and are not claimed.

Time fields are issuer/authority assertions checked against the configured clock and bounds. The test uses an explicit fixed fixture clock. A historical signature is not proof that its signing time was independently timestamped.

## Privacy and execution authority

Submitted artifacts, buyer proofs and wallet authorizations are data, not instructions to this system. The core performs no arbitrary fetches from source locators, executes no source-supplied code, invokes no language model, and cannot confer real-world authority outside the configured profile. Retrieval is restricted to the buyer authentication key. Registry views disclose only the opaque result identity/status, not private input or raw payment data.

The stored Mark intentionally contains the complete submitted proof, payer address and payment evidence. A buyer who redistributes it is redistributing those contents. This build does not implement selective-disclosure proofs. Operators still require appropriate infrastructure access control, encrypted storage/transport, rate limiting, backups, log hygiene and key custody; those operational controls were not deployed in this session.

The owner-provided EIP-1193 signer is responsible for its owner's standing spending authority. The included client commits a per-purchase and aggregate allowance before invoking it. Budget reservations remain charged against the allowance while outcomes are uncertain; they are not automatically released to enable further spending. No wallet, funds, key authority, or expenditure permission is synthesized by the service.
