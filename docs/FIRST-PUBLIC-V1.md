# WHP Standing — first public v1 cryptographic contract

## Completed object and release identity

The completed TEST object is one paid simulated evaluation, one durable signed historical record, independent replay, fresh separate status, and three cold propagation traversals reaching an unpaid x402 boundary. The commercial completed object additionally requires a genuine outside buyer's finalized authorized funds and actual production authority. TEST evidence never satisfies those production predicates.

This is the first public WHP Standing Mark v1, not v2. The candidate archive and its 83-test execution remain development provenance. The recovered 107-test discovery work remains separate development provenance. Neither is an alternative public wire format, verifier fallback, or compatibility obligation.

## The three objects

A Mark is the immutable issuance-time record. Its exact signed submission, embedded profile, root-authorized verification contract, authority bundle, evaluator decision and settlement commitments define its meaning. A current website cannot change those bytes or semantics.

A registry snapshot is a separately signed, at-most-300-second observation of current standing. Its append-only event chain binds the exact Mark file SHA-256, purchase ID and Mark ID. Revocation, withdrawal, supersession, dispute and expiry do not invalidate the mathematical historical signature or rewrite the Mark. Historical verification without a fresh registry yields NOT_CHECKED, never ACTIVE.

A discovery resolution is a separately signed, at-most-300-second current capability/service statement. Its signer requires the explicit DISCOVERY role in a fresh root-authorized certificate. It binds the stable capability and resolution IDs, root, environment, current service origin, current contract hash/URL and immutable artifact locations. It is neither a standing assessment nor a registry status. A valid signature cannot substitute one of these types for another.

## Exact historical envelope

The envelope fields are exactly protected, payload, signature. Protected fields are exactly type, algorithm, canonicalization, key_id. Type is WHP-STANDING-MARK-v1 only for ESTABLISHED, otherwise WHP-STANDING-ASSESSMENT-v1. The payload version is WHP-STANDING-RESULT-v1. There is no extension bag and no candidate fallback.

Payload fields are exactly version, environment, issuer, issuer_key_id, purchase_id, mark_id, issued_at, effective_at, expires_at, object, profile, profile_authorization, authority, submission, submission_hash, decision_record, decision_record_ref, standing, commerce, retrieval, limitations, current_status_rule, protocol, discovery. Every required field is mandatory, including explicit null standing and mark_id on negative assessments.

The submission is the exact evaluated object/action and connected signed provenance graph. Its named object version/root, node content, locators, epistemic status, source qualifiers, unknowns, blocking operations, scope, jurisdiction, time windows and separately signed transformation warrants survive unaltered. The decision includes exact rule outcomes, permitted operations, components, unknowns, ceiling and unassessed components. A Mark does not certify external truth, external legal authority, completeness outside that graph, unassessed continuity or an action boundary. The exposed standing object is a constrained projection checked against independent replay, not an additional claim.

Profile content is embedded in full and SHA-256-bound to the submission and root authorization. The exact public Structured Passage 1.0.0 profile is frozen with the contract. Later profile content cannot reinterpret an old record. Unknown profile or semantic contract hashes fail closed, even when signed.

The protocol object has exactly document, sha256, verifier_sha256. document is the complete immutable public contract manifest; sha256 hashes its canonical JSON. That manifest includes the exact result-schema hash and generic self-description/bootstrap recipe. verifier_sha256 hashes the standalone Python verifier's exact UTF-8 bytes. The root-signed profile authorization binds profile_hash, contract_hash and verifier_sha256 together with ratified, issuer, environment, valid_from and valid_until. An issuer signature alone cannot appoint a different verification program or profile. The verifier embeds its schema and checks its own file hash against that root authorization; no producer modules or mutable schema are imported during verification.

The decision-record commitment is urn:sha256: plus SHA-256 of its canonical JSON. submission_hash is SHA-256 of canonical submission JSON. Purchase identity is the existing domain-separated hash of root pin, buyer Ed25519 key and durable client reference. Commerce retains the exact signed quote, EIP-3009 authorization, payer/recipient/amount/network/asset/resource/nonce bindings and finalized-or-explicitly-TEST settlement evidence. The historical quoted resource URL remains signed solely as a payment identity commitment, never as the current discovery route.

## Immutable discovery identity

The discovery object has exactly version, capability_id, capability_class, resolution_id, resolution_url, root_key_id and status_id. Its version is WHP-STANDING-DISCOVERY-IDENTITY-v1. The WHP capability ID is urn:whp:standing:capability:1. Its vendor-neutral capability class is urn:capability:machine-verifiable-standing:1. The stable resolution ID is urn:whp:standing:resolution:1. status_id is urn:whp:standing:status: followed by the purchase ID. root_key_id is the historical root SPKI fingerprint.

resolution_url is an immutable bootstrap locator for that stable identity, not an assertion that the evaluation service still runs at that origin. It must be HTTPS, with no userinfo, query or fragment; explicit TEST permits literal 127.0.0.1 HTTP only. Current commercial URLs, availability, OpenAPI, purchase endpoint and provider metadata are absent from this historical identity. They are learned from the fresh, authorized signed resolution. A migrated service and registry can operate at another origin without changing a Mark. A substituted resolver root, expired resolution, wrong capability or unauthorized discovery key fails closed.

The service captures this identity in the durable quote row before payment. Recovery does not recalculate it from a changed current origin. Published immutable contract/profile/schema/verifier resources are addressed by SHA-256; a resolver can relocate those bytes but not replace their content. No indefinite availability promise is inferred from a hash. Missing archived material is an explicit failed traversal, not a silent fallback. The full profile and historical meaning remain in the Mark itself.

## Canonicalization and failure rules

WHP-JCS-I1 is the deliberately restricted JSON algebra used here: null, booleans, well-formed Unicode strings, safe integers, dense arrays, and plain string-keyed data objects. Object keys sort by UTF-16 code units; arrays retain order; output is UTF-8 with JSON escaping and no Unicode normalization. Integer wire tokens use only -?(0|[1-9][0-9]*), excluding -0. Fractional and exponent tokens, NaN, infinity, unsafe integers, invalid UTF-8, lone surrogates, duplicate keys, undefined, sparse arrays, accessors and hidden/symbol properties are rejected. Maximum canonical depth is 64; submissions reserve 16 levels. Input body and trust-bundle ceilings remain 262144 and 65536 bytes.

Ed25519 signs UTF-8 canonical JSON of {protected,payload}; protected.type supplies domain separation. key_id is lowercase SHA-256 of canonical Ed25519 DER SPKI bytes. Signatures and public keys use canonical padded base64. Exact hashes refer to canonical JSON except explicitly byte-addressed verifier source and durable result files. Unknown semantic fields are rejected at every schema-defined semantic object. The source content field alone admits arbitrary JSON as evaluated data; it is never interpreted as a protocol extension. Negative or failed checks never upgrade to positive standing. All schema, hash, signature, authority, freshness, type and replay failures are explicit non-success.

## Independent trust and status

An embedded root is a commitment, not self-created institutional authority. The standalone verifier still requires an independently supplied/admitted root pin. The cold TEST reader can discover and compare a root commitment from its sole artifact and signed resolution, and prove internal signatures/replay relative to that root; it reports TEST_SELF_CONSISTENT_ROOT, not institutional authentication. A cold LIVE reader cannot promote that self-consistency to institutional admission. Production requires an independently authenticated root policy, not a wallet address, TLS origin alone or the issuer's assertion. Root replacement is not automatically admitted; historical root rotation requires a separately authorized continuity mechanism outside this frozen v1.

Historical issuance authority is evaluated at issuance/evaluation times against the embedded committed trust state. Current status is separately checked with fresh signed trust/revocations at observation time. A current registry error returns historical proof separately and never ACTIVE. The payment recipient is not an issuer, root or buyer identity.

## Vendor-neutral need and bounded propagation

STANDING-NEED-v1 names absence of independently verifiable standing, provenance insufficiency, missing transformation warrant, unestablished authority, unpreserved qualifications and blocking unknowns without naming a vendor. Its evidence-status inputs do not themselves confer authority. Discovery queries a generic capability catalog by capability class and required properties; matching is independent of brand and tested with alternative and incompatible providers.

Cold A receives only a completed TEST Mark file and generic runtime. Cold B receives only an external object, contemplated action and vendor-neutral need interface, including a generic catalog entrypoint. That entrypoint is a discovery interface, not a WHP address. Cold C verifies a first Mark, then handles a different unsupported object/action through the same need interface and catalog. Each executes real localhost HTTP, fetches signed current contracts, and reaches actual HTTP 402 with matching PAYMENT-REQUIRED terms. None signs a wallet authorization or settles the next request. A schema-valid, explicitly unadmitted self-attestation may probe that boundary; payment or probing never manufactures source authority or guarantees a Mark.

These are bounded TEST proofs through a neutral local catalog, not evidence of open-internet indexing, demand, a real sale, a deployed public service or LIVE issuance. The isolated downloaded verifier has no network, a read-only filesystem, no producer source, no private keys, dropped capabilities and bounded resources.

## Release evidence

Exact machine semantics are published in public/contract.json, schemas/result.schema.json, profiles/structured-passage-1.0.0.json and the hash-addressed standalone verifier. The public-v1 evidence report binds their hashes, the tested source manifest, full test output, real local transaction, separate-process retrieval and all three cold traversals. Main is promoted only as a coherent verified multi-file commit. Development evidence is never rewritten as production evidence.
