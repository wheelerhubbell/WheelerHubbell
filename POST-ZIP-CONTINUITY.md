# WHP Standing v1 — Post-ZIP Continuity Record

This file exists so the amended WHP Standing archive carries forward the knowledge established after `WHP-Standing-v1-candidate-1.zip` was first added at commit `12fd5beb2564f90a57079e598b0dbddf09dfcada` on 2026-09-15.

## Governing recovery rule

Do not restart from the original candidate assumptions. The archive is a continuity object. Preserve established truths, their provenance, and their scope. Do not redesign the architecture merely because production execution exposes an implementation or provider defect.

The known clean propagation-capable checkpoint is `1cc06944fc821dbb182ecdec826b85da949cabce`. It demonstrated 107 tests passed, zero failures, zero skips, preservation of the original 83 tests, independent Python verification, isolated cold-agent Mark traversal, an actual HTTP 402 boundary in TEST, PostgreSQL concurrency and durable retrieval, Netlify package execution, and fail-closed TEST/LIVE separation.

## Production authority now established

Wheeler Hubbell Publishing explicitly authorized establishment of its production cryptographic root and issuer authority for WHP Standing v1. No external institutional admission is a prerequisite to WHP establishing its own root.

The production authority ceremony subsequently succeeded using the repository's existing canonical cryptographic primitives rather than a parallel signing implementation.

Verified production root pin:

`c9507f2c5d0d80935a4885071c8372eeba25010e514e81401acabb246134bff6`

Verified issuer key ID:

`baabb9cd21f367bb8467f1bce570cd1f4ef1b418172f2cb68968ebe7186f487e`

Bound profile:

- ID: `WHP-STANDING-STRUCTURED-PASSAGE`
- Version: `1.0.0`
- SHA-256: `dc25aa63cadad8b5b02ba3cbaac552ca8273c6d6793b4eefdef16aadd180046e`

The root/issuer keys are separate. The issuer certificate verifies under the WHP root and carries ISSUER and REGISTRY roles. LIVE profile authorization and trust/status state are root-signed. Independent Python authority verification and schema validation passed. TEST-to-LIVE relabeling, wrong root pin, profile tampering, expired status, unadmitted jurisdiction, and unadmitted scope fail closed. Private keys are not committed or printed. Root custody is isolated from production runtime; the issuer production secret is separately held in authenticated Netlify environment custody.

## Fixed production service parameters

Canonical origin: `https://whpstanding.netlify.app`

Payment recipient: `0x1050eddd8282623b0c263ed6bdbd42370bbc28d3`

Network: `eip155:8453` (Base)

Asset: native Base USDC contract `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`

Configured launch amount: `1000000` USDC base units (1 USDC per evaluation).

The payment recipient is not the root key, issuer key, or buyer.

## Production provider findings

Authenticated Netlify access is verified. The canonical Netlify site exists and is publicly accessible. WHP production authority configuration is present.

The selected facilitator is `https://facilitator.payai.network`. Its supported endpoint was verified compatible with x402 v2, exact scheme, `eip155:8453`. No settlement was executed merely to prove configuration.

The selected issuer RPC is `https://base-rpc.publicnode.com`. Base chain ID 8453, finalized-block access, USDC bytecode presence, log access, and agreement with an independent Base RPC were verified.

Netlify managed PostgreSQL exists. Direct migration through the API-returned role exposed `permission denied for schema public`; the repository therefore added the same existing schema as Netlify's native migration `netlify/database/migrations/0001_whp_standing.sql`. Do not reinterpret this as a database-architecture redesign.

## Current external deployment blocker

A real production deployment attempt reached Netlify's deploy API and was rejected with HTTP 403:

`Account credit usage exceeded - new deploys are blocked until credits are added`

No user payment, billing mutation, fake buyer, self-sale, or LIVE Mark issuance occurred.

A subsequent authenticated read-only account inspection produced conflicting provider data: the Free account capability counters reported 300 included credits and 0 used for the current usage period while deployment remained blocked for exceeded credits. Therefore a paid upgrade requirement is NOT established. Treat this as a provider-account/credit-ledger discrepancy until reconciled. Do not tell the user to buy credits merely from the deploy rejection.

## Evidence-state labels

Production authority: VERIFIED.

Canonical site: existing public site, but the newly configured production build has not crossed the blocked deployment edge.

Production payment boundary: NOT VERIFIED after the blocked deploy.

SOLD: false.

ISSUED: false for LIVE.

PROPAGATION-PROVEN: false for LIVE. TEST propagation evidence remains valid within its TEST scope.

REGISTERED: do not claim without legitimate external registry acceptance/read-back.

## Execution constraint

The remaining object is not a new architecture. Continue from the verified machine plus the established WHP production authority and the accumulated production evidence. Do not spend the user's money, manufacture a buyer, rotate authority, rerun solved work without a concrete need, or convert a provider defect into a redesign.

This continuity record supplements, and does not replace, the exact source, evidence, schemas, tests, workflows, public authority artifacts, and commit history represented by the amended archive.
