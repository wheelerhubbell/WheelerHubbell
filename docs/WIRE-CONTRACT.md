# WHP Standing first public v1 wire contract

The normative first-public contract is [FIRST-PUBLIC-V1.md](FIRST-PUBLIC-V1.md), the exact `public/contract.json` manifest, the closed `schemas/result.schema.json`, the embedded `profiles/structured-passage-1.0.0.json`, and the root-authorized hash-addressed standalone verifier.

There is one public format, not a candidate adapter, dual result format or v2. The schema generator and deterministic `scripts/freeze-contract.py --check` bind these representations; executable verification enforces their cross-field authority, graph, time, payment, replay and discovery invariants.

The former candidate wire document is preserved unchanged at `evidence/development/candidate-WIRE-CONTRACT.md` solely as development provenance. It is not an alternative public contract.
