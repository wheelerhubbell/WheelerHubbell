# Bounded machine exposure — 2026-09-16

Production baseline: `8385a331dc9894f2037eab9b17d3329fc78bf74f`, Netlify production deploy `6aa9d2d6e6c01a0008c7b918`, site `813ee022-f4d9-4d8e-a974-86158583a39f`. Actual origin: https://wheelerhubbellpublishingstandingmark.netlify.app. The older assembly target in AGENTS.md is historical; current production configuration and the user's current-source instruction control this operation.

Recovered implementation: DIP commit `45365dab000277460d741c8dd536781536f6f22d` contains nine `public/profiles/` machine-discovery profiles, four pilot records in `data/verticals.json`, generated industry routes, a Census NAICS ingester, deterministic batches, source checking, validation and quarantine. Its old evaluator, URLs and action-boundary claims are not current Standing semantics and are not imported.

Retained execution evidence: https://github.com/wheelerhubbell/DIP/actions/runs/34800557821/job/103842220055 records 1,012 six-digit NAICS industries ingested, 50 queued candidates and 962 remaining on 2026-09-14. Artifact `10331307279`, `vertical-taxonomy-batch`, SHA256 `37bf998c4f6912f80483b053289a2a59867dca781b49c5c377e38732ec9efb6c`, was listed unexpired. Listing and logs are recovered evidence; artifact bytes have not been retrieved here. NAICS industries are not O*NET/SOC occupations. No 1,200-occupation mapping has been recovered. Queued candidates are not validated domain profiles.

Recovered propagation implementation: DIP `tools/receipt-companion.mjs` preserves exact receipt bytes in a caller-controlled package. The current Standing Mark already binds its discovery identity, so no legacy receipt envelope or duplicate companion is introduced. The caller-control and exact-byte requirements are carried into current discovery instructions.

Recovered Standing implementation: WHPStanding `fdf72e5963f76b89b387f88cdfb32228c6c83114` contains the MCP publisher, discovery routes, vendor-neutral provider matching and separate TEST cold traversal evidence. The production assembly already has the publisher script but had no publication workflow. This change joins the existing script to production using GitHub OIDC, subject to actual registry acceptance and read-back. It does not claim registration merely from metadata.

Other inspected repository trees: whp-dip-rebuilt `d783c297de877471bcda8d551981dcb6b2735756`; whp-dip-x402-source `e89570a95fb57b483fc46b5c67932c5b61f02051`; direct-build-execute `2b9efe0fc4927f97df0c14b3126cd86e689b2eb1`; wheeler-hubbell-machine `feab751279faf9c62a1d4083344de36181bdd6da`. These are an inventory, not an assertion that every historical object was exhausted. Private repository git cloning lacks CLI credentials; configured connector reads remain available. DIP and WHPStanding public histories were cloned read-only.

Changes: thirteen provenance-linked contexts narrowed to Structured Passage semantics; a caller-controlled exact-byte recursive handoff resource; MCP resource discovery/read joins; expanded llms.txt and sitemap; canonical production repository in server metadata; HTTP Link discovery on production responses without modifying response bytes; bounded publication workflow.

Not changed: cryptographic contract, signed schema, verifier, evaluator, trust roots, certificates, payment binding, source admission, storage, historical Marks, or old repositories. Only new exposure relationship tests run; inherited 129/107/83 suites are not rerun or reclassified. No wallet authorization or settlement is created by this release.

Publication, external reachability, external indexing, independent encounter, interpretation, acquisition and recursive acquisition remain separate predicates. New resources are discovery aids, not authority or observed demand. Generic x402 random-nonce clients remain incompatible with exact WHP quote binding. Domain contexts do not grant domain authority, and payment does not guarantee a Mark.

Official MCP publication reference: https://modelcontextprotocol.io/registry/github-actions . CDP Bazaar indexing requires a successfully settled payment through its facilitator; metadata alone is insufficient: https://docs.cdp.coinbase.com/x402/seller/get-discovered . Do not switch the existing payment facilitator or spend funds to manufacture indexing.

Rollback: revert only this exposure release's file changes, preserving any subsequent authority-epoch commits. Do not reset main to the baseline: it may erase renewed trust material. MCP external registry records require separate registry administration; a code rollback does not retract them.
