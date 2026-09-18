# GitHub repository control admission, version 1

The first open admission class is control of a public GitHub repository. Use a canonical lowercase namespace `https://github.com/{owner}/{repo}`, that exact namespace as `scope`, and `namespace-control` as `jurisdiction`.

The controller publishes `.well-known/standing-authority.json` on the repository's default branch. An assessment's `authority` array contains `{ "namespace": "https://github.com/owner/repo", "manifest_sha256": "SHA256 of the manifest's WHP-JCS-I1 canonical JSON" }`. All source and transition signatures remain inside the submitted graph.

The manifest's exact fields are `version` (`WHP-NAMESPACE-GRANTS-v1`), `namespace`, integer Unix `valid_from` / `valid_until`, and `grants`. Each grant contains `public_key` (Ed25519 SPKI base64), `role` (`SOURCE` or `TRANSITION`), `payload_hashes` (canonical SHA256 hashes of the exact signed payloads), `scope`, `jurisdiction`, `operations`, `valid_from`, and `valid_until`. No wildcard grants are admitted. Each source locator must be a canonical URL inside that repository namespace, without query, fragment, percent escapes or userinfo.

The service reads only the fixed HTTPS GitHub Contents API path, without redirects, with bounded response size and time. It checks the Git blob hash, exact requested manifest hash, key, role, payload hashes, bounds, operations and time. It records its signed observation separately from the provenance signatures and from the root's issuer authorization. The submitted signer never has to enter WHP's root certificate list.

This establishes that the repository controller authorized this key to attest to these exact repository objects within these bounds. It does not establish universal truth, external institutional appointment, legal authority or permission to execute an external action. The independent verifier checks the signed HTTPS observation and replays every grant and evaluator rule. The observation is not a self-contained cryptographic proof of GitHub's historical state.

Observations are fresh for 300 seconds. Historical records retain their issuance-time evidence. Each current registry check for an active Mark fetches the same submitted manifest hashes again and carries fresh signed observations in the registry snapshot. Unchanged valid grants can therefore retain ACTIVE standing after the issuance observations age. A withdrawn, changed, expired or inaccessible manifest produces LIMITED current standing without altering the original Mark or charging another payment. The independent verifier validates the new observations against the original submission before accepting ACTIVE. Those same failures also prevent fresh admission for a new purchase.

Empty or insufficient authority can produce a negative assessment. Payment never converts it to a positive Mark. Transport or evidence binding errors are rejected before settlement.
