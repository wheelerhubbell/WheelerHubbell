# Open machine acquisition

POST the exact assessment JSON to `/v1/evaluations`. The service returns ordinary x402 v2 `PAYMENT-REQUIRED` terms, a durable purchase ID, recovery URLs, and the unpaid eligibility result. No buyer key, WHP proof, registration or library is required.

An existing owner-authorized x402 EIP-3009 wallet client creates its normal random nonce and `PAYMENT-SIGNATURE`, then retries the same POST. A positive evaluation returns a Mark; a negative evaluation returns a signed assessment with no Mark. Uncertain settlement returns 202.

Persist the original request, purchase ID and signed payment before transmission. Retrieve by GET `/v1/purchases/{purchase_id}/result` or recover by empty POST `/v1/purchases/{purchase_id}/recover`. Recovery reuses the stored authorization and cannot create a second charge. Keep the 256-bit client reference and purchase capability confidential until deliberately publishing the result.

The optional `PAYMENT-PAYER` / `PAYMENT-WALLET-SIGNATURE` helper remains available for EIP-1193 hosts. It is not the canonical buyer protocol. StandingBuyer is an optional durable reference client.

The wallet signature authorizes the transfer only. Namespace grants and signed provenance establish eligibility separately. See `/namespace-authority.md`.
