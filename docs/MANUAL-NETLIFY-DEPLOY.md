# Manual Netlify deployment

Import `wheelerhubbell/WheelerHubbellPublishingStandingMark`, branch `main`. The repository supplies the build command, `public` publish directory, function directory, Node 24, Python dependencies, the signed public authority, and verifier artifacts. The runtime uses Netlify's site `URL` unless `WHP_ORIGIN` is explicitly set. Do not copy the previous site's `WHP_ORIGIN` or `WHP_RESOLUTION_URL` to a different URL. Omitting `WHP_RESOLUTION_URL` makes discovery use the current site's resolver.

A new account does not contain the previous site's secrets or database. Before deploying, supply the existing `WHP_ISSUER_PRIVATE_KEY`, `WHP_PAYMENT_REQUIREMENTS_JSON`, `WHP_FACILITATOR_URL`, and `WHP_RPC_URL` through Netlify environment variables available to Builds and Functions. Keep private keys outside GitHub. Preserve the existing issuer and payment destination; creating unrelated keys will not authorize this profile.

The committed signed root and trust bundle are the defaults. `WHP_ROOT_PIN` and `WHP_TRUST_BUNDLE_JSON` may explicitly supply the same authorized identity and a current signed status snapshot. The build rejects expired or mismatched authority. The original profile ratification remains preserved with its historical origin; current machine discovery signs the runtime's configured origin.

Provision a Netlify PostgreSQL database and set `WHP_USE_NETLIFY_DATABASE=true`, or supply an authorized PostgreSQL `DATABASE_URL`. The build performs the existing idempotent schema migration and checks database access before publication. It does not authorize a payment. A different empty database does not carry over historical purchases; preserve the existing database or migrate its records before claiming recovery continuity.

The build reports missing configuration before running the full acquisition gate. A missing signing key or database remains a deployment blocker; a successful TEST gate cannot supply either. The downloaded verifier and historical immutable objects are explicitly included in the function bundle.

The previous site's GitHub administration workflow is now manual only; this change does not deploy to that site. The new site still needs current signed status publication. The committed status snapshot expires at its signed `valid_until`; a new account does not renew it automatically. Existing-key status renewal must be configured for the new account before that expiry. Do not generate a replacement root or relabel TEST evidence as LIVE.

After the first deploy, verify the live contract, signed discovery, and unpaid acquisition boundary. The real paid A-to-B chain remains mandatory after deployment before claiming production completion. No new-account deployment or LIVE chain has been verified by these repository changes.
