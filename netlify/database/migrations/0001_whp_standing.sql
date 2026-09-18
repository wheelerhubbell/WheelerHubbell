
CREATE TABLE IF NOT EXISTS purchases(
 id TEXT PRIMARY KEY, buyer_key TEXT NOT NULL, client_reference TEXT NOT NULL,
 request_hash TEXT NOT NULL, state TEXT NOT NULL,
 payment_key TEXT UNIQUE, record TEXT NOT NULL, result_bytes TEXT,
 lease_owner TEXT, lease_until BIGINT NOT NULL DEFAULT 0,
 UNIQUE(buyer_key,client_reference)
);
CREATE TABLE IF NOT EXISTS registry_events(
 purchase_id TEXT NOT NULL REFERENCES purchases(id), sequence INTEGER NOT NULL,
 event_bytes TEXT NOT NULL, event_hash TEXT NOT NULL,
 PRIMARY KEY(purchase_id,sequence)
);
CREATE TABLE IF NOT EXISTS review_requests(
 review_id TEXT PRIMARY KEY, purchase_id TEXT NOT NULL REFERENCES purchases(id), record TEXT NOT NULL
);
