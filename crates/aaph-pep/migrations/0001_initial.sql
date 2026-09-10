CREATE TABLE IF NOT EXISTS instance_epochs(
    instance_id TEXT PRIMARY KEY,
    session_epoch INTEGER NOT NULL CHECK(session_epoch >= 0),
    containment_epoch INTEGER NOT NULL CHECK(containment_epoch >= 0)
);
CREATE TABLE IF NOT EXISTS consumed_nonces(
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS containment_events(
    instance_id TEXT NOT NULL,
    containment_epoch INTEGER NOT NULL,
    signed_digest TEXT NOT NULL,
    PRIMARY KEY(instance_id, containment_epoch)
);
CREATE TABLE IF NOT EXISTS result_digests(
    nonce TEXT PRIMARY KEY,
    result_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
