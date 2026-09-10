PRAGMA foreign_keys = ON;

CREATE TABLE agent_definitions (
    agent_id TEXT PRIMARY KEY NOT NULL,
    current_release_id TEXT NOT NULL,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE agent_releases (
    release_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agent_definitions(agent_id),
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);
CREATE INDEX idx_agent_releases_agent ON agent_releases(agent_id);

CREATE TABLE behavioral_manifests (
    release_id TEXT PRIMARY KEY NOT NULL REFERENCES agent_releases(release_id),
    digest TEXT NOT NULL UNIQUE,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE agent_instances (
    instance_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agent_definitions(agent_id),
    release_id TEXT NOT NULL REFERENCES agent_releases(release_id),
    public_key TEXT NOT NULL UNIQUE,
    key_fingerprint TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','CONTAINED','RECOVERY_PENDING','REVOKED')),
    containment_epoch INTEGER NOT NULL CHECK (containment_epoch >= 0)
);
CREATE INDEX idx_agent_instances_agent ON agent_instances(agent_id);

CREATE TABLE agent_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL REFERENCES agent_instances(instance_id),
    state TEXT NOT NULL CHECK (state IN ('CREATED','ACTIVE','TERMINATED','EXPIRED','REVOKED')),
    session_epoch INTEGER NOT NULL CHECK (session_epoch >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX idx_agent_sessions_instance ON agent_sessions(instance_id);

CREATE TABLE mandates (
    mandate_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agent_definitions(agent_id),
    budget_id TEXT NOT NULL UNIQUE,
    not_before INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > not_before),
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE budget_ledgers (
    budget_id TEXT PRIMARY KEY NOT NULL,
    mandate_id TEXT NOT NULL UNIQUE REFERENCES mandates(mandate_id),
    action_capacity INTEGER NOT NULL CHECK (action_capacity >= 0),
    read_capacity INTEGER NOT NULL CHECK (read_capacity >= 0),
    write_capacity INTEGER NOT NULL CHECK (write_capacity >= 0),
    action_consumed INTEGER NOT NULL DEFAULT 0 CHECK (action_consumed >= 0),
    read_consumed INTEGER NOT NULL DEFAULT 0 CHECK (read_consumed >= 0),
    write_consumed INTEGER NOT NULL DEFAULT 0 CHECK (write_consumed >= 0),
    action_reserved INTEGER NOT NULL DEFAULT 0 CHECK (action_reserved >= 0),
    read_reserved INTEGER NOT NULL DEFAULT 0 CHECK (read_reserved >= 0),
    write_reserved INTEGER NOT NULL DEFAULT 0 CHECK (write_reserved >= 0),
    CHECK (action_consumed + action_reserved <= action_capacity),
    CHECK (read_consumed + read_reserved <= read_capacity),
    CHECK (write_consumed + write_reserved <= write_capacity)
);

CREATE TABLE budget_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    budget_id TEXT NOT NULL REFERENCES budget_ledgers(budget_id),
    session_id TEXT NOT NULL REFERENCES agent_sessions(session_id),
    state TEXT NOT NULL CHECK (state IN ('RESERVED','COMMITTED','RELEASED')),
    action_count INTEGER NOT NULL CHECK (action_count >= 0),
    read_bytes INTEGER NOT NULL CHECK (read_bytes >= 0),
    write_bytes INTEGER NOT NULL CHECK (write_bytes >= 0)
);
CREATE INDEX idx_budget_reservations_budget_state ON budget_reservations(budget_id, state);
CREATE INDEX idx_budget_reservations_session_state ON budget_reservations(session_id, state);

CREATE TABLE action_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES agent_sessions(session_id),
    action_kind TEXT NOT NULL CHECK (action_kind IN ('LIST_DIRECTORY','READ_FILE','COMPUTE_SHA256','WRITE_REPORT')),
    resource TEXT NOT NULL,
    request_digest TEXT NOT NULL UNIQUE,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE decision_records (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE REFERENCES action_requests(request_id),
    decision TEXT NOT NULL CHECK (decision IN ('PERMIT','DENY','QUARANTINE')),
    reason_code TEXT NOT NULL,
    decided_at INTEGER NOT NULL,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE execution_permits (
    permit_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL UNIQUE REFERENCES action_requests(request_id),
    reservation_id TEXT NOT NULL UNIQUE REFERENCES budget_reservations(reservation_id),
    audience_pep_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    session_epoch INTEGER NOT NULL CHECK (session_epoch >= 0),
    containment_epoch INTEGER NOT NULL CHECK (containment_epoch >= 0),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);

CREATE TABLE containment_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL REFERENCES agent_instances(instance_id),
    expected_epoch INTEGER NOT NULL CHECK (expected_epoch >= 0),
    new_epoch INTEGER NOT NULL CHECK (new_epoch = expected_epoch + 1),
    reason_code TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);
CREATE INDEX idx_containment_events_instance ON containment_events(instance_id, new_epoch);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    current_hash TEXT NOT NULL UNIQUE,
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json))
);
