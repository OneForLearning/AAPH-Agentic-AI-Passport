CREATE TABLE consumed_jtis(
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE effect_operations(
    effect_operation_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL UNIQUE,
    jti TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE,
    tenant TEXT NOT NULL CHECK(tenant = 'NON_PRODUCTION_DEMO'),
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('RECEIVED','STARTED','COMPLETED','FAILED','AMBIGUOUS')),
    result_digest TEXT,
    result_json TEXT CHECK(result_json IS NULL OR json_valid(result_json)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK((state = 'COMPLETED' AND result_digest IS NOT NULL AND result_json IS NOT NULL)
       OR (state <> 'COMPLETED'))
);
