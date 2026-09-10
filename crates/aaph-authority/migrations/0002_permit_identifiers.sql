-- Non-destructive Sprint 14 extension. Existing permit rows remain readable;
-- every newly issued permit supplies all three columns.
ALTER TABLE execution_permits ADD COLUMN jti TEXT;
ALTER TABLE execution_permits ADD COLUMN effect_operation_id TEXT;
CREATE UNIQUE INDEX idx_execution_permits_jti
    ON execution_permits(jti) WHERE jti IS NOT NULL;
CREATE UNIQUE INDEX idx_execution_permits_effect_operation_id
    ON execution_permits(effect_operation_id) WHERE effect_operation_id IS NOT NULL;
