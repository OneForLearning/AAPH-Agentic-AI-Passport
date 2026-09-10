use aaph_core::action::ReasonCode;
use aaph_core::audit::verify_audit_chain;
use aaph_core::ids::{InstanceId, RequestId};
use aaph_core::signed::SignedActionProposal;
use axum::extract::{Path, Request as AxumRequest, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

static CORRELATION_IDS: AtomicU64 = AtomicU64::new(1);

use crate::orchestrator::{
    ApiFailure, ApiReason, AuthorityOrchestrator, LocalDiagnostic, SignedSessionRequest,
};
use crate::storage::{AuditRepository, DecisionRepository, StateRepository};

pub fn public_router(state: AuthorityOrchestrator) -> Router {
    Router::new()
        .route("/v1/sessions", post(create_session))
        .route("/v1/actions/propose", post(propose))
        .route("/v1/instances/:instance_id", get(instance))
        .route("/v1/decisions/:request_id", get(decision))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/audit/export", get(audit_export))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(correlation))
        .with_state(state)
}

pub fn admin_router(state: AuthorityOrchestrator) -> Router {
    Router::new()
        .route("/v1/admin/instances/:instance_id/recovery", post(recovery))
        .layer(middleware::from_fn(correlation))
        .with_state(state)
}

pub fn router(state: AuthorityOrchestrator) -> Router {
    Router::new()
        .route("/health", get(health))
        .merge(public_router(state.clone()))
        .merge(admin_router(state))
}

async fn correlation(request: AxumRequest, next: Next) -> Response {
    let id = format!("aaph-{}", CORRELATION_IDS.fetch_add(1, Ordering::Relaxed));
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if let Ok(value) = axum::http::HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-correlation-id", value);
    }
    tracing::info!(correlation_id = %id, %method, %path, status = response.status().as_u16(), "request completed");
    response
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    marker: &'static str,
}
async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        marker: "NON_PRODUCTION_DEMO",
    })
}

async fn create_session(
    State(state): State<AuthorityOrchestrator>,
    request: AxumRequest,
) -> Result<Json<crate::orchestrator::SessionResponse>, ApiFailure> {
    let body = bounded_body(request, state.config.policy_file.max_body_bytes).await?;
    let request = serde_json::from_slice::<SignedSessionRequest>(&body).map_err(|_| schema())?;
    let result = state.create_session(request).await;
    match &result {
        Ok(session) => {
            tracing::info!(
                session_id = session.session_id.as_str(),
                "session transition CREATED->ACTIVE"
            );
        }
        Err(error) => tracing::warn!(reason = ?error.reason, "session creation denied"),
    }
    result.map(Json)
}

async fn propose(
    State(state): State<AuthorityOrchestrator>,
    request: AxumRequest,
) -> Result<Json<crate::orchestrator::ActionResponse>, ApiFailure> {
    let body = bounded_body(request, state.config.policy_file.max_body_bytes).await?;
    let request = serde_json::from_slice::<SignedActionProposal>(&body).map_err(|_| schema())?;
    let result = state.propose(request).await;
    match &result {
        Ok(response) => {
            tracing::info!(decision = ?response.decision.decision, reason = ?response.decision.reason, "authorization decision");
        }
        Err(error) => tracing::warn!(reason = ?error.reason, "authorization request rejected"),
    }
    result.map(Json)
}

async fn instance(
    State(state): State<AuthorityOrchestrator>,
    Path(id): Path<String>,
) -> Result<Json<crate::storage::InstanceSnapshot>, ApiFailure> {
    let id = InstanceId::new(id).map_err(|_| schema())?;
    state
        .store
        .get_instance(&id)
        .await
        .map(Json)
        .map_err(|_| not_found())
}

async fn decision(
    State(state): State<AuthorityOrchestrator>,
    Path(id): Path<String>,
) -> Result<Json<aaph_core::permit::DecisionRecord>, ApiFailure> {
    let id = RequestId::new(id).map_err(|_| schema())?;
    state
        .store
        .get_decision(&id)
        .await
        .map(Json)
        .map_err(|_| not_found())
}

#[derive(Serialize)]
struct AuditStatus {
    valid: bool,
    event_count: usize,
}
async fn audit_verify(
    State(state): State<AuthorityOrchestrator>,
) -> Result<Json<AuditStatus>, ApiFailure> {
    let events = state
        .store
        .load_audit_chain()
        .await
        .map_err(|_| internal())?;
    verify_audit_chain(&events).map_err(|_| internal())?;
    Ok(Json(AuditStatus {
        valid: true,
        event_count: events.len(),
    }))
}

async fn audit_export(
    State(state): State<AuthorityOrchestrator>,
) -> Result<Json<Vec<aaph_core::permit::AuditEvent>>, ApiFailure> {
    state
        .store
        .load_audit_chain()
        .await
        .map(Json)
        .map_err(|_| internal())
}

async fn metrics(State(state): State<AuthorityOrchestrator>) -> Result<String, ApiFailure> {
    let rows = sqlx::query("SELECT decision, reason_code, COUNT(*) AS total FROM decisions GROUP BY decision, reason_code")
        .fetch_all(state.store.pool()).await.map_err(|_| internal())?;
    let mut permits = 0_i64;
    let mut denies = 0_i64;
    let mut quarantines = 0_i64;
    let mut replays = 0_i64;
    for row in rows {
        use sqlx::Row as _;
        let decision: String = row.try_get("decision").map_err(|_| internal())?;
        let reason: String = row.try_get("reason_code").map_err(|_| internal())?;
        let total: i64 = row.try_get("total").map_err(|_| internal())?;
        match decision.as_str() {
            "PERMIT" => permits += total,
            "DENY" => denies += total,
            "QUARANTINE" => quarantines += total,
            _ => return Err(internal()),
        }
        if reason == "E_REPLAY" {
            replays += total;
        }
    }
    let delay = crate::dispatcher::last_propagation_millis();
    Ok(format!("aaph_permits_total {permits}\naaph_denies_total {denies}\naaph_quarantines_total {quarantines}\naaph_replays_total {replays}\naaph_containment_propagation_delay_milliseconds {delay}\n"))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRequest {
    validation: bool,
}
async fn recovery(
    State(state): State<AuthorityOrchestrator>,
    Path(id): Path<String>,
    headers: HeaderMap,
    request: AxumRequest,
) -> Result<Json<serde_json::Value>, ApiFailure> {
    let body = bounded_body(request, state.config.policy_file.max_body_bytes).await?;
    let input: RecoveryRequest = serde_json::from_slice(&body).map_err(|_| schema())?;
    let secret = headers
        .get("x-aaph-admin-secret")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let instance = InstanceId::new(id).map_err(|_| schema())?;
    if let Err(error) = state.recover(&instance, secret, input.validation).await {
        tracing::warn!(reason = ?error.reason, "recovery denied");
        return Err(error);
    }
    tracing::info!(
        instance_id = instance.as_str(),
        "instance transition RECOVERY_PENDING->ACTIVE with new epoch"
    );
    Ok(Json(
        serde_json::json!({"state":"ACTIVE","new_session_required":true}),
    ))
}

#[derive(Serialize)]
struct ErrorBody {
    reason: ApiReason,
}
impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                reason: self.reason,
            }),
        )
            .into_response()
    }
}
fn schema() -> ApiFailure {
    ApiFailure {
        status: StatusCode::BAD_REQUEST,
        reason: ApiReason::Registered(ReasonCode::SchemaInvalid),
    }
}
async fn bounded_body(request: AxumRequest, limit: usize) -> Result<axum::body::Bytes, ApiFailure> {
    axum::body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiFailure {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            reason: ApiReason::Registered(ReasonCode::SchemaInvalid),
        })
}
fn not_found() -> ApiFailure {
    ApiFailure {
        status: StatusCode::NOT_FOUND,
        reason: ApiReason::Local(LocalDiagnostic::InternalFailClosed),
    }
}
fn internal() -> ApiFailure {
    ApiFailure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        reason: ApiReason::Local(LocalDiagnostic::InternalFailClosed),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use aaph_core::action::{ActionKind, RawActionProposal};
    use aaph_core::crypto::SigningKeyMaterial;
    use aaph_core::ids::{InstanceId, RequestId, SessionId};
    use aaph_core::signed::{SignedActionProposal, SignedArtifact};
    use aaph_core::UtcTimestamp;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::clock::FixedClock;
    use crate::configuration::DemoConfig;
    use crate::dispatcher::DeterministicNoopDispatcher;
    use crate::dispatcher::{ContainmentSink, EffectDispatcher, PermitDispatcher};
    use crate::id_generator::ProductionIdGenerator;
    use crate::orchestrator::{
        AuthorityOrchestrator, Ed25519PermitSigner, PermitSigner, SessionRequest,
    };
    use crate::storage::SqliteStore;

    static DB: AtomicU64 = AtomicU64::new(1);
    const NOW: i64 = 1_780_000_000;

    struct FailingSigner;
    impl PermitSigner for FailingSigner {
        fn sign(
            &self,
            _permit: aaph_core::permit::ExecutionPermit,
        ) -> Result<aaph_core::signed::SignedExecutionPermit, crate::orchestrator::PermitSigningError>
        {
            Err(crate::orchestrator::PermitSigningError)
        }
        fn sign_containment(
            &self,
            _event: aaph_core::permit::ContainmentEvent,
        ) -> Result<
            aaph_core::signed::SignedContainmentEvent,
            crate::orchestrator::PermitSigningError,
        > {
            Err(crate::orchestrator::PermitSigningError)
        }
    }
    struct FailingPropagation;
    #[async_trait]
    impl PermitDispatcher for FailingPropagation {
        async fn accept(
            &self,
            _permit: &aaph_core::signed::SignedExecutionPermit,
        ) -> Result<(), ()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ContainmentSink for FailingPropagation {
        async fn propagate_containment(
            &self,
            _event: &aaph_core::signed::SignedContainmentEvent,
        ) -> Result<(), ()> {
            Err(())
        }
    }

    async fn setup(
        mut change: impl FnMut(&mut DemoConfig),
        failing: bool,
    ) -> (Router, SqliteStore, SigningKeyMaterial) {
        setup_dispatcher(&mut change, failing, Arc::new(DeterministicNoopDispatcher)).await
    }
    async fn setup_dispatcher(
        mut change: impl FnMut(&mut DemoConfig),
        failing: bool,
        dispatcher: Arc<dyn EffectDispatcher>,
    ) -> (Router, SqliteStore, SigningKeyMaterial) {
        let id = DB.fetch_add(1, Ordering::Relaxed);
        let url = format!("sqlite:file:api-{id}?mode=memory&cache=shared");
        let store = SqliteStore::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let mut config =
            DemoConfig::load(&directory, UtcTimestamp::from_unix_seconds(NOW)).unwrap();
        change(&mut config);
        let bootstrap_key = SigningKeyMaterial::generate().public_key();
        crate::bootstrap(&store, &config, &bootstrap_key)
            .await
            .unwrap();
        let agent_key = SigningKeyMaterial::generate();
        let public = agent_key.public_key();
        let fingerprint = aaph_core::crypto::public_key_fingerprint(&public).unwrap();
        sqlx::query("UPDATE agent_instances SET public_key=?,key_fingerprint=? WHERE instance_id='demo-instance'")
            .bind(public.as_str()).bind(fingerprint.as_str()).execute(store.pool()).await.unwrap();
        let signer: Arc<dyn PermitSigner> = if failing {
            Arc::new(FailingSigner)
        } else {
            Arc::new(Ed25519PermitSigner(SigningKeyMaterial::generate()))
        };
        let state = AuthorityOrchestrator {
            store: store.clone(),
            config: Arc::new(config),
            clock: Arc::new(FixedClock(NOW)),
            signer,
            dispatcher,
            id_generator: Arc::new(ProductionIdGenerator),
            admin_secret: Arc::new("test-secret".to_owned()),
            issuance_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        (crate::AuthorityApp::new(state).router(), store, agent_key)
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn session(app: Router, key: &SigningKeyMaterial, id: &str) -> (Router, StatusCode) {
        let envelope = SignedArtifact::sign(
            SessionRequest {
                instance_id: InstanceId::new("demo-instance").unwrap(),
                session_id: SessionId::new(id).unwrap(),
                issued_at: UtcTimestamp::from_unix_seconds(NOW),
            },
            key,
        )
        .unwrap();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v1/sessions",
            serde_json::to_vec(&envelope).unwrap(),
        )
        .await;
        (app, status)
    }

    fn proposal(
        key: &SigningKeyMaterial,
        request: &str,
        session: &str,
        action: &str,
        resource: &str,
        size: u64,
    ) -> Vec<u8> {
        let value = RawActionProposal {
            request_id: RequestId::new(request).unwrap(),
            session_id: SessionId::new(session).unwrap(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            size_bytes: Some(size),
            purpose: "analysis".to_owned(),
            destination: None,
        };
        serde_json::to_vec(&SignedActionProposal::sign(value, key).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn authority_router_builds_in_memory_without_socket() {
        let (app, _store, _key) = setup(|_| {}, false).await;
        assert_eq!(
            call(app, "GET", "/health", Vec::new()).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn health_session_and_instance_state_guards() {
        let (app, store, key) = setup(|_| {}, false).await;
        assert_eq!(
            call(app.clone(), "GET", "/health", vec![]).await.0,
            StatusCode::OK
        );
        let (app, status) = session(app, &key, "session-ok").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            call(app.clone(), "GET", "/v1/instances/demo-instance", vec![])
                .await
                .0,
            StatusCode::OK
        );
        sqlx::query(
            "UPDATE agent_instances SET state='CONTAINED' WHERE instance_id='demo-instance'",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert_eq!(
            session(app.clone(), &key, "session-contained").await.1,
            StatusCode::FORBIDDEN
        );
        sqlx::query("UPDATE agent_instances SET state='REVOKED' WHERE instance_id='demo-instance'")
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            session(app, &key, "session-revoked").await.1,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn signature_expiration_replay_and_permit_binding() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "session-a").await;
        let wrong = SigningKeyMaterial::generate();
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(&wrong, "wrong", "session-a", "READ_FILE", "inbox/a", 2)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, json) = call(
            app.clone(),
            "POST",
            "/v1/actions/propose",
            proposal(&key, "good", "session-a", "READ_FILE", "inbox/a", 2),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["decision"]["decision"], "PERMIT");
        assert!(json["permit"]["artifact"]["request_digest"]
            .as_str()
            .is_some());
        assert_eq!(
            call(app.clone(), "GET", "/v1/decisions/good", vec![])
                .await
                .0,
            StatusCode::OK
        );
        let (repeat_status, repeated) = call(
            app.clone(),
            "POST",
            "/v1/actions/propose",
            proposal(&key, "good", "session-a", "READ_FILE", "inbox/a", 2),
        )
        .await;
        assert_eq!(repeat_status, StatusCode::OK);
        assert_eq!(repeated["permit"], json["permit"]);
        let reservation_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM budget_reservations")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(reservation_count, 1);
        let (different_status, different) = call(
            app.clone(),
            "POST",
            "/v1/actions/propose",
            proposal(&key, "good", "session-a", "READ_FILE", "inbox/b", 2),
        )
        .await;
        assert_eq!(different_status, StatusCode::CONFLICT);
        assert_eq!(different["reason"], "E_SCHEMA_INVALID");
        let unchanged_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM budget_reservations")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(unchanged_count, 1);
        sqlx::query(
            "UPDATE agent_sessions SET created_at=?,expires_at=? WHERE session_id='session-a'",
        )
        .bind(NOW - 100)
        .bind(NOW - 1)
        .execute(store.pool())
        .await
        .unwrap();
        assert_eq!(
            call(
                app,
                "POST",
                "/v1/actions/propose",
                proposal(&key, "expired", "session-a", "READ_FILE", "inbox/a", 2)
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn idempotency_same_request_returns_same_reservation() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "idempotent-session").await;
        let body = proposal(
            &key,
            "idempotent-request",
            "idempotent-session",
            "READ_FILE",
            "inbox/a",
            2,
        );
        let (_, first) = call(app.clone(), "POST", "/v1/actions/propose", body.clone()).await;
        let (_, second) = call(app, "POST", "/v1/actions/propose", body).await;
        assert_eq!(first["permit"], second["permit"]);
        for table in [
            "budget_reservations",
            "action_requests",
            "decision_records",
            "execution_permits",
        ] {
            let query = format!("SELECT COUNT(*) FROM {table}");
            let count: i64 = sqlx::query_scalar(&query)
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert_eq!(count, 1, "unexpected mutation in {table}");
        }
    }

    #[tokio::test]
    async fn concurrent_same_idempotency_key_consumes_budget_once() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "concurrent-idempotency-session").await;
        let body = proposal(
            &key,
            "concurrent-idempotency-request",
            "concurrent-idempotency-session",
            "READ_FILE",
            "inbox/a",
            2,
        );
        let (first, second) = tokio::join!(
            call(app.clone(), "POST", "/v1/actions/propose", body.clone()),
            call(app, "POST", "/v1/actions/propose", body)
        );
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(second.0, StatusCode::OK);
        assert_eq!(first.1["permit"], second.1["permit"]);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM budget_reservations")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn same_key_different_digest_mutates_nothing() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "conflict-session").await;
        let _ = call(
            app.clone(),
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "same-key",
                "conflict-session",
                "READ_FILE",
                "inbox/a",
                2,
            ),
        )
        .await;
        let (status, _) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "same-key",
                "conflict-session",
                "READ_FILE",
                "inbox/b",
                2,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        for table in [
            "budget_reservations",
            "action_requests",
            "decision_records",
            "execution_permits",
        ] {
            let query = format!("SELECT COUNT(*) FROM {table}");
            let count: i64 = sqlx::query_scalar(&query)
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert_eq!(count, 1, "unexpected mutation in {table}");
        }
    }

    #[tokio::test]
    async fn credential_persisted_before_return() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "persist-session").await;
        let (status, response) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "persist-request",
                "persist-session",
                "READ_FILE",
                "inbox/a",
                2,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let permit_id = response["permit"]["artifact"]["permit_id"]
            .as_str()
            .unwrap();
        let jti = response["permit"]["artifact"]["jti"].as_str().unwrap();
        let operation_id = response["permit"]["artifact"]["effect_operation_id"]
            .as_str()
            .unwrap();
        let nonce = response["permit"]["artifact"]["nonce"].as_str().unwrap();
        for identifier in [permit_id, jti, operation_id] {
            assert_eq!(identifier.len(), 36);
            assert_eq!(&identifier[14..15], "7");
            assert!(matches!(&identifier[19..20], "8" | "9" | "a" | "b"));
        }
        assert_ne!(permit_id, jti);
        assert_ne!(permit_id, operation_id);
        assert_ne!(jti, operation_id);
        assert_eq!(nonce.len(), 22);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM execution_permits WHERE permit_id=?")
                .bind(permit_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn authority_manifest_budget_and_signing_fail_closed() {
        let (app, _, key) = setup(
            |config| {
                config
                    .mandate
                    .allowed_actions
                    .retain(|a| *a != ActionKind::WriteReport);
            },
            false,
        )
        .await;
        let (app, _) = session(app, &key, "s-mandate").await;
        let (_, json) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "outside-mandate",
                "s-mandate",
                "WRITE_REPORT",
                "output/a",
                2,
            ),
        )
        .await;
        assert_eq!(json["decision"]["reason"], "E_ACTION_NOT_ALLOWED");

        let (app, _, key) = setup(
            |config| {
                config
                    .manifest
                    .allowed_actions
                    .retain(|a| *a != ActionKind::WriteReport);
            },
            false,
        )
        .await;
        let (app, _) = session(app, &key, "s-manifest").await;
        let (_, json) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "outside-manifest",
                "s-manifest",
                "WRITE_REPORT",
                "output/a",
                2,
            ),
        )
        .await;
        assert_eq!(json["decision"]["decision"], "QUARANTINE");

        let (app, store, key) =
            setup(|config| config.policy_file.budget.action_count = 0, false).await;
        let (app, _) = session(app, &key, "s-budget").await;
        let (status, json) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(&key, "budget", "s-budget", "READ_FILE", "inbox/a", 2),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["decision"]["reason"], "E_BUDGET_EXCEEDED");
        let permits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_permits")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(permits, 0);

        let (app, store, key) = setup(|_| {}, true).await;
        let (app, _) = session(app, &key, "s-sign").await;
        assert_eq!(
            call(
                app,
                "POST",
                "/v1/actions/propose",
                proposal(&key, "sign-fail", "s-sign", "READ_FILE", "inbox/a", 2)
            )
            .await
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let reserved: i64 = sqlx::query_scalar("SELECT action_reserved FROM budget_ledgers")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(reserved, 0);
    }

    #[tokio::test]
    async fn strict_body_and_audit_for_permit_and_deny() {
        let (app, _, key) = setup(|_| {}, false).await;
        let mut unknown = serde_json::to_value(
            SignedArtifact::sign(
                SessionRequest {
                    instance_id: InstanceId::new("demo-instance").unwrap(),
                    session_id: SessionId::new("unknown").unwrap(),
                    issued_at: UtcTimestamp::from_unix_seconds(NOW),
                },
                &key,
            )
            .unwrap(),
        )
        .unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::Value::Bool(true));
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/sessions",
                serde_json::to_vec(&unknown).unwrap()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(app.clone(), "POST", "/v1/sessions", vec![b'x'; 70_000])
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let (app, _) = session(app, &key, "s-audit").await;
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(&key, "audit-permit", "s-audit", "READ_FILE", "inbox/a", 2)
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(
                    &key,
                    "audit-deny",
                    "s-audit",
                    "READ_FILE",
                    "inbox/a",
                    2_000_000
                )
            )
            .await
            .0,
            StatusCode::OK
        );
        let (_, json) = call(app, "GET", "/v1/audit/verify", vec![]).await;
        assert_eq!(json["valid"], true);
        assert!(json["event_count"].as_u64().unwrap() >= 3);
    }

    #[tokio::test]
    async fn recovery_requires_new_session() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "quarantine-session").await;
        let before: (i64, i64) =
            sqlx::query_as("SELECT action_consumed,read_consumed FROM budget_ledgers")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let hostile = proposal(
            &key,
            "hostile",
            "quarantine-session",
            "READ_FILE",
            "inbox/../secret",
            2,
        );
        let (_, json) = call(app.clone(), "POST", "/v1/actions/propose", hostile).await;
        assert_eq!(json["decision"]["decision"], "QUARANTINE");
        let state: (String, i64) = sqlx::query_as(
            "SELECT state,containment_epoch FROM agent_instances WHERE instance_id='demo-instance'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state, ("CONTAINED".to_owned(), 1));
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(
                    &key,
                    "later",
                    "quarantine-session",
                    "READ_FILE",
                    "inbox/a",
                    2
                )
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                app.clone(),
                "POST",
                "/v1/admin/instances/demo-instance/recovery",
                br#"{"validation":true}"#.to_vec()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let invalid = Request::builder()
            .method("POST")
            .uri("/v1/admin/instances/demo-instance/recovery")
            .header("x-aaph-admin-secret", "test-secret")
            .body(Body::from(br#"{"validation":false}"#.to_vec()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(invalid).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let valid = Request::builder()
            .method("POST")
            .uri("/v1/admin/instances/demo-instance/recovery")
            .header("x-aaph-admin-secret", "test-secret")
            .body(Body::from(br#"{"validation":true}"#.to_vec()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(valid).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            session(app.clone(), &key, "new-session").await.1,
            StatusCode::OK
        );
        assert_eq!(
            session(app, &key, "quarantine-session").await.1,
            StatusCode::FORBIDDEN
        );
        let after: (i64, i64) =
            sqlx::query_as("SELECT action_consumed,read_consumed FROM budget_ledgers")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(before, after);
        let recovery_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='INSTANCE_RECOVERED'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(recovery_audits, 1);
    }

    #[tokio::test]
    async fn pep_failure_after_containment_is_visible_and_fail_closed() {
        let (app, store, key) = setup(|_| {}, false).await;
        let (app, _) = session(app, &key, "race-session").await;
        let (a, b) = tokio::join!(
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(&key, "race-a", "race-session", "READ_FILE", "inbox/../a", 1)
            ),
            call(
                app.clone(),
                "POST",
                "/v1/actions/propose",
                proposal(&key, "race-b", "race-session", "READ_FILE", "inbox/../b", 1)
            )
        );
        assert!(a.0 == StatusCode::OK || b.0 == StatusCode::OK);
        let epoch: i64 = sqlx::query_scalar(
            "SELECT containment_epoch FROM agent_instances WHERE instance_id='demo-instance'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(epoch, 1);
        let (app, _, key) = setup_dispatcher(|_| {}, false, Arc::new(FailingPropagation)).await;
        let (app, _) = session(app, &key, "fail-session").await;
        let (_, json) = call(
            app,
            "POST",
            "/v1/actions/propose",
            proposal(
                &key,
                "fail-propagation",
                "fail-session",
                "READ_FILE",
                "inbox/../x",
                1,
            ),
        )
        .await;
        assert_eq!(json["containment_propagation_incomplete"], true);
    }
}
