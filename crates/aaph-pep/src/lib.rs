pub mod executor;
pub mod operation;
pub mod replay;
pub mod sandbox;
pub mod verification;
use aaph_core::action::ReasonCode;
use aaph_core::crypto::{digest, PublicKeyValue, ACTION_PROPOSAL_DOMAIN, AUDIT_EVENT_DOMAIN};
use aaph_core::ids::PepId;
use aaph_core::signed::{artifact_digest, SignedContainmentEvent};
use aaph_core::UtcTimestamp;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use executor::EffectResult;
use operation::{OperationExecutor, WorkspaceOperationExecutor};
use replay::{ApplyResult, PepStore, ReceiveOperation, ReceiveOperationInput};
use sandbox::Workspace;
use verification::EffectRequest;

static CORRELATION_IDS: AtomicU64 = AtomicU64::new(1);

pub trait Clock: Send + Sync {
    fn now(&self) -> UtcTimestamp;
}
#[derive(Clone)]
struct AppState {
    store: PepStore,
    executor: Arc<dyn OperationExecutor>,
    authority: PublicKeyValue,
    audience: PepId,
    clock: Arc<dyn Clock>,
    body_limit: usize,
    max_lifetime: u64,
}

/// In-memory PEP application assembled from typed capabilities.
///
/// The workspace capability is required here, making the PEP the sole crate
/// able to construct routes that can produce protected file effects.
pub struct PepApp {
    state: AppState,
}

pub struct PepAppConfig {
    pub authority: PublicKeyValue,
    pub audience: PepId,
    pub body_limit: usize,
    pub max_lifetime: u64,
}

impl PepApp {
    #[must_use]
    pub fn new(
        store: PepStore,
        workspace: Arc<Workspace>,
        clock: Arc<dyn Clock>,
        config: PepAppConfig,
    ) -> Self {
        Self::with_executor(
            store,
            Arc::new(WorkspaceOperationExecutor::new(workspace)),
            clock,
            config,
        )
    }

    #[must_use]
    pub fn with_executor(
        store: PepStore,
        executor: Arc<dyn OperationExecutor>,
        clock: Arc<dyn Clock>,
        config: PepAppConfig,
    ) -> Self {
        Self {
            state: AppState {
                store,
                executor,
                authority: config.authority,
                audience: config.audience,
                clock,
                body_limit: config.body_limit,
                max_lifetime: config.max_lifetime,
            },
        }
    }

    pub fn router(self) -> Router {
        router(self.state)
    }

    pub fn public_router(&self) -> Router {
        public_router(self.state.clone())
    }

    pub fn internal_router(&self) -> Router {
        internal_router(self.state.clone())
    }
}
#[derive(Serialize)]
struct ErrorBody {
    reason: ApiReason,
}
#[derive(Serialize)]
#[serde(untagged)]
enum ApiReason {
    Registered(ReasonCode),
    Local(LocalReason),
}
#[derive(Serialize)]
enum LocalReason {
    #[serde(rename = "LOCAL_INTERNAL_FAIL_CLOSED")]
    InternalFailClosed,
    #[serde(rename = "LOCAL_EFFECT_AMBIGUOUS")]
    EffectAmbiguous,
}
struct Failure(StatusCode, ApiReason);
impl Failure {
    fn registered(status: StatusCode, reason: ReasonCode) -> Self {
        Self(status, ApiReason::Registered(reason))
    }
    fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiReason::Local(LocalReason::InternalFailClosed),
        )
    }
    fn ambiguous() -> Self {
        Self(
            StatusCode::CONFLICT,
            ApiReason::Local(LocalReason::EffectAmbiguous),
        )
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorBody { reason: self.1 })).into_response()
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({"status":"ok","marker":"NON_PRODUCTION_DEMO"}))
            }),
        )
        .merge(public_router(state.clone()))
        .merge(internal_router(state))
}

fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/effects/execute", post(execute_effect))
        .layer(axum::middleware::from_fn(correlation))
        .with_state(state)
}

fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/internal/v1/containment-events", post(containment))
        .layer(axum::middleware::from_fn(correlation))
        .with_state(state)
}
async fn correlation(request: Request, next: axum::middleware::Next) -> Response {
    let id = format!("pep-{}", CORRELATION_IDS.fetch_add(1, Ordering::Relaxed));
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if let Ok(value) = axum::http::HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-correlation-id", value);
    }
    tracing::info!(correlation_id = %id, %method, %path, status = response.status().as_u16(), "request completed");
    response
}
async fn body(request: Request, limit: usize) -> Result<axum::body::Bytes, Failure> {
    axum::body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| Failure::registered(StatusCode::PAYLOAD_TOO_LARGE, ReasonCode::SchemaInvalid))
}
async fn execute_effect(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<EffectResult>, Failure> {
    let bytes = body(request, state.body_limit).await?;
    let input: EffectRequest = serde_json::from_slice(&bytes)
        .map_err(|_| Failure::registered(StatusCode::BAD_REQUEST, ReasonCode::SchemaInvalid))?;
    verification::verify(
        &input,
        &state.authority,
        &state.audience,
        state.clock.now(),
        state.max_lifetime,
        &state.store,
    )
    .await
    .map_err(|reason| {
        if reason == ReasonCode::InternalFailClosed {
            Failure::internal()
        } else {
            Failure::registered(StatusCode::FORBIDDEN, reason)
        }
    })?;
    tracing::info!(action = ?input.request.action(), resource = input.request.resource(), "permit verified");
    let permit = input.permit.artifact();
    let request_digest =
        digest(ACTION_PROPOSAL_DOMAIN, &input.request).map_err(|_| Failure::internal())?;
    let now = state.clock.now().unix_seconds();
    match state
        .store
        .receive_operation(&ReceiveOperationInput {
            operation_id: permit.effect_operation_id().as_str(),
            permit_id: permit.permit_id().as_str(),
            jti: permit.jti().as_str(),
            nonce: permit.nonce(),
            idempotency_key: input.request.request_id().as_str(),
            request_digest: request_digest.as_str(),
            expires_at: permit.expires_at().unix_seconds(),
            now,
        })
        .await
        .map_err(|_| Failure::internal())?
    {
        ReceiveOperation::Completed(json) => {
            let result = serde_json::from_str(&json).map_err(|_| Failure::internal())?;
            return Ok(Json(result));
        }
        ReceiveOperation::Conflict => {
            return Err(Failure::registered(
                StatusCode::CONFLICT,
                ReasonCode::SchemaInvalid,
            ))
        }
        ReceiveOperation::Replay => {
            return Err(Failure::registered(
                StatusCode::FORBIDDEN,
                ReasonCode::Replay,
            ))
        }
        ReceiveOperation::Ambiguous => return Err(Failure::ambiguous()),
        ReceiveOperation::Ready => {}
    }
    state
        .store
        .mark_started(permit.effect_operation_id().as_str(), now)
        .await
        .map_err(|_| Failure::internal())?;
    let result = match state.executor.execute(&input.request) {
        Ok(result) => result,
        Err(error) => {
            state
                .store
                .fail_operation(
                    permit.effect_operation_id().as_str(),
                    state.clock.now().unix_seconds(),
                )
                .await
                .map_err(|_| Failure::internal())?;
            return Err(match error {
                sandbox::SandboxError::Limit => {
                    Failure::registered(StatusCode::FORBIDDEN, ReasonCode::ActionNotAllowed)
                }
                sandbox::SandboxError::Path => {
                    Failure::registered(StatusCode::FORBIDDEN, ReasonCode::ResourceOutOfScope)
                }
                sandbox::SandboxError::Io => Failure::internal(),
            });
        }
    };
    let result_digest = digest(AUDIT_EVENT_DOMAIN, &result).map_err(|_| Failure::internal())?;
    let result_json = serde_json::to_string(&result).map_err(|_| Failure::internal())?;
    state
        .store
        .complete_operation(
            permit.effect_operation_id().as_str(),
            result_digest.as_str(),
            &result_json,
            state.clock.now().unix_seconds(),
        )
        .await
        .map_err(|_| Failure::internal())?;
    Ok(Json(result))
}
async fn containment(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, Failure> {
    let bytes = body(request, state.body_limit).await?;
    let event: SignedContainmentEvent = serde_json::from_slice(&bytes)
        .map_err(|_| Failure::registered(StatusCode::BAD_REQUEST, ReasonCode::SchemaInvalid))?;
    if event.signer_public_key() != &state.authority || event.verify().is_err() {
        return Err(Failure::registered(
            StatusCode::UNAUTHORIZED,
            ReasonCode::BadSignature,
        ));
    }
    let digest = artifact_digest(event.artifact()).map_err(|_| Failure::internal())?;
    let applied = state
        .store
        .apply_containment(
            event.artifact().instance_id.as_str(),
            event.artifact().containment_epoch,
            digest.as_str(),
        )
        .await
        .map_err(|_| Failure::internal())?;
    if applied == ApplyResult::Regressive {
        tracing::warn!(reason = ?ReasonCode::EpochStale, "containment event rejected");
        return Err(Failure::registered(
            StatusCode::CONFLICT,
            ReasonCode::EpochStale,
        ));
    }
    tracing::info!(
        instance_id = event.artifact().instance_id.as_str(),
        containment_epoch = event.artifact().containment_epoch,
        "containment epoch applied"
    );
    Ok(Json(
        serde_json::json!({"applied":applied==ApplyResult::Applied,"already_applied":applied==ApplyResult::AlreadyApplied,"containment_epoch":event.artifact().containment_epoch}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aaph_core::action::{CanonicalActionRequest, RawActionProposal};
    use aaph_core::crypto::{
        digest, public_key_fingerprint, SigningKeyMaterial, ACTION_PROPOSAL_DOMAIN,
    };
    use aaph_core::ids::{
        AgentId, BudgetReservationId, EffectOperationId, InstanceId, Jti, PermitId, PolicyVersion,
        RequestId, SessionId,
    };
    use aaph_core::permit::{
        ContainmentEvent, ExecutionPermit, ExecutionPermitFields, PermitTimePolicy,
    };
    use aaph_core::signed::{SignedContainmentEvent, SignedExecutionPermit};
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt;
    use std::sync::atomic::AtomicUsize;
    use tower::ServiceExt;

    const NOW: i64 = 1_000;
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> UtcTimestamp {
            UtcTimestamp::from_unix_seconds(NOW)
        }
    }

    struct Fixture {
        app: Router,
        authority: SigningKeyMaterial,
        holder: SigningKeyMaterial,
        temp: tempfile::TempDir,
    }
    async fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("inbox")).unwrap();
        std::fs::create_dir(temp.path().join("output")).unwrap();
        std::fs::write(temp.path().join("inbox/a.txt"), b"data").unwrap();
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        store.set_epoch("instance", 0, 0).await.unwrap();
        let authority = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let app = PepApp::new(
            store.clone(),
            Arc::new(Workspace::open(temp.path(), 8, 16, 16).unwrap()),
            Arc::new(FixedClock),
            PepAppConfig {
                authority: authority.public_key(),
                audience: PepId::new("pep").unwrap(),
                body_limit: 65_536,
                max_lifetime: 60,
            },
        );
        Fixture {
            app: app.router(),
            authority,
            holder,
            temp,
        }
    }
    fn request(action: &str, resource: &str, size: Option<u64>) -> CanonicalActionRequest {
        CanonicalActionRequest::try_from(RawActionProposal {
            request_id: RequestId::new(format!("r-{action}-{resource}")).unwrap(),
            session_id: SessionId::new("session").unwrap(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            size_bytes: size,
            purpose: "analysis".to_owned(),
            destination: None,
        })
        .unwrap()
    }
    fn permit(f: &Fixture, request: &CanonicalActionRequest, nonce: &str) -> SignedExecutionPermit {
        let fields = ExecutionPermitFields {
            permit_id: PermitId::new(format!("p-{nonce}")).unwrap(),
            jti: Jti::new(format!("j-{nonce}")).unwrap(),
            request_digest: digest(ACTION_PROPOSAL_DOMAIN, request).unwrap(),
            agent_id: AgentId::new("agent").unwrap(),
            instance_id: InstanceId::new("instance").unwrap(),
            session_id: SessionId::new("session").unwrap(),
            holder_key_fingerprint: public_key_fingerprint(&f.holder.public_key()).unwrap(),
            audience_pep_id: PepId::new("pep").unwrap(),
            issued_at: UtcTimestamp::from_unix_seconds(NOW),
            expires_at: UtcTimestamp::from_unix_seconds(NOW + 30),
            nonce: nonce.to_owned(),
            effect_operation_id: EffectOperationId::new(format!("o-{nonce}")).unwrap(),
            session_epoch: 0,
            containment_epoch: 0,
            budget_reservation_id: BudgetReservationId::new(format!("b-{nonce}")).unwrap(),
            policy_version: PolicyVersion::new("v1").unwrap(),
            policy_digest: digest(ACTION_PROPOSAL_DOMAIN, request).unwrap(),
        };
        SignedExecutionPermit::sign(
            ExecutionPermit::new(
                fields,
                PermitTimePolicy::default(),
                UtcTimestamp::from_unix_seconds(NOW),
            )
            .unwrap(),
            &f.authority,
        )
        .unwrap()
    }
    fn payload(f: &Fixture, request: CanonicalActionRequest, nonce: &str) -> Vec<u8> {
        let signed = permit(f, &request, nonce);
        let request = serde_json::to_value(request).unwrap();
        serde_json::to_vec(&serde_json::json!({"permit":signed,"request":request,"holder_public_key":f.holder.public_key()})).unwrap()
    }

    fn payload_with_ids(
        authority: &SigningKeyMaterial,
        holder: &SigningKeyMaterial,
        request: &CanonicalActionRequest,
        permit_id: &str,
        jti: &str,
        nonce: &str,
        operation_id: &str,
    ) -> Vec<u8> {
        let fields = ExecutionPermitFields {
            permit_id: PermitId::new(permit_id).unwrap(),
            jti: Jti::new(jti).unwrap(),
            request_digest: digest(ACTION_PROPOSAL_DOMAIN, request).unwrap(),
            agent_id: AgentId::new("agent").unwrap(),
            instance_id: InstanceId::new("instance").unwrap(),
            session_id: SessionId::new("session").unwrap(),
            holder_key_fingerprint: public_key_fingerprint(&holder.public_key()).unwrap(),
            audience_pep_id: PepId::new("pep").unwrap(),
            issued_at: UtcTimestamp::from_unix_seconds(NOW),
            expires_at: UtcTimestamp::from_unix_seconds(NOW + 30),
            nonce: nonce.to_owned(),
            effect_operation_id: EffectOperationId::new(operation_id).unwrap(),
            session_epoch: 0,
            containment_epoch: 0,
            budget_reservation_id: BudgetReservationId::new(format!("b-{permit_id}")).unwrap(),
            policy_version: PolicyVersion::new("v1").unwrap(),
            policy_digest: digest(ACTION_PROPOSAL_DOMAIN, request).unwrap(),
        };
        let signed = SignedExecutionPermit::sign(
            ExecutionPermit::new(
                fields,
                PermitTimePolicy::default(),
                UtcTimestamp::from_unix_seconds(NOW),
            )
            .unwrap(),
            authority,
        )
        .unwrap();
        serde_json::to_vec(&serde_json::json!({"permit":signed,"request":request,"holder_public_key":holder.public_key()})).unwrap()
    }
    async fn call(app: Router, uri: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    struct CountingExecutor(Arc<AtomicUsize>);
    impl OperationExecutor for CountingExecutor {
        fn execute(
            &self,
            request: &CanonicalActionRequest,
        ) -> Result<EffectResult, sandbox::SandboxError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(EffectResult {
                action: request.action(),
                resource: request.resource().to_owned(),
                entries: None,
                content: Some("stored".to_owned()),
                sha256: None,
                bytes: 6,
            })
        }
    }

    #[tokio::test]
    async fn completed_operation_returns_stored_result_without_new_effect() {
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        store.set_epoch("instance", 0, 0).await.unwrap();
        let authority = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let calls = Arc::new(AtomicUsize::new(0));
        let app = PepApp::with_executor(
            store,
            Arc::new(CountingExecutor(calls.clone())),
            Arc::new(FixedClock),
            PepAppConfig {
                authority: authority.public_key(),
                audience: PepId::new("pep").unwrap(),
                body_limit: 65_536,
                max_lifetime: 60,
            },
        )
        .router();
        let fixture = Fixture {
            app: app.clone(),
            authority,
            holder,
            temp: tempfile::tempdir().unwrap(),
        };
        let body = payload(
            &fixture,
            request("READ_FILE", "inbox/a.txt", Some(4)),
            "stored",
        );
        let first = call(app.clone(), "/v1/effects/execute", body.clone()).await;
        let second = call(app, "/v1/effects/execute", body).await;
        assert_eq!(first, second);
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn jti_replay_rejected_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("inbox")).unwrap();
        std::fs::create_dir(temp.path().join("output")).unwrap();
        std::fs::write(temp.path().join("inbox/a.txt"), b"data").unwrap();
        let url = format!("sqlite://{}", temp.path().join("pep.db").display());
        let authority = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let first_store = PepStore::connect(&url).await.unwrap();
        first_store.set_epoch("instance", 0, 0).await.unwrap();
        let first_app = PepApp::new(
            first_store,
            Arc::new(Workspace::open(temp.path(), 8, 16, 16).unwrap()),
            Arc::new(FixedClock),
            PepAppConfig {
                authority: authority.public_key(),
                audience: PepId::new("pep").unwrap(),
                body_limit: 65_536,
                max_lifetime: 60,
            },
        )
        .router();
        let first_request = request("READ_FILE", "inbox/a.txt", Some(4));
        let first = payload_with_ids(
            &authority,
            &holder,
            &first_request,
            "permit-first",
            "shared-jti",
            "nonce-first",
            "operation-first",
        );
        assert_eq!(
            call(first_app, "/v1/effects/execute", first).await.0,
            StatusCode::OK
        );

        let restarted_store = PepStore::connect(&url).await.unwrap();
        let restarted_app = PepApp::new(
            restarted_store,
            Arc::new(Workspace::open(temp.path(), 8, 16, 16).unwrap()),
            Arc::new(FixedClock),
            PepAppConfig {
                authority: authority.public_key(),
                audience: PepId::new("pep").unwrap(),
                body_limit: 65_536,
                max_lifetime: 60,
            },
        )
        .router();
        let second_request = CanonicalActionRequest::try_from(RawActionProposal {
            request_id: RequestId::new("second-request").unwrap(),
            session_id: SessionId::new("session").unwrap(),
            action: "READ_FILE".to_owned(),
            resource: "inbox/a.txt".to_owned(),
            size_bytes: Some(4),
            purpose: "analysis".to_owned(),
            destination: None,
        })
        .unwrap();
        let replay = payload_with_ids(
            &authority,
            &holder,
            &second_request,
            "permit-second",
            "shared-jti",
            "nonce-second",
            "operation-second",
        );
        assert_eq!(
            call(restarted_app, "/v1/effects/execute", replay).await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn ambiguous_operation_is_never_replayed() {
        let store = PepStore::connect("sqlite::memory:").await.unwrap();
        store.set_epoch("instance", 0, 0).await.unwrap();
        let authority = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let request = request("READ_FILE", "inbox/a.txt", Some(4));
        let request_digest = digest(ACTION_PROPOSAL_DOMAIN, &request).unwrap();
        store
            .receive_operation(&ReceiveOperationInput {
                operation_id: "ambiguous-operation",
                permit_id: "ambiguous-permit",
                jti: "ambiguous-jti",
                nonce: "ambiguous-nonce",
                idempotency_key: request.request_id().as_str(),
                request_digest: request_digest.as_str(),
                expires_at: NOW + 30,
                now: NOW,
            })
            .await
            .unwrap();
        store
            .mark_started("ambiguous-operation", NOW + 1)
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let app = PepApp::with_executor(
            store,
            Arc::new(CountingExecutor(calls.clone())),
            Arc::new(FixedClock),
            PepAppConfig {
                authority: authority.public_key(),
                audience: PepId::new("pep").unwrap(),
                body_limit: 65_536,
                max_lifetime: 60,
            },
        )
        .router();
        let body = payload_with_ids(
            &authority,
            &holder,
            &request,
            "ambiguous-permit",
            "ambiguous-jti",
            "ambiguous-nonce",
            "ambiguous-operation",
        );
        let (status, response) = call(app, "/v1/effects/execute", body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["reason"], "LOCAL_EFFECT_AMBIGUOUS");
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn pep_router_builds_in_memory_without_socket() {
        let fixture = fixture().await;
        let response = fixture
            .app
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_and_all_four_registered_actions() {
        let f = fixture().await;
        let health = f
            .app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        for (index, (action, path, size)) in [
            ("LIST_DIRECTORY", "inbox/", None),
            ("READ_FILE", "inbox/a.txt", Some(4)),
            ("COMPUTE_SHA256", "inbox/a.txt", Some(4)),
            ("WRITE_REPORT", "output/report.txt", Some(4)),
        ]
        .into_iter()
        .enumerate()
        {
            let req = request(action, path, size);
            assert_eq!(
                call(
                    f.app.clone(),
                    "/v1/effects/execute",
                    payload(&f, req, &format!("n{index}"))
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        assert_eq!(
            std::fs::read(f.temp.path().join("output/report.txt")).unwrap(),
            b"####"
        );
    }

    #[tokio::test]
    async fn rejects_missing_bad_expired_audience_digest_and_epochs() {
        let f = fixture().await;
        assert_eq!(
            call(f.app.clone(), "/v1/effects/execute", b"{}".to_vec())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let req = request("READ_FILE", "inbox/a.txt", Some(4));
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload(&f, req.clone(), "bad-sign")).unwrap();
        value["permit"]["signature"]=serde_json::Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned());
        assert_eq!(
            call(
                f.app.clone(),
                "/v1/effects/execute",
                serde_json::to_vec(&value).unwrap()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        for (field, replacement, nonce) in [
            ("expires_at", serde_json::json!(NOW), "expired"),
            ("audience_pep_id", serde_json::json!("other"), "audience"),
            (
                "request_digest",
                serde_json::json!(digest(
                    ACTION_PROPOSAL_DOMAIN,
                    &request("READ_FILE", "inbox/a.txt", Some(3))
                )
                .unwrap()),
                "digest",
            ),
            ("session_epoch", serde_json::json!(1), "epoch"),
        ] {
            let valid = permit(&f, &req, nonce);
            let mut artifact = serde_json::to_value(valid.artifact()).unwrap();
            artifact[field] = replacement;
            let unchecked: ExecutionPermit = serde_json::from_value(artifact).unwrap();
            let signed = SignedExecutionPermit::sign(unchecked, &f.authority).unwrap();
            let body=serde_json::to_vec(&serde_json::json!({"permit":signed,"request":req,"holder_public_key":f.holder.public_key()})).unwrap();
            assert_eq!(
                call(f.app.clone(), "/v1/effects/execute", body).await.0,
                StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn same_completed_request_is_idempotent_sequential_and_concurrent() {
        let f = fixture().await;
        let req = request("READ_FILE", "inbox/a.txt", Some(4));
        let body = payload(&f, req, "replay");
        assert_eq!(
            call(f.app.clone(), "/v1/effects/execute", body.clone())
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(f.app.clone(), "/v1/effects/execute", body).await.0,
            StatusCode::OK
        );
        let body = payload(&f, request("READ_FILE", "inbox/a.txt", Some(4)), "race");
        let (a, b) = tokio::join!(
            call(f.app.clone(), "/v1/effects/execute", body.clone()),
            call(f.app.clone(), "/v1/effects/execute", body)
        );
        assert_eq!(
            [a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count(),
            2
        );
    }

    #[tokio::test]
    async fn rejects_paths_limits_destination_and_preserves_atomic_writes() {
        let f = fixture().await;
        for (index, path) in [
            "inbox/../a.txt",
            "C:/absolute",
            "/absolute",
            "inbox/a\0.txt",
            "inbox/%2e%2e/a",
        ]
        .into_iter()
        .enumerate()
        {
            let raw = serde_json::json!({"request_id":format!("bad{index}"),"session_id":"session","action":"READ_FILE","resource":path,"size_bytes":4,"purpose":"analysis","destination":null});
            let req: CanonicalActionRequest = serde_json::from_value(raw).unwrap();
            assert_eq!(
                call(
                    f.app.clone(),
                    "/v1/effects/execute",
                    payload(&f, req, &format!("path{index}"))
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
        }
        for (action, path, size, nonce) in [
            ("READ_FILE", "inbox/a.txt", 17, "read-limit"),
            ("WRITE_REPORT", "output/x", 17, "write-limit"),
            ("WRITE_REPORT", "inbox/x", 4, "write-scope"),
        ] {
            let req = request(action, path, Some(size));
            assert_eq!(
                call(
                    f.app.clone(),
                    "/v1/effects/execute",
                    payload(&f, req, nonce)
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
        }
        let mut external =
            serde_json::to_value(request("READ_FILE", "inbox/a.txt", Some(4))).unwrap();
        external["request_id"] = serde_json::json!("external-destination");
        external["destination"] = serde_json::json!("https://example.invalid");
        let external: CanonicalActionRequest = serde_json::from_value(external).unwrap();
        assert_eq!(
            call(
                f.app.clone(),
                "/v1/effects/execute",
                payload(&f, external, "destination")
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let mut unknown: serde_json::Value = serde_json::from_slice(&payload(
            &f,
            request("READ_FILE", "inbox/a.txt", Some(4)),
            "unknown",
        ))
        .unwrap();
        unknown["request"]["action"] = serde_json::json!("OPEN_SHELL");
        assert_eq!(
            call(
                f.app.clone(),
                "/v1/effects/execute",
                serde_json::to_vec(&unknown).unwrap()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert!(!f.temp.path().join("output/x").exists());
        assert!(!std::fs::read_dir(f.temp.path().join("output"))
            .unwrap()
            .any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("aaph-tmp")));
    }

    #[tokio::test]
    async fn containment_events_are_signed_monotonic_and_unique() {
        let f = fixture().await;
        let event = ContainmentEvent {
            instance_id: InstanceId::new("instance").unwrap(),
            containment_epoch: 1,
            reason: ReasonCode::AgentContained,
            occurred_at: UtcTimestamp::from_unix_seconds(NOW),
        };
        let signed = SignedContainmentEvent::sign(event, &f.authority).unwrap();
        let body = serde_json::to_vec(&signed).unwrap();
        assert_eq!(
            call(
                f.app.clone(),
                "/internal/v1/containment-events",
                body.clone()
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(f.app.clone(), "/internal/v1/containment-events", body)
                .await
                .0,
            StatusCode::OK
        );
        let wrong = SigningKeyMaterial::generate();
        let bad = SignedContainmentEvent::sign(
            ContainmentEvent {
                instance_id: InstanceId::new("instance").unwrap(),
                containment_epoch: 2,
                reason: ReasonCode::AgentContained,
                occurred_at: UtcTimestamp::from_unix_seconds(NOW),
            },
            &wrong,
        )
        .unwrap();
        assert_eq!(
            call(
                f.app.clone(),
                "/internal/v1/containment-events",
                serde_json::to_vec(&bad).unwrap()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let regressive = SignedContainmentEvent::sign(
            ContainmentEvent {
                instance_id: InstanceId::new("instance").unwrap(),
                containment_epoch: 0,
                reason: ReasonCode::AgentContained,
                occurred_at: UtcTimestamp::from_unix_seconds(NOW),
            },
            &f.authority,
        )
        .unwrap();
        assert_eq!(
            call(
                f.app,
                "/internal/v1/containment-events",
                serde_json::to_vec(&regressive).unwrap()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn old_permit_rejected_after_containment() {
        let f = fixture().await;
        let old = payload(
            &f,
            request("READ_FILE", "inbox/a.txt", Some(4)),
            "old-before-containment",
        );
        let event = SignedContainmentEvent::sign(
            ContainmentEvent {
                instance_id: InstanceId::new("instance").unwrap(),
                containment_epoch: 1,
                reason: ReasonCode::AgentContained,
                occurred_at: UtcTimestamp::from_unix_seconds(NOW),
            },
            &f.authority,
        )
        .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            call(
                f.app.clone(),
                "/internal/v1/containment-events",
                serde_json::to_vec(&event).unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(f.app, "/v1/effects/execute", old).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_escaping_inbox() {
        use std::os::unix::fs::symlink;
        let f = fixture().await;
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), f.temp.path().join("inbox/link")).unwrap();
        let req = request("READ_FILE", "inbox/link", Some(4));
        assert_eq!(
            call(
                f.app.clone(),
                "/v1/effects/execute",
                payload(&f, req, "symlink")
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn rejects_symlink_escaping_inbox_when_creation_is_permitted() {
        use std::os::windows::fs::symlink_file;
        let f = fixture().await;
        let outside = tempfile::NamedTempFile::new().unwrap();
        if symlink_file(outside.path(), f.temp.path().join("inbox/link")).is_err() {
            return;
        }
        let req = request("READ_FILE", "inbox/link", Some(4));
        assert_eq!(
            call(
                f.app.clone(),
                "/v1/effects/execute",
                payload(&f, req, "symlink"),
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
}
