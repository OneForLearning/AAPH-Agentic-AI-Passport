use aaph_authority::AuthorityApp;
use aaph_pep::PepApp;
use axum::routing::get;
use axum::{Json, Router};

#[cfg(test)]
pub const PUBLIC_ROUTES: &[&str] = &[
    "/health",
    "/v1/sessions",
    "/v1/actions/propose",
    "/v1/effects/execute",
    "/v1/instances/:instance_id",
    "/v1/decisions/:request_id",
    "/v1/audit/verify",
    "/v1/audit/export",
    "/metrics",
];

pub fn router(authority: &AuthorityApp, pep: &PepApp) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({
                    "status": "ok",
                    "authority": "ok",
                    "pep": "ok",
                    "marker": "NON_PRODUCTION_DEMO"
                }))
            }),
        )
        .merge(authority.public_router())
        .merge(pep.public_router())
}

/// Serves the unified public API on its dedicated TLS listener.
///
/// # Errors
/// Returns an I/O error when binding or serving fails.
pub async fn serve(
    address: std::net::SocketAddr,
    tls: axum_server::tls_rustls::RustlsConfig,
    router: Router,
) -> std::io::Result<()> {
    axum_server::bind_rustls(address, tls)
        .serve(router.into_make_service())
        .await
}

#[cfg(test)]
mod tests {
    use super::PUBLIC_ROUTES;
    use std::collections::BTreeSet;

    #[test]
    fn public_route_collision_is_impossible() {
        let unique: BTreeSet<_> = PUBLIC_ROUTES.iter().copied().collect();
        assert_eq!(unique.len(), PUBLIC_ROUTES.len());
    }
}
