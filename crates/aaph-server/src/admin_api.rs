use aaph_authority::AuthorityApp;
use axum::Router;

#[cfg(test)]
pub const ADMIN_ROUTES: &[&str] = &["/v1/admin/instances/:instance_id/recovery"];

pub fn router(authority: &AuthorityApp) -> Router {
    authority.admin_router()
}

/// Serves only administrative routes on the dedicated TLS listener.
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
    use super::ADMIN_ROUTES;
    use crate::public_api::PUBLIC_ROUTES;

    #[test]
    fn public_and_admin_listeners_have_disjoint_routes() {
        assert!(ADMIN_ROUTES
            .iter()
            .all(|route| !PUBLIC_ROUTES.contains(route)));
    }
}
