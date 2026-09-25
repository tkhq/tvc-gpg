//! Router for the TVC GPG REST server.
use crate::allowlist::Allowlist;
use crate::response::AppError;
use crate::session_key::{MAX_BODY_BYTES, session_key};
use crate::team_key::TeamKey;
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    response::IntoResponse,
    routing::{get, post},
};
use qos_p256::P256Pair;
use serde_json::json;
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// The enclave's quorum key, used to derive the team OpenPGP key and to
    /// sign receipts.
    pub quorum_key: Arc<P256Pair>,
    /// The team OpenPGP key derived from the quorum key.
    pub team_key: Arc<TeamKey>,
    /// Engineer GPG keys allowed to request session keys.
    pub allowlist: Arc<Allowlist>,
    /// Identifier for this app, included in signed receipts.
    pub app_id: String,
}

impl AppState {
    /// Create a new application state value.
    #[must_use]
    pub fn new(
        quorum_key: P256Pair,
        team_key: TeamKey,
        allowlist: Allowlist,
        app_id: String,
    ) -> Self {
        Self {
            quorum_key: Arc::new(quorum_key),
            team_key: Arc::new(team_key),
            allowlist: Arc::new(allowlist),
            app_id,
        }
    }
}

/// Build the application router with the given state.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/public-key", get(public_key))
        .route("/revocation-certificate", get(revocation_certificate))
        .route(
            "/session-key",
            post(session_key).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "healthy"}))
}

async fn public_key(State(state): State<AppState>) -> Result<String, AppError> {
    state
        .team_key
        .public_key_armored()
        .map_err(|e| AppError::internal(format!("failed to export the public key: {e}")))
}

async fn revocation_certificate(State(state): State<AppState>) -> Result<String, AppError> {
    state
        .team_key
        .revocation_certificate_armored()
        .map_err(|e| {
            AppError::internal(format!("failed to export the revocation certificate: {e}"))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid utf8")
    }

    fn router_with_generated_state() -> Router {
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");
        let team_key = TeamKey::derive(&quorum_key).expect("failed to derive the team key");
        let allowlist = Allowlist::embedded().expect("failed to load the embedded allowlist");
        router_with_state(AppState::new(
            quorum_key,
            team_key,
            allowlist,
            "test-app".to_string(),
        ))
    }

    async fn get_body(uri: &str) -> String {
        let response = router_with_generated_state()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        body_string(response.into_body()).await
    }

    #[tokio::test]
    async fn test_public_key() {
        let body = get_body("/public-key").await;
        assert!(body.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }

    #[tokio::test]
    async fn test_revocation_certificate() {
        let body = get_body("/revocation-certificate").await;
        assert!(body.starts_with("-----BEGIN PGP SIGNATURE-----"));
    }

    #[tokio::test]
    async fn test_health() {
        let app = router_with_generated_state();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        assert_eq!(json["status"], "healthy");
    }
}
