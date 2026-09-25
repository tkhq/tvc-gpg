#![allow(missing_docs, clippy::unwrap_used)]

use e2e::TestArgs;

#[tokio::test]
async fn test_health() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "healthy");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_public_key() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/public-key", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_revocation_certificate() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/revocation-certificate", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.starts_with("-----BEGIN PGP SIGNATURE-----"));
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_session_key_rejects_empty_body() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/session-key", test_args.base_url))
            .body("")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_metrics() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        // Trigger a request so the histogram has at least one observation.
        client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();

        let resp = client
            .get(format!("{}/metrics", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("tvc_http_request_duration_ms"));
    }
    e2e::Builder::new().execute(test).await;
}
