use super::*;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn respond_with_body(body: Vec<u8>) -> reqwest::Response {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/body"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    reqwest::get(format!("{}/body", mock_server.uri()))
        .await
        .expect("request to mock server failed")
}

#[tokio::test]
async fn test_read_body_capped_accepts_body_at_limit() {
    let response = respond_with_body(vec![b'a'; MAX_RESPONSE_BYTES]).await;

    let body = read_body_capped(response).await.unwrap();
    assert_eq!(body.len(), MAX_RESPONSE_BYTES);
}

#[tokio::test]
async fn test_read_body_capped_rejects_oversized_body() {
    let response = respond_with_body(vec![b'a'; MAX_RESPONSE_BYTES + 1]).await;

    let error = read_body_capped(response).await.unwrap_err();
    match error {
        SignerError::SerializationError(detail) => {
            assert_eq!(detail, "response exceeded maximum size");
        }
        other => panic!("expected SerializationError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_parse_json_response_rejects_oversized_body() {
    // Valid JSON past the cap: rejected before any parsing happens.
    let mut body = Vec::with_capacity(MAX_RESPONSE_BYTES + 16);
    body.push(b'"');
    body.resize(MAX_RESPONSE_BYTES + 15, b'a');
    body.push(b'"');
    let response = respond_with_body(body).await;

    let error = parse_json_response::<serde_json::Value>(response, "test API")
        .await
        .unwrap_err();
    assert!(matches!(error, SignerError::SerializationError(_)));
}

#[tokio::test]
async fn test_parse_json_response_parses_body_within_limit() {
    let response = respond_with_body(b"{\"ok\":true}".to_vec()).await;

    let value: serde_json::Value = parse_json_response(response, "test API").await.unwrap();
    assert_eq!(value["ok"], serde_json::Value::Bool(true));
}
