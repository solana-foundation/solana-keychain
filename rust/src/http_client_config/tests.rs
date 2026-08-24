use super::*;
#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
))]
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[test]
fn test_defaults_are_applied_when_unset() {
    let config = HttpClientConfig::default();
    assert_eq!(
        config.resolved_request_timeout(),
        HttpClientConfig::DEFAULT_REQUEST_TIMEOUT
    );
    assert_eq!(
        config.resolved_connect_timeout(),
        HttpClientConfig::DEFAULT_CONNECT_TIMEOUT
    );
}

#[test]
fn test_custom_values_override_defaults() {
    let config = HttpClientConfig {
        request_timeout: Some(Duration::from_secs(42)),
        connect_timeout: Some(Duration::from_secs(7)),
    };
    assert_eq!(config.resolved_request_timeout(), Duration::from_secs(42));
    assert_eq!(config.resolved_connect_timeout(), Duration::from_secs(7));
}

// The policy is exercised against plain-HTTP mock servers, so the client
// under test carries only the redirect policy; https_only is covered by
// the production builder and would reject the mock URL before any
// redirect could happen.
#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
))]
#[tokio::test]
async fn test_no_redirect_policy_fails_instead_of_following() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collect"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;

    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sign"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/collect", target.uri()).as_str()),
        )
        .expect(1)
        .mount(&origin)
        .await;

    let client = reqwest::Client::builder()
        .redirect(no_redirect_policy())
        .build()
        .unwrap();

    let result = client
        .post(format!("{}/sign", origin.uri()))
        .header("X-Vault-Token", "secret-token")
        .send()
        .await;

    let error = result.expect_err("a redirect must fail the request, not be followed");
    assert!(
        error.is_redirect(),
        "expected a redirect error, got: {error}"
    );
}
