use super::SignerError;

#[test]
fn test_display_is_redacted_for_all_variants() {
    let secret = "sensitive-secret-material";
    let cases = [
        SignerError::InvalidPrivateKey(secret.to_string()),
        SignerError::InvalidPublicKey(secret.to_string()),
        SignerError::SigningFailed(secret.to_string()),
        SignerError::RemoteApiError(secret.to_string()),
        SignerError::HttpError(secret.to_string()),
        SignerError::SerializationError(secret.to_string()),
        SignerError::ConfigError(secret.to_string()),
        SignerError::NotAvailable(secret.to_string()),
        SignerError::IoError(secret.to_string()),
        SignerError::Other(secret.to_string()),
        SignerError::BroadcastUnconfirmed {
            provider_tx_id: Some("tx-id".to_string()),
            provider_status: None,
            detail: secret.to_string(),
        },
    ];

    for err in cases {
        let display = format!("{err}");
        assert!(
            !display.contains(secret),
            "display output leaked sensitive content: {display}"
        );
    }
}

#[test]
fn test_display_messages_are_stable_and_generic() {
    assert_eq!(
        format!("{}", SignerError::InvalidPrivateKey("x".to_string())),
        "Invalid private key format"
    );
    assert_eq!(
        format!("{}", SignerError::InvalidPublicKey("x".to_string())),
        "Invalid public key"
    );
    assert_eq!(
        format!("{}", SignerError::SigningFailed("x".to_string())),
        "Signing failed"
    );
    assert_eq!(
        format!("{}", SignerError::RemoteApiError("x".to_string())),
        "Remote API error"
    );
    assert_eq!(
        format!("{}", SignerError::HttpError("x".to_string())),
        "HTTP request failed"
    );
    assert_eq!(
        format!("{}", SignerError::SerializationError("x".to_string())),
        "Serialization error"
    );
    assert_eq!(
        format!("{}", SignerError::ConfigError("x".to_string())),
        "Configuration error"
    );
    assert_eq!(
        format!("{}", SignerError::NotAvailable("x".to_string())),
        "Signer not available"
    );
    assert_eq!(
        format!("{}", SignerError::IoError("x".to_string())),
        "IO error"
    );
    assert_eq!(
        format!("{}", SignerError::Other("x".to_string())),
        "Signer error"
    );
}

#[test]
fn test_broadcast_unconfirmed_surfaces_tx_id_but_not_detail() {
    let err = SignerError::BroadcastUnconfirmed {
        provider_tx_id: Some("provider-tx-123".to_string()),
        provider_status: None,
        detail: "sensitive-detail".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("provider-tx-123"));
    assert!(!display.contains("sensitive-detail"));
    let debug = format!("{err:?}");
    assert!(debug.contains("provider-tx-123"));
    assert!(!debug.contains("sensitive-detail"));
}
