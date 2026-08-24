
use super::*;
use p256::ecdsa::signature::Verifier as _;

const TEST_P256_PKCS8_PEM: &str = concat!(
    "-----BEGIN PRIVATE KEY-----\n",
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n",
    "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n",
    "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n",
    "-----END PRIVATE KEY-----"
);
const TEST_P256_PKCS8_BASE64: &str = concat!(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG",
    "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY",
    "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf"
);

fn authorization_request(body: Value) -> PrivyAuthorizationRequestInput {
    PrivyAuthorizationRequestInput {
        version: 1,
        method: "POST".to_string(),
        url: "https://api.privy.test/wallets/test-wallet-id/rpc".to_string(),
        body,
        headers: BTreeMap::from([
            ("privy-app-id".to_string(), "test-app-id".to_string()),
            ("privy-request-expiry".to_string(), "1900000".to_string()),
        ]),
    }
}

#[test]
fn formats_empty_authorization_request_bodies_like_privy_sdk() {
    let request = authorization_request(serde_json::json!({}));

    let payload = format_privy_authorization_signature_payload(&request).unwrap();

    assert_eq!(
            String::from_utf8(payload).unwrap(),
            "{\"body\":\"\",\"headers\":{\"privy-app-id\":\"test-app-id\",\"privy-request-expiry\":\"1900000\"},\"method\":\"POST\",\"url\":\"https://api.privy.test/wallets/test-wallet-id/rpc\",\"version\":1}"
        );
}

#[test]
fn generates_base64_der_authorization_signatures_from_privy_private_keys() {
    let request = authorization_request(serde_json::json!({
        "chain_type": "solana",
        "method": "signMessage",
        "params": {
            "encoding": "base64",
            "message": "AQIDBA=="
        }
    }));
    let context = PrivyAuthorizationContext {
        authorization_private_keys: vec![format!("wallet-auth:{TEST_P256_PKCS8_BASE64}")],
        ..Default::default()
    };

    let signatures = generate_privy_authorization_signatures(&request, &context).unwrap();
    let payload = format_privy_authorization_signature_payload(&request).unwrap();
    let signature_bytes = STANDARD.decode(&signatures[0]).unwrap();
    let signature = p256::ecdsa::Signature::from_der(&signature_bytes).unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(TEST_P256_PKCS8_PEM).unwrap();

    signing_key
        .verifying_key()
        .verify(&payload, &signature)
        .unwrap();
}

#[test]
fn preserves_privy_signature_order() {
    let request = authorization_request(serde_json::json!({"method": "signMessage"}));
    let context = PrivyAuthorizationContext {
        signatures: vec!["provided".to_string()],
        sign_fns: vec![Arc::new(|_| Ok("sign-fn".to_string()))],
        ..Default::default()
    };

    let signatures = generate_privy_authorization_signatures(&request, &context).unwrap();

    assert_eq!(signatures, vec!["provided", "sign-fn"]);
}

#[test]
fn invalid_privy_private_key_errors_do_not_include_parser_details() {
    let invalid_der = STANDARD.encode("not-secret-but-sensitive");
    let cases = [
        (
            "wallet-auth:not-secret-but-sensitive",
            "Invalid Privy authorization private key encoding",
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nnot-secret-but-sensitive\n-----END PRIVATE KEY-----",
            "Invalid Privy authorization private key",
        ),
        (
            invalid_der.as_str(),
            "Invalid Privy authorization private key",
        ),
    ];

    for (invalid_key, expected_message) in cases {
        let err = parse_p256_private_key(invalid_key).unwrap_err();

        match err {
            SignerError::InvalidPrivateKey(message) => {
                assert_eq!(message, expected_message);
                assert!(!message.contains(invalid_key));
            }
            other => panic!("expected InvalidPrivateKey, got {other:?}"),
        }
    }
}
