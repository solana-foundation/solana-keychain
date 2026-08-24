use super::VaultResponse;

#[test]
fn deserializes_chain_specific_vault_response() {
    let response: VaultResponse = serde_json::from_value(serde_json::json!({
        "address": "7EcVq7V4FqgM9JgjQjDyX3tLwGfX5CrJf7RsB4dQ2mCz",
        "id": "vault-id",
        "type": "solana"
    }))
    .unwrap();

    assert_eq!(
        response.address.as_deref(),
        Some("7EcVq7V4FqgM9JgjQjDyX3tLwGfX5CrJf7RsB4dQ2mCz")
    );
    assert_eq!(response.id, "vault-id");
    assert_eq!(response.public_key_compressed, None);
    assert_eq!(response.vault_type.as_deref(), Some("solana"));
}

#[test]
fn deserializes_black_box_vault_response() {
    let response: VaultResponse = serde_json::from_value(serde_json::json!({
        "id": "vault-id",
        "public_key_compressed": "cHVibGljLWtleQ==",
        "type": "black_box"
    }))
    .unwrap();

    assert_eq!(response.address, None);
    assert_eq!(response.id, "vault-id");
    assert_eq!(
        response.public_key_compressed.as_deref(),
        Some("cHVibGljLWtleQ==")
    );
    assert_eq!(response.vault_type.as_deref(), Some("black_box"));
}
