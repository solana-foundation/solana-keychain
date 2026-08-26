use super::VaultResponse;

#[test]
fn deserializes_vault_response_ignoring_extra_fields() {
    let response: VaultResponse = serde_json::from_value(serde_json::json!({
        "address": "7EcVq7V4FqgM9JgjQjDyX3tLwGfX5CrJf7RsB4dQ2mCz",
        "id": "vault-id",
        "public_key_compressed": "cHVibGljLWtleQ==",
        "type": "solana"
    }))
    .unwrap();

    assert_eq!(response.id, "vault-id");
}
