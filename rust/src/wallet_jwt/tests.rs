use super::*;

#[test]
fn test_jwt_uri_format() {
    let uri = jwt_uri(
        "api.example.com",
        "POST",
        "/v2/accounts/backend/acc_abc/sign",
    );
    assert_eq!(uri, "POST api.example.com/v2/accounts/backend/acc_abc/sign");
}

#[test]
fn test_compute_req_hash_sorted_is_key_order_invariant() {
    let body_a = serde_json::json!({ "a": 1, "b": 2 });
    let body_b = serde_json::json!({ "b": 2, "a": 1 });
    let h1 = compute_req_hash(Some(&body_a)).unwrap();
    let h2 = compute_req_hash(Some(&body_b)).unwrap();
    assert_eq!(h1, h2);
    assert!(h1.is_some());
}

#[test]
fn test_compute_req_hash_skips_missing_null_and_empty_bodies() {
    assert_eq!(compute_req_hash(None).unwrap(), None);
    assert_eq!(compute_req_hash(Some(&Value::Null)).unwrap(), None);
    assert_eq!(
        compute_req_hash(Some(&serde_json::json!({}))).unwrap(),
        None
    );
}
