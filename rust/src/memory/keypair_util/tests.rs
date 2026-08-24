use super::*;
use crate::sdk_adapter::keypair_pubkey;

const TEST_KEYPAIR_BYTES: &str = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]";
const TEST_KEYPAIR_BASE58: &str =
    "pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1";
const TEST_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

#[test]
fn test_from_u8_array_string() {
    let result = KeypairUtil::from_u8_array_string(TEST_KEYPAIR_BYTES);
    assert!(result.is_ok());

    let keypair = result.unwrap();
    assert_eq!(keypair_pubkey(&keypair).to_string(), TEST_PUBKEY);
}

#[test]
fn test_from_u8_array_invalid_length() {
    let too_short = "[1,2,3]";
    let result = KeypairUtil::from_u8_array_string(too_short);
    assert!(result.is_err());
}

#[test]
fn test_from_u8_array_invalid_format() {
    let invalid = "[not,a,number]";
    let result = KeypairUtil::from_u8_array_string(invalid);
    assert!(result.is_err());
}

#[test]
fn test_from_u8_array_empty() {
    let empty = "[]";
    let result = KeypairUtil::from_u8_array_string(empty);
    assert!(result.is_err());
}

#[test]
fn test_from_json_keypair() {
    let json = TEST_KEYPAIR_BYTES;
    let result = KeypairUtil::from_json_keypair(json);
    assert!(result.is_ok());
}

#[test]
fn test_from_json_keypair_invalid() {
    let invalid_json = "{\"not\": \"an array\"}";
    let result = KeypairUtil::from_json_keypair(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_from_private_key_string_base58() {
    let result = KeypairUtil::from_private_key_string(TEST_KEYPAIR_BASE58);
    assert!(result.is_ok());
    assert_eq!(keypair_pubkey(&result.unwrap()).to_string(), TEST_PUBKEY);
}

#[test]
fn test_from_private_key_string_u8_array() {
    let result = KeypairUtil::from_private_key_string(TEST_KEYPAIR_BYTES);
    assert!(result.is_ok());
    assert_eq!(keypair_pubkey(&result.unwrap()).to_string(), TEST_PUBKEY);
}

#[test]
fn test_from_private_key_string_invalid() {
    let result = KeypairUtil::from_private_key_string("clearly-not-a-valid-key");
    assert!(result.is_err());
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_from_private_key_string_does_not_read_file_path() {
    let tmp_dir = std::env::temp_dir();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let file_path = tmp_dir.join(format!("solana-keychain-private-key-{unique}.json"));

    std::fs::write(&file_path, TEST_KEYPAIR_BYTES).expect("failed to write temp keypair file");
    let path_str = file_path.to_string_lossy().to_string();

    let result = KeypairUtil::from_private_key_string(&path_str);
    assert!(result.is_err());

    let _ = std::fs::remove_file(&file_path);
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_from_private_key_file_json_keypair() {
    let tmp_dir = std::env::temp_dir();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let file_path = tmp_dir.join(format!("solana-keychain-private-key-{unique}.json"));

    std::fs::write(&file_path, TEST_KEYPAIR_BYTES).expect("failed to write temp keypair file");
    let path_str = file_path.to_string_lossy().to_string();

    let result = KeypairUtil::from_private_key_file(&path_str);
    assert!(result.is_ok());
    assert_eq!(keypair_pubkey(&result.unwrap()).to_string(), TEST_PUBKEY);

    let _ = std::fs::remove_file(&file_path);
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_from_private_key_file_missing_file() {
    let result = KeypairUtil::from_private_key_file("/tmp/definitely-missing-keypair-file.json");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::IoError(_)));
}
