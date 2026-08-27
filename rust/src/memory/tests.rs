use crate::test_util::create_test_transaction;
#[cfg(feature = "sdk-v4")]
use crate::test_util::create_test_v1_transaction;
#[cfg(feature = "sdk-v4")]
use base64::Engine;

use super::*;

const TEST_KEYPAIR_BYTES: &str = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]";
const TEST_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

fn create_test_signer() -> MemorySigner {
    MemorySigner::from_private_key_string(TEST_KEYPAIR_BYTES).expect("Failed to create test signer")
}

#[test]
fn test_create_from_u8_array() {
    let signer = MemorySigner::from_private_key_string(TEST_KEYPAIR_BYTES);
    assert!(signer.is_ok());
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_create_from_file() {
    let tmp_dir = std::env::temp_dir();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let file_path = tmp_dir.join(format!("solana-keychain-memory-signer-{unique}.json"));

    std::fs::write(&file_path, TEST_KEYPAIR_BYTES).expect("failed to write temp keypair file");
    let result = MemorySigner::from_private_key_file(&file_path.to_string_lossy());
    assert!(result.is_ok());
    assert_eq!(result.unwrap().pubkey().to_string(), TEST_PUBKEY);

    let _ = std::fs::remove_file(&file_path);
}

#[test]
fn test_pubkey() {
    let signer = create_test_signer();
    let pubkey = signer.pubkey();
    assert_eq!(pubkey.to_string(), TEST_PUBKEY);
}

#[cfg_attr(miri, ignore)]
#[tokio::test]
async fn test_sign_message() {
    let signer = create_test_signer();
    let message = b"Hello Solana!";
    let signature = signer.sign_message(message).await;

    assert!(signature.is_ok());
    let sig = signature.unwrap();
    assert_eq!(sig.as_ref().len(), 64);
}

#[cfg_attr(miri, ignore)]
#[tokio::test]
async fn test_is_available() {
    let signer = create_test_signer();
    assert!(signer.is_available().await);
}

#[cfg_attr(miri, ignore)]
#[tokio::test]
async fn test_sign_transaction() {
    let signer = create_test_signer();

    let mut tx = create_test_transaction(&keypair_pubkey(&signer.keypair));

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_ok());

    let (serialized_tx, signature) = result.unwrap().into_signed_transaction();

    // Verify the signature is valid
    assert_eq!(signature.as_ref().len(), 64);

    // Verify the transaction is properly serialized
    assert!(!serialized_tx.is_empty());

    // Verify the transaction has the signature
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(tx.signatures[0], signature);
}

#[cfg(feature = "sdk-v4")]
#[cfg_attr(miri, ignore)]
#[tokio::test]
async fn test_sign_v1_transaction() {
    let signer = create_test_signer();
    let pubkey = keypair_pubkey(&signer.keypair);
    let mut tx = create_test_v1_transaction(&pubkey);

    let message_bytes = tx.message.serialize();
    assert_eq!(message_bytes[0], 0x81);

    let result = signer
        .sign_transaction(&mut tx)
        .await
        .expect("v1 transaction should sign");
    let (serialized_tx, signature) = result.into_signed_transaction();

    assert!(signature.verify(&pubkey.to_bytes(), &message_bytes));
    assert_eq!(tx.signatures[0], signature);

    let wire = base64::engine::general_purpose::STANDARD
        .decode(&serialized_tx)
        .expect("serialized transaction should be base64");
    assert_eq!(wire[..message_bytes.len()], message_bytes[..]);
    assert_eq!(wire.len(), message_bytes.len() + 64);
}
