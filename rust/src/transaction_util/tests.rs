
#[cfg(feature = "sdk-v4")]
use super::*;
#[cfg(feature = "sdk-v4")]
use crate::test_util::{create_test_transaction, create_test_v1_transaction};

#[cfg(feature = "sdk-v4")]
#[test]
fn wincode_matches_bincode_for_a_legacy_transaction() {
    let transaction = create_test_transaction(&Pubkey::new_unique());

    let wire = serialize_wire_transaction(&transaction).expect("serialize");
    let bincode_wire = bincode::serialize(&transaction).expect("bincode serialize");

    assert_eq!(wire, bincode_wire);
}

#[cfg(feature = "sdk-v4")]
#[test]
fn v1_envelope_places_the_message_first_and_signatures_last() {
    let transaction = create_test_v1_transaction(&Pubkey::new_unique());
    let message_bytes = transaction.message.serialize();

    let wire = serialize_wire_transaction(&transaction).expect("serialize");

    assert_eq!(message_bytes[0], 0x81);
    assert_eq!(wire[..message_bytes.len()], message_bytes[..]);
    assert_eq!(wire.len(), message_bytes.len() + 64);
    assert_ne!(wire, bincode::serialize(&transaction).expect("bincode"));
}

#[cfg(feature = "sdk-v4")]
#[test]
fn v1_wire_transaction_round_trips() {
    let transaction = create_test_v1_transaction(&Pubkey::new_unique());
    let wire = serialize_wire_transaction(&transaction).expect("serialize");

    let decoded = deserialize_wire_transaction(&wire).expect("deserialize");

    assert_eq!(decoded.message.serialize(), transaction.message.serialize());
    assert_eq!(decoded.signatures, transaction.signatures);
}
