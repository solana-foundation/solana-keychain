use async_trait::async_trait;

use super::{require_broadcast_signature, sign_and_send};
use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::test_util::create_test_transaction;
use crate::traits::{SignTransactionResult, SolanaSigner, TransactionSigner};

const ENCODED: &str = "encoded-transaction";

struct StubSigner {
    complete: bool,
    signature: Signature,
}

impl StubSigner {
    fn new(complete: bool) -> Self {
        Self {
            complete,
            signature: Signature::from([7u8; 64]),
        }
    }
}

#[async_trait]
impl SolanaSigner for StubSigner {
    fn pubkey(&self) -> Pubkey {
        Pubkey::new_unique()
    }

    async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.signature)
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[async_trait]
impl TransactionSigner for StubSigner {
    async fn sign_transaction(
        &self,
        _tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed = (ENCODED.to_string(), self.signature);
        Ok(if self.complete {
            SignTransactionResult::Complete(signed)
        } else {
            SignTransactionResult::Partial(signed)
        })
    }
}

#[tokio::test]
async fn sign_only_signer_broadcasts_the_encoded_transaction() {
    let signer = StubSigner::new(true);
    let mut tx = create_test_transaction(&Pubkey::new_unique());
    let broadcast_signature = Signature::from([9u8; 64]);

    let signature = sign_and_send(&signer, &mut tx, |encoded| async move {
        assert_eq!(encoded, ENCODED);
        Ok(broadcast_signature)
    })
    .await
    .unwrap();

    assert_eq!(signature, broadcast_signature);
}

/// A partially signed transaction cannot land, so it must never be broadcast.
#[tokio::test]
async fn partial_signature_is_rejected_before_broadcast() {
    let signer = StubSigner::new(false);
    let mut tx = create_test_transaction(&Pubkey::new_unique());

    let error = sign_and_send(&signer, &mut tx, |_| async {
        panic!("send must not run for a partially signed transaction");
    })
    .await
    .unwrap_err();

    assert!(matches!(error, SignerError::SigningFailed(_)));
}

/// The signature a broadcasting provider returns is the only handle on the
/// transaction it just put on chain, so an empty one cannot be passed off as one.
#[test]
fn empty_broadcast_signature_is_rejected() {
    let error = require_broadcast_signature(Signature::default()).unwrap_err();
    assert!(matches!(error, SignerError::SigningFailed(_)));

    let signature = Signature::from([9u8; 64]);
    assert_eq!(require_broadcast_signature(signature).unwrap(), signature);
}
