use async_trait::async_trait;

use super::sign_and_send;
use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::test_util::create_test_transaction;
use crate::traits::{SignTransactionResult, SolanaSigner};

const ENCODED: &str = "encoded-transaction";

struct StubSigner {
    broadcasts: bool,
    complete: bool,
    signature: Signature,
}

impl StubSigner {
    fn new(broadcasts: bool, complete: bool) -> Self {
        Self {
            broadcasts,
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

    fn broadcasts_transactions(&self) -> bool {
        self.broadcasts
    }

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

    async fn sign_and_send_transaction(
        &self,
        _tx: &mut VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        Ok(self.signature)
    }

    async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.signature)
    }

    async fn is_available(&self) -> bool {
        true
    }
}

/// A provider that broadcasts server-side already put the transaction on chain.
#[tokio::test]
async fn broadcasting_signer_skips_the_injected_send() {
    let signer = StubSigner::new(true, true);
    let mut tx = create_test_transaction(&Pubkey::new_unique());

    let signature = sign_and_send(&signer, &mut tx, |_| async {
        panic!("send must not run for a signer that broadcasts");
    })
    .await
    .unwrap();

    assert_eq!(signature, signer.signature);
}

#[tokio::test]
async fn sign_only_signer_broadcasts_the_encoded_transaction() {
    let signer = StubSigner::new(false, true);
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

/// The signature a broadcasting provider returns is the only handle on the
/// transaction it just put on chain, so an empty one cannot be passed off as one.
#[tokio::test]
async fn broadcasting_signer_without_a_signature_is_rejected() {
    let mut signer = StubSigner::new(true, true);
    signer.signature = Signature::default();
    let mut tx = create_test_transaction(&Pubkey::new_unique());

    let error = sign_and_send(&signer, &mut tx, |_| async {
        panic!("send must not run for a signer that broadcasts");
    })
    .await
    .unwrap_err();

    assert!(matches!(error, SignerError::SigningFailed(_)));
}

/// A partially signed transaction cannot land, so it must never be broadcast.
#[tokio::test]
async fn partial_signature_is_rejected_before_broadcast() {
    let signer = StubSigner::new(false, false);
    let mut tx = create_test_transaction(&Pubkey::new_unique());

    let error = sign_and_send(&signer, &mut tx, |_| async {
        panic!("send must not run for a partially signed transaction");
    })
    .await
    .unwrap_err();

    assert!(matches!(error, SignerError::SigningFailed(_)));
}
