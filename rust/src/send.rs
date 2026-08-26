//! Getting a signed transaction on chain.

use std::future::Future;

use crate::error::SignerError;
use crate::sdk_adapter::{Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, TransactionSigner};

/// Sign `tx` and get it on chain with one call.
///
/// The signer signs and `send` broadcasts the encoded wire transaction. The
/// crate has no RPC client, so the network hop is always caller-supplied.
/// A [`SendingSigner`](crate::traits::SendingSigner) broadcasts through its
/// provider instead; call its `sign_and_send_transaction` directly.
///
/// # Errors
///
/// [`SignerError::SigningFailed`] when the transaction is still partially
/// signed. Backend signing errors and anything `send` returns propagate
/// unchanged.
pub async fn sign_and_send<S, F, Fut>(
    signer: &S,
    tx: &mut VersionedTransaction,
    send: F,
) -> Result<Signature, SignerError>
where
    S: TransactionSigner + ?Sized,
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Signature, SignerError>>,
{
    let result = signer.sign_transaction(tx).await?;
    let is_complete = matches!(result, SignTransactionResult::Complete(_));
    let (encoded_transaction, _) = result.into_signed_transaction();

    if !is_complete {
        return Err(SignerError::SigningFailed(
            "Transaction is still missing signatures after signing and cannot be broadcast"
                .to_string(),
        ));
    }
    send(encoded_transaction).await
}

pub(crate) fn require_broadcast_signature(signature: Signature) -> Result<Signature, SignerError> {
    if signature == Signature::default() {
        return Err(SignerError::SigningFailed(
            "Signer returned no signature for the transaction it broadcast".to_string(),
        ));
    }
    Ok(signature)
}

#[cfg(test)]
mod tests;
