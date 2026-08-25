//! Getting a signed transaction on chain, whichever shape the signer has.

use std::future::Future;

use crate::error::SignerError;
use crate::sdk_adapter::{Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SolanaSigner};

/// Sign `tx` and get it on chain with one call.
///
/// A signer that reports [`SolanaSigner::broadcasts_transactions`] broadcasts
/// through its provider, so its own signature identifies the transaction and `send`
/// is never called; any other signer signs and `send` broadcasts the encoded wire
/// transaction. The crate has no RPC client, so the network hop is always
/// caller-supplied.
///
/// # Errors
///
/// [`SignerError::SigningFailed`] when a broadcasting signer returns no signature,
/// or when the transaction is still partially signed. Backend signing errors and
/// anything `send` returns propagate unchanged.
pub async fn sign_and_send<S, F, Fut>(
    signer: &S,
    tx: &mut VersionedTransaction,
    send: F,
) -> Result<Signature, SignerError>
where
    S: SolanaSigner + ?Sized,
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Signature, SignerError>>,
{
    if signer.broadcasts_transactions() {
        let signature = signer.sign_and_send_transaction(tx).await?;
        if signature == Signature::default() {
            return Err(SignerError::SigningFailed(
                "Signer returned no signature for the transaction it broadcast".to_string(),
            ));
        }
        return Ok(signature);
    }

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

#[cfg(test)]
mod tests;
