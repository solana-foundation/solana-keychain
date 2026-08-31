//! Getting a signed transaction on chain.

use std::future::Future;

use crate::error::SignerError;
use crate::sdk_adapter::{Signature, VersionedTransaction};
use crate::traits::{ModifyingSigner, SignTransactionResult, TransactionSigner};

/// Sign `tx` and get it on chain with one call.
///
/// The signer signs and `send` broadcasts the encoded wire transaction. The
/// crate has no RPC client, so the network hop is always caller-supplied.
/// A [`SendingSigner`](crate::traits::SendingSigner) broadcasts through its
/// provider instead; call its `sign_and_send_transaction` directly. A
/// [`ModifyingSigner`] rewrites the transaction before signing it, so route it
/// through [`Signer::sign_and_send`](crate::Signer::sign_and_send).
///
/// # Errors
///
/// [`SignerError::SigningFailed`] when the transaction is still partially
/// signed. Backend signing errors propagate unchanged. A `send` failure becomes
/// [`SignerError::BroadcastUnconfirmed`] carrying the completed transaction's
/// fee-payer signature.
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
    broadcast_complete(result, tx.signatures.first().copied(), send).await
}

/// Let the signer rewrite `tx`, then get the rewritten transaction on chain.
///
/// `tx` is replaced with the transaction the signature covers, and `send`
/// broadcasts that one.
pub(crate) async fn modify_and_send<S, F, Fut>(
    signer: &S,
    tx: &mut VersionedTransaction,
    send: F,
) -> Result<Signature, SignerError>
where
    S: ModifyingSigner + ?Sized,
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Signature, SignerError>>,
{
    let result = signer.modify_and_sign_transaction(tx).await?;
    broadcast_complete(result, tx.signatures.first().copied(), send).await
}

async fn broadcast_complete<F, Fut>(
    result: SignTransactionResult,
    transaction_signature: Option<Signature>,
    send: F,
) -> Result<Signature, SignerError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Signature, SignerError>>,
{
    let is_complete = matches!(result, SignTransactionResult::Complete(_));
    let (encoded_transaction, _) = result.into_signed_transaction();

    if !is_complete {
        return Err(SignerError::SigningFailed(
            "Transaction is still missing signatures after signing and cannot be broadcast"
                .to_string(),
        ));
    }
    let transaction_signature = transaction_signature
        .filter(|signature| *signature != Signature::default())
        .ok_or_else(|| {
            SignerError::SigningFailed(
                "Broadcast transaction has no fee payer signature to identify it by".to_string(),
            )
        })?;
    send(encoded_transaction)
        .await
        .map_err(|error| SignerError::BroadcastUnconfirmed {
            provider_tx_id: None,
            provider_status: None,
            idempotency_key: None,
            transaction_signature: Some(Box::new(transaction_signature)),
            detail: error.detail_string(),
        })
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
