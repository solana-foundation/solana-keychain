//! Openfort backend wallet API request/response types.

use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
pub(super) struct SignResponse {
    pub object: String,
    pub account: String,
    pub signature: String,
}

/// Subset of `GET /v1/accounts/{id}` we care about — just the on-chain address.
#[derive(Deserialize)]
pub(super) struct AccountInfo {
    pub address: String,
}
