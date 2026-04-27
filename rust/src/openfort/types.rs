//! Openfort backend wallet API request/response types.

use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
pub(super) struct SignResponse {
    pub object: String,
    pub account: String,
    pub signature: String,
}
