use crate::sdk_adapter::Hash;
use std::error::Error;
use std::str::FromStr;

/// Fetch latest blockhash from a real Solana RPC endpoint
pub async fn get_rpc_blockhash(rpc_url: &str) -> Result<Hash, Box<dyn Error>> {
    let client = reqwest::Client::new();

    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": []
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let response_json: serde_json::Value = response.json().await?;

    let blockhash_str = response_json["result"]["value"]["blockhash"]
        .as_str()
        .ok_or("Failed to get blockhash from RPC response")?;

    Hash::from_str(blockhash_str).map_err(|e| e.into())
}

/// Send a base64-encoded signed wire transaction via `sendTransaction`.
/// Returns the transaction signature.
pub async fn send_raw_transaction(
    rpc_url: &str,
    base64_tx: &str,
) -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();

    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [base64_tx, { "encoding": "base64" }]
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let response_json: serde_json::Value = response.json().await?;

    if let Some(error) = response_json.get("error") {
        return Err(format!("sendTransaction RPC error: {error}").into());
    }

    response_json["result"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "sendTransaction response missing result".into())
}

/// Poll `getSignatureStatuses` until the transaction is confirmed or finalized,
/// or `timeout_secs` elapses.
pub async fn confirm_transaction(
    rpc_url: &str,
    signature: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    while std::time::Instant::now() < deadline {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature], { "searchTransactionHistory": true }]
        });

        let response = client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;
        let status = &response_json["result"]["value"][0];

        if !status.is_null() {
            if let Some(err) = status.get("err").filter(|v| !v.is_null()) {
                return Err(format!("Transaction failed on-chain: {err}").into());
            }

            let confirmation = status["confirmationStatus"].as_str().unwrap_or("");
            if confirmation == "confirmed" || confirmation == "finalized" {
                return Ok(());
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    Err(format!("Timed out waiting for confirmation of {signature}").into())
}
