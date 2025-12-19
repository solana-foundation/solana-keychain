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
