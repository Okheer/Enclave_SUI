use crate::error::Result;
use base64::Engine as _;
use serde_json::{json, Value};

/// Minimal Sui JSON-RPC client for dry-running and executing settlement transactions.
#[derive(Clone)]
pub struct SuiRpcClient {
    rpc_url: String,
    client: reqwest::Client,
}

impl SuiRpcClient {
    /// Create a new client connected to the given Sui JSON-RPC endpoint.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Dry-run a BCS-encoded `Transaction` (or `TransactionKind` / `ProgrammableTransaction`).
    ///
    /// The Sui RPC expects a full `Transaction` (with sender + gas payment).
    /// Returns the raw JSON-RPC result.
    pub async fn dry_run_tx(&self, tx_bytes: &[u8]) -> Result<Value> {
        let base64_tx = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
        self.call("sui_dryRunTransactionBlock", vec![Value::String(base64_tx)])
            .await
    }

    /// Execute a signed transaction.
    ///
    /// `tx_bytes` should be BCS-encoded `Transaction` bytes.
    /// `signatures` should be base64-encoded user signatures.
    pub async fn execute_tx(
        &self,
        tx_bytes: &[u8],
        signatures: &[String],
    ) -> Result<Value> {
        let base64_tx = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
        let sigs: Vec<Value> = signatures
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        self.call(
            "sui_executeTransactionBlock",
            vec![
                Value::String(base64_tx),
                Value::Array(sigs),
                Value::Null, // request_type = WaitForEffectsCert
            ],
        )
        .await
    }

    /// Fetch an object by its 32-byte ID.
    pub async fn get_object(&self, object_id: &[u8; 32]) -> Result<Value> {
        let hex_id = format!("0x{}", hex::encode(object_id));
        self.call(
            "sui_getObject",
            vec![
                Value::String(hex_id),
                json!({"showType": true, "showContent": true}),
            ],
        )
        .await
    }

    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::TeeError::NetworkError(format!("RPC request failed: {e}")))?;

        let value: Value = resp
            .json()
            .await
            .map_err(|e| crate::error::TeeError::NetworkError(format!("RPC parse failed: {e}")))?;

        if let Some(err) = value.get("error") {
            return Err(crate::error::TeeError::NetworkError(format!(
                "RPC error: {err}"
            )));
        }

        value
            .get("result")
            .cloned()
            .ok_or_else(|| crate::error::TeeError::NetworkError("RPC missing result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = SuiRpcClient::new("https://fullnode.testnet.sui.io:443");
        assert_eq!(client.rpc_url, "https://fullnode.testnet.sui.io:443");
    }
}
