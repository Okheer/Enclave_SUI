//! Walrus blob storage client.
//!
//! Uploads quote log blobs to the Walrus decentralized storage network.
//! Walrus exposes an HTTP PUT endpoint at the publisher URL.
//! See: <https://docs.walrus.site>

use crate::error::{Result, TeeError};
use reqwest::Client as HttpClient;
use serde::Deserialize;

/// Default Walrus publisher endpoint (testnet).
const DEFAULT_PUBLISHER_URL: &str = "https://publisher.walrus-testnet.walrus.space";

/// Response from the Walrus publisher after a successful blob upload.
#[derive(Debug, Deserialize)]
pub struct WalrusUploadResponse {
    #[serde(rename = "blobId")]
    pub blob_id: String,
    #[serde(rename = "event")]
    pub event: Option<WalrusEvent>,
    #[serde(rename = "alreadyCertified")]
    pub already_certified: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct WalrusEvent {
    #[serde(rename = "txDigest")]
    pub tx_digest: Option<String>,
    #[serde(rename = "eventType")]
    pub event_type: String,
}

/// Client for uploading blobs to Walrus.
pub struct WalrusClient {
    http_client: HttpClient,
    publisher_url: String,
}

impl WalrusClient {
    /// Create a new Walrus client with the default publisher URL.
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
            publisher_url: DEFAULT_PUBLISHER_URL.to_string(),
        }
    }

    /// Create a Walrus client with a custom publisher URL.
    pub fn with_publisher(publisher_url: String) -> Self {
        Self {
            http_client: HttpClient::new(),
            publisher_url,
        }
    }

    /// Upload raw bytes to Walrus and return the blob ID.
    ///
    /// The blob ID is a Base64-encoded BLAKE2b-256 hash of the content,
    /// used as the `walrus_blob_id` field in the Move `Attestation` struct.
    pub async fn upload_blob(&self, data: &[u8]) -> Result<String> {
        let url = format!("{}/v1/blobs", self.publisher_url);

        let response = self
            .http_client
            .put(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| TeeError::CommunicationError(format!("Walrus upload failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unreadable body".to_string());
            return Err(TeeError::CommunicationError(format!(
                "Walrus returned HTTP {}: {}",
                status, body
            )));
        }

        let walrus_resp: WalrusUploadResponse = response
            .json()
            .await
            .map_err(|e| TeeError::CommunicationError(format!("Failed to parse Walrus response: {}", e)))?;

        Ok(walrus_resp.blob_id)
    }

    /// Upload a JSON-serializable value as the quote log blob.
    pub async fn upload_json<T: serde::Serialize>(&self, value: &T) -> Result<String> {
        let json_bytes = serde_json::to_vec(value)
            .map_err(|e| TeeError::SerializationError(format!("JSON serialization failed: {}", e)))?;
        self.upload_blob(&json_bytes).await
    }
}

impl Default for WalrusClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walrus_client_creation() {
        let _client = WalrusClient::new();
    }

    #[test]
    fn test_walrus_client_custom_url() {
        let _client = WalrusClient::with_publisher("https://custom-publisher.example.com".to_string());
    }

    #[tokio::test]
    async fn test_upload_fails_without_server() {
        let client = WalrusClient::with_publisher("http://localhost:9999".to_string());
        let result = client.upload_blob(b"test data").await;
        assert!(result.is_err(), "Should fail connecting to nowhere");
    }
}
