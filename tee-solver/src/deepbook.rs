//! DeepBook pool query client.
//!
//! Resolves DeepBook pool IDs from token type names by querying a Sui full node.
//! In production this queries the on-chain `Pool` objects created by DeepBook.
//! Locally it can operate from a cached pool registry.

use crate::error::{Result, TeeError};
use crate::types::ObjectID;
use serde::{Deserialize, Serialize};

/// Represents a DeepBook pool and its token pair type names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolInfo {
    /// The 32-byte Sui object ID of the pool.
    pub pool_id: ObjectID,
    /// String representation of the input token type (e.g. "0x2::sui::SUI").
    pub token_in_type: String,
    /// String representation of the output token type.
    pub token_out_type: String,
}

/// Client for resolving DeepBook pool IDs.
///
/// Uses a local cache and optionally queries a Sui full node.
pub struct DeepBookClient {
    /// Cached pool registry: (token_in, token_out) → pool_id
    pool_cache: std::sync::RwLock<Vec<PoolInfo>>,
    /// Optional Sui RPC endpoint for on-chain queries.
    rpc_endpoint: Option<String>,
}

impl DeepBookClient {
    /// Create a new DeepBook client with an empty cache.
    pub fn new() -> Self {
        Self {
            pool_cache: std::sync::RwLock::new(Vec::new()),
            rpc_endpoint: None,
        }
    }

    /// Create a DeepBook client with a Sui RPC endpoint for on-chain queries.
    pub fn with_rpc(rpc_endpoint: String) -> Self {
        Self {
            pool_cache: std::sync::RwLock::new(Vec::new()),
            rpc_endpoint: Some(rpc_endpoint),
        }
    }

    /// Seed the cache with known pool infos (e.g. from a config file).
    pub fn seed_cache(&self, pools: Vec<PoolInfo>) {
        let mut cache = self.pool_cache.write().unwrap();
        cache.extend(pools);
    }

    /// Resolve a pool ID for a given token pair.
    ///
    /// First checks the local cache, then falls back to an on-chain query
    /// if a Sui RPC endpoint is configured.
    pub fn resolve_pool(&self, token_in: &str, token_out: &str) -> Result<ObjectID> {
        // Check cache first
        {
            let cache = self.pool_cache.read().unwrap();
            for pool in cache.iter() {
                if pool.token_in_type == token_in && pool.token_out_type == token_out {
                    return Ok(pool.pool_id);
                }
            }
        }

        // Fallback: if RPC endpoint is configured, query on-chain
        if let Some(_rpc) = &self.rpc_endpoint {
            // TODO: query Sui full node for Pool objects matching the type parameters
            // For now, return an error — pools must be configured or queried.
            return Err(TeeError::InternalError(format!(
                "Pool not found for {} → {}",
                token_in, token_out
            )));
        }

        Err(TeeError::InternalError(format!(
            "No pool registered for {} → {} and no RPC endpoint configured",
            token_in, token_out
        )))
    }

    /// Register a pool in the local cache.
    pub fn register_pool(&self, pool_id: ObjectID, token_in: String, token_out: String) {
        let mut cache = self.pool_cache.write().unwrap();
        cache.push(PoolInfo {
            pool_id,
            token_in_type: token_in,
            token_out_type: token_out,
        });
    }

    /// List all cached pools.
    pub fn list_pools(&self) -> Vec<PoolInfo> {
        self.pool_cache.read().unwrap().clone()
    }
}

impl Default for DeepBookClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_cached_pool() {
        let client = DeepBookClient::new();
        let pool_id = [0x01u8; 32];
        client.register_pool(
            pool_id,
            "0x2::sui::SUI".to_string(),
            "0x2::sui::SUI".to_string(),
        );

        let resolved = client.resolve_pool("0x2::sui::SUI", "0x2::sui::SUI").unwrap();
        assert_eq!(resolved, pool_id);
    }

    #[test]
    fn test_resolve_missing_pool() {
        let client = DeepBookClient::new();
        let result = client.resolve_pool("0x2::sui::SUI", "0xdead::beef::TOKEN");
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_cache() {
        let client = DeepBookClient::new();
        let pool_id = [0x02u8; 32];
        client.seed_cache(vec![PoolInfo {
            pool_id,
            token_in_type: "A".to_string(),
            token_out_type: "B".to_string(),
        }]);

        let resolved = client.resolve_pool("A", "B").unwrap();
        assert_eq!(resolved, pool_id);
    }
}
