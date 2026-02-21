//! API token model.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// API token entity for programmatic access.
///
/// Tokens are stored as hashes with only a prefix stored in plaintext
/// for identification purposes. The full token is only returned once
/// during creation and cannot be retrieved later.
#[derive(Clone, FromRow, Serialize)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by_user_id: Option<Uuid>,
    pub description: Option<String>,
    pub repo_selector: Option<serde_json::Value>,
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("token_hash", &"[REDACTED]")
            .field("token_prefix", &self.token_prefix)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Response type for API token creation (includes the actual token only once).
#[derive(Clone, Serialize)]
pub struct ApiTokenCreated {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub repository_ids: Vec<Uuid>,
}

impl fmt::Debug for ApiTokenCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiTokenCreated")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("token", &"[REDACTED]")
            .field("token_prefix", &self.token_prefix)
            .finish_non_exhaustive()
    }
}
