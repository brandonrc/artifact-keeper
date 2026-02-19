//! Storage garbage collection service.
//!
//! Finds soft-deleted artifacts whose storage keys are no longer referenced
//! by any live artifact, deletes the physical storage files, and hard-deletes
//! the artifact records from the database.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::error::Result;
use crate::storage::StorageBackend;

/// Result of a storage GC run.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StorageGcResult {
    pub dry_run: bool,
    pub storage_keys_deleted: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
}

/// Storage garbage collection service.
pub struct StorageGcService {
    db: PgPool,
    storage: Arc<dyn StorageBackend>,
}

impl StorageGcService {
    pub fn new(db: PgPool, storage: Arc<dyn StorageBackend>) -> Self {
        Self { db, storage }
    }

    /// Run garbage collection on orphaned storage keys.
    ///
    /// Finds storage keys referenced only by soft-deleted artifacts (no live
    /// artifact shares the same key), deletes the physical file, then
    /// hard-deletes the database records.
    pub async fn run_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        // Find orphaned storage keys: keys where ALL referencing artifacts are deleted
        let orphans = sqlx::query(
            r#"
            SELECT DISTINCT a.storage_key, SUM(a.size_bytes) as total_bytes, COUNT(*) as artifact_count
            FROM artifacts a
            WHERE a.is_deleted = true
              AND NOT EXISTS (
                SELECT 1 FROM artifacts a2
                WHERE a2.storage_key = a.storage_key
                  AND a2.is_deleted = false
              )
            GROUP BY a.storage_key
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        let mut result = StorageGcResult {
            dry_run,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: Vec::new(),
        };

        if dry_run {
            for row in &orphans {
                let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
                let count: i64 = row.try_get("artifact_count").unwrap_or(0);
                result.storage_keys_deleted += 1;
                result.artifacts_removed += count;
                result.bytes_freed += bytes;
            }
            return Ok(result);
        }

        for row in &orphans {
            let storage_key: String = row.try_get("storage_key").unwrap_or_default();
            let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
            let count: i64 = row.try_get("artifact_count").unwrap_or(0);

            // Delete the physical file first
            if let Err(e) = self.storage.delete(&storage_key).await {
                let msg = format!("Failed to delete storage key {}: {}", storage_key, e);
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                // Skip DB cleanup if storage delete fails
                continue;
            }

            // Delete promotion_approvals (no CASCADE on this FK)
            if let Err(e) = sqlx::query(
                r#"
                DELETE FROM promotion_approvals
                WHERE artifact_id IN (
                    SELECT id FROM artifacts
                    WHERE storage_key = $1 AND is_deleted = true
                )
                "#,
            )
            .bind(&storage_key)
            .execute(&self.db)
            .await
            {
                let msg = format!(
                    "Failed to delete promotion_approvals for key {}: {}",
                    storage_key, e
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // Hard-delete artifact records (cascades to child tables)
            match sqlx::query(
                "DELETE FROM artifacts WHERE storage_key = $1 AND is_deleted = true",
            )
            .bind(&storage_key)
            .execute(&self.db)
            .await
            {
                Ok(_) => {
                    result.storage_keys_deleted += 1;
                    result.artifacts_removed += count;
                    result.bytes_freed += bytes;
                }
                Err(e) => {
                    let msg = format!(
                        "Failed to hard-delete artifacts for key {}: {}",
                        storage_key, e
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if result.storage_keys_deleted > 0 {
            tracing::info!(
                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                result.storage_keys_deleted,
                result.artifacts_removed,
                result.bytes_freed
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_gc_result_serialization() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 5,
            artifacts_removed: 12,
            bytes_freed: 1024 * 1024,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"storage_keys_deleted\":5"));
        assert!(json.contains("\"artifacts_removed\":12"));
    }

    #[test]
    fn test_storage_gc_result_dry_run() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn test_storage_gc_result_with_errors() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 3,
            artifacts_removed: 3,
            bytes_freed: 512,
            errors: vec!["Failed to delete key abc".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.errors.len(), 1);
        assert_eq!(deserialized.storage_keys_deleted, 3);
    }
}
