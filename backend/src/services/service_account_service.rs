//! Service account management.
//!
//! Service accounts are machine identities managed by admins. They
//! authenticate only via API tokens (no password, no TOTP, no SSO).

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// Summary of a service account for list responses.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceAccountSummary {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub token_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct ServiceAccountService {
    db: PgPool,
}

impl ServiceAccountService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new service account.
    pub async fn create(&self, name: &str, description: Option<&str>) -> Result<User> {
        // Validate name: alphanumeric + hyphens, 2-64 chars
        let username = format!("svc-{}", name.to_lowercase().replace(' ', "-"));
        if username.len() > 64 || !username.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Err(AppError::Validation(
                "Service account name must be alphanumeric with hyphens, 2-64 characters"
                    .to_string(),
            ));
        }

        let email = format!("{}@service-accounts.local", username);
        let id = Uuid::new_v4();

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                id, username, email, display_name, auth_provider,
                is_admin, is_active, is_service_account, must_change_password
            )
            VALUES ($1, $2, $3, $4, 'local', false, true, true, false)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            "#,
            id,
            username,
            email,
            description,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Validation(format!("Service account '{}' already exists", username))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        Ok(user)
    }

    /// List all service accounts.
    pub async fn list(&self, include_inactive: bool) -> Result<Vec<ServiceAccountSummary>> {
        let rows = sqlx::query_as!(
            ServiceAccountSummary,
            r#"
            SELECT
                u.id,
                u.username,
                u.display_name,
                u.is_active,
                COALESCE(t.cnt, 0) as "token_count!: i64",
                u.created_at,
                u.updated_at
            FROM users u
            LEFT JOIN (
                SELECT user_id, COUNT(*) as cnt
                FROM api_tokens
                GROUP BY user_id
            ) t ON t.user_id = u.id
            WHERE u.is_service_account = true
              AND ($1 OR u.is_active = true)
            ORDER BY u.created_at DESC
            "#,
            include_inactive
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Get a single service account by ID.
    pub async fn get(&self, id: Uuid) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            FROM users
            WHERE id = $1 AND is_service_account = true
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Service account not found".to_string()))?;

        Ok(user)
    }

    /// Update a service account's display name or active status.
    pub async fn update(
        &self,
        id: Uuid,
        display_name: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<User> {
        // Verify it's a service account
        self.get(id).await?;

        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET display_name = COALESCE($2, display_name),
                is_active = COALESCE($3, is_active),
                updated_at = NOW()
            WHERE id = $1 AND is_service_account = true
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            "#,
            id,
            display_name,
            is_active
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(user)
    }

    /// Delete a service account and all its tokens (via CASCADE).
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM users WHERE id = $1 AND is_service_account = true",
            id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Service account not found".to_string()));
        }

        Ok(())
    }
}
