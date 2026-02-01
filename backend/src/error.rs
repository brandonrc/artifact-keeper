//! Application error types and result alias.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Application result type alias
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Missing credentials
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Access denied: {0}")]
    Authorization(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Duplicate resource (e.g., artifact version already exists)
    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("WASM error: {0}")]
    Wasm(#[from] crate::services::wasm_runtime::WasmError),
}

impl AppError {
    /// Map error variant to HTTP status code and machine-readable error code.
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR"),
            Self::Database(_) | Self::Sqlx(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
            }
            Self::Migration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MIGRATION_ERROR"),
            Self::Authentication(_) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::Authorization(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::QuotaExceeded(_) => (StatusCode::INSUFFICIENT_STORAGE, "QUOTA_EXCEEDED"),
            Self::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"),
            Self::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR"),
            Self::AddrParse(_) => (StatusCode::INTERNAL_SERVER_ERROR, "ADDR_PARSE_ERROR"),
            Self::Json(_) => (StatusCode::BAD_REQUEST, "JSON_ERROR"),
            Self::Jwt(_) => (StatusCode::UNAUTHORIZED, "JWT_ERROR"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::Wasm(_) => (StatusCode::INTERNAL_SERVER_ERROR, "WASM_ERROR"),
        }
    }

    /// Return a user-facing message. Internal details are hidden for
    /// wrapped foreign errors (Sqlx, Io, etc.) to avoid leaking internals.
    fn user_message(&self) -> String {
        match self {
            Self::Sqlx(_) => "Database operation failed".to_string(),
            Self::Migration(_) => "Database migration failed".to_string(),
            Self::Io(_) => "IO operation failed".to_string(),
            Self::AddrParse(_) => "Invalid address".to_string(),
            Self::Json(_) => "Invalid JSON".to_string(),
            Self::Jwt(_) => "Invalid token".to_string(),
            // All other variants carry their own user-facing message
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = self.user_message();

        tracing::error!(error = %self, code = code, "Request error");

        let body = Json(json!({
            "code": code,
            "message": message,
        }));

        (status, body).into_response()
    }
}
