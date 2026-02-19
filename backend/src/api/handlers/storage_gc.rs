//! Storage garbage collection API handler.

use axum::{extract::State, routing::post, Json, Router};
use axum::extract::Extension;
use serde::Deserialize;
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::storage_gc_service::{StorageGcResult, StorageGcService};
use crate::storage::filesystem::FilesystemStorage;

#[derive(OpenApi)]
#[openapi(
    paths(run_storage_gc),
    components(schemas(StorageGcRequest, StorageGcResult))
)]
pub struct StorageGcApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new().route("/", post(run_storage_gc))
}

/// Request body for storage GC.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StorageGcRequest {
    /// When true, report what would be deleted without actually deleting.
    #[serde(default)]
    pub dry_run: bool,
}

/// POST /api/v1/admin/storage-gc
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/admin/storage-gc",
    tag = "admin",
    operation_id = "run_storage_gc",
    request_body = StorageGcRequest,
    responses(
        (status = 200, description = "GC result", body = StorageGcResult),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn run_storage_gc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<StorageGcRequest>,
) -> Result<Json<StorageGcResult>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }

    let storage = Arc::new(FilesystemStorage::new(&state.config.storage_path));
    let service = StorageGcService::new(state.db.clone(), storage);
    let result = service.run_gc(payload.dry_run).await?;
    Ok(Json(result))
}
