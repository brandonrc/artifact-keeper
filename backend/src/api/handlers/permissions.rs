//! Permission management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create permission routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_permissions).post(create_permission))
        .route(
            "/:id",
            get(get_permission).put(update_permission).delete(delete_permission),
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_principal_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PrincipalType {
    User,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_target_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TargetType {
    Repository,
    Group,
    Artifact,
}

#[derive(Debug, Deserialize)]
pub struct ListPermissionsQuery {
    pub principal_type: Option<String>,
    pub principal_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub principal_name: Option<String>,
    pub target_type: String,
    pub target_id: Uuid,
    pub target_name: Option<String>,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct PermissionListResponse {
    pub items: Vec<PermissionResponse>,
    pub pagination: Pagination,
}

/// List permissions
pub async fn list_permissions(
    State(state): State<SharedState>,
    Query(query): Query<ListPermissionsQuery>,
) -> Result<Json<PermissionListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let permissions = sqlx::query!(
        r#"
        SELECT p.id, p.principal_type, p.principal_id, p.target_type, p.target_id,
               p.actions, p.created_at, p.updated_at,
               CASE
                   WHEN p.principal_type = 'user' THEN u.username
                   WHEN p.principal_type = 'group' THEN g.name
               END as principal_name,
               CASE
                   WHEN p.target_type = 'repository' THEN r.name
               END as target_name
        FROM permissions p
        LEFT JOIN users u ON p.principal_type = 'user' AND p.principal_id = u.id
        LEFT JOIN groups g ON p.principal_type = 'group' AND p.principal_id = g.id
        LEFT JOIN repositories r ON p.target_type = 'repository' AND p.target_id = r.id
        WHERE ($1::text IS NULL OR p.principal_type = $1)
          AND ($2::uuid IS NULL OR p.principal_id = $2)
          AND ($3::text IS NULL OR p.target_type = $3)
          AND ($4::uuid IS NULL OR p.target_id = $4)
        ORDER BY p.created_at DESC
        OFFSET $5
        LIMIT $6
        "#,
        query.principal_type,
        query.principal_id,
        query.target_type,
        query.target_id,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM permissions
        WHERE ($1::text IS NULL OR principal_type = $1)
          AND ($2::uuid IS NULL OR principal_id = $2)
          AND ($3::text IS NULL OR target_type = $3)
          AND ($4::uuid IS NULL OR target_id = $4)
        "#,
        query.principal_type,
        query.principal_id,
        query.target_type,
        query.target_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(PermissionListResponse {
        items: permissions
            .into_iter()
            .map(|p| PermissionResponse {
                id: p.id,
                principal_type: p.principal_type,
                principal_id: p.principal_id,
                principal_name: p.principal_name,
                target_type: p.target_type,
                target_id: p.target_id,
                target_name: p.target_name,
                actions: p.actions,
                created_at: p.created_at,
                updated_at: p.updated_at,
            })
            .collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub principal_type: String,
    pub principal_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub actions: Vec<String>,
}

/// Create a permission
pub async fn create_permission(
    State(state): State<SharedState>,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let permission = sqlx::query!(
        r#"
        INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, principal_type, principal_id, target_type, target_id, actions, created_at, updated_at
        "#,
        payload.principal_type,
        payload.principal_id,
        payload.target_type,
        payload.target_id,
        &payload.actions
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict("Permission already exists".to_string())
        } else {
            AppError::Database(msg)
        }
    })?;

    Ok(Json(PermissionResponse {
        id: permission.id,
        principal_type: permission.principal_type,
        principal_id: permission.principal_id,
        principal_name: None,
        target_type: permission.target_type,
        target_id: permission.target_id,
        target_name: None,
        actions: permission.actions,
        created_at: permission.created_at,
        updated_at: permission.updated_at,
    }))
}

/// Get a permission by ID
pub async fn get_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionResponse>> {
    let permission = sqlx::query!(
        r#"
        SELECT p.id, p.principal_type, p.principal_id, p.target_type, p.target_id,
               p.actions, p.created_at, p.updated_at,
               CASE
                   WHEN p.principal_type = 'user' THEN u.username
                   WHEN p.principal_type = 'group' THEN g.name
               END as principal_name,
               CASE
                   WHEN p.target_type = 'repository' THEN r.name
               END as target_name
        FROM permissions p
        LEFT JOIN users u ON p.principal_type = 'user' AND p.principal_id = u.id
        LEFT JOIN groups g ON p.principal_type = 'group' AND p.principal_id = g.id
        LEFT JOIN repositories r ON p.target_type = 'repository' AND p.target_id = r.id
        WHERE p.id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    Ok(Json(PermissionResponse {
        id: permission.id,
        principal_type: permission.principal_type,
        principal_id: permission.principal_id,
        principal_name: permission.principal_name,
        target_type: permission.target_type,
        target_id: permission.target_id,
        target_name: permission.target_name,
        actions: permission.actions,
        created_at: permission.created_at,
        updated_at: permission.updated_at,
    }))
}

/// Update a permission
pub async fn update_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let permission = sqlx::query!(
        r#"
        UPDATE permissions
        SET principal_type = $2, principal_id = $3, target_type = $4, target_id = $5,
            actions = $6, updated_at = NOW()
        WHERE id = $1
        RETURNING id, principal_type, principal_id, target_type, target_id, actions, created_at, updated_at
        "#,
        id,
        payload.principal_type,
        payload.principal_id,
        payload.target_type,
        payload.target_id,
        &payload.actions
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    Ok(Json(PermissionResponse {
        id: permission.id,
        principal_type: permission.principal_type,
        principal_id: permission.principal_id,
        principal_name: None,
        target_type: permission.target_type,
        target_id: permission.target_id,
        target_name: None,
        actions: permission.actions,
        created_at: permission.created_at,
        updated_at: permission.updated_at,
    }))
}

/// Delete a permission
pub async fn delete_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!("DELETE FROM permissions WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }

    Ok(())
}
