//! Group management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create group routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route(
            "/:id",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/:id/members", post(add_members).delete(remove_members))
}

#[derive(Debug, Deserialize)]
pub struct ListGroupsQuery {
    pub search: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub member_count: i64,
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
pub struct GroupListResponse {
    pub items: Vec<GroupResponse>,
    pub pagination: Pagination,
}

/// List groups
pub async fn list_groups(
    State(state): State<SharedState>,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<GroupListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));

    let groups = sqlx::query!(
        r#"
        SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
               COUNT(ugm.user_id) as "member_count!"
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE ($1::text IS NULL OR g.name ILIKE $1 OR g.description ILIKE $1)
        GROUP BY g.id
        ORDER BY g.name
        OFFSET $2
        LIMIT $3
        "#,
        search_pattern,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM groups
        WHERE ($1::text IS NULL OR name ILIKE $1 OR description ILIKE $1)
        "#,
        search_pattern
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(GroupListResponse {
        items: groups
            .into_iter()
            .map(|g| GroupResponse {
                id: g.id,
                name: g.name,
                description: g.description,
                member_count: g.member_count,
                created_at: g.created_at,
                updated_at: g.updated_at,
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
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

/// Create a group
pub async fn create_group(
    State(state): State<SharedState>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let group = sqlx::query!(
        r#"
        INSERT INTO groups (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description, created_at, updated_at
        "#,
        payload.name,
        payload.description
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict("Group name already exists".to_string())
        } else {
            AppError::Database(msg)
        }
    })?;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count: 0,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Get a group by ID
pub async fn get_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupResponse>> {
    let group = sqlx::query!(
        r#"
        SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
               COUNT(ugm.user_id) as "member_count!"
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE g.id = $1
        GROUP BY g.id
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count: group.member_count,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Update a group
pub async fn update_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let group = sqlx::query!(
        r#"
        UPDATE groups
        SET name = $2, description = $3, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, description, created_at, updated_at
        "#,
        id,
        payload.name,
        payload.description
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let member_count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM user_group_members WHERE group_id = $1"#,
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Delete a group
pub async fn delete_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!("DELETE FROM groups WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Group not found".to_string()));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MembersRequest {
    pub user_ids: Vec<Uuid>,
}

/// Add members to a group
pub async fn add_members(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
    for user_id in payload.user_ids {
        sqlx::query!(
            r#"
            INSERT INTO user_group_members (user_id, group_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
            user_id,
            id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    Ok(())
}

/// Remove members from a group
pub async fn remove_members(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
    for user_id in payload.user_ids {
        sqlx::query!(
            "DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2",
            user_id,
            id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    Ok(())
}
