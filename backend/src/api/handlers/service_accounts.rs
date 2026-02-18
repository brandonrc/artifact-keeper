//! Service account management handlers.
//!
//! All routes require admin authentication. Service accounts are machine
//! identities that own API tokens independently of any human user.

use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::service_account_service::{ServiceAccountService, ServiceAccountSummary};
use crate::services::token_service::TokenService;

/// Create service account routes (all require admin)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_service_accounts).post(create_service_account))
        .route(
            "/:id",
            get(get_service_account)
                .patch(update_service_account)
                .delete(delete_service_account),
        )
        .route("/:id/tokens", get(list_tokens).post(create_token))
        .route("/:id/tokens/:token_id", axum::routing::delete(revoke_token))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateServiceAccountRequest {
    /// Name for the service account (will be prefixed with "svc-")
    pub name: String,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountListResponse {
    pub items: Vec<ServiceAccountSummaryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountSummaryResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub token_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ServiceAccountSummary> for ServiceAccountSummaryResponse {
    fn from(s: ServiceAccountSummary) -> Self {
        Self {
            id: s.id,
            username: s.username,
            display_name: s.display_name,
            is_active: s.is_active,
            token_count: s.token_count,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateServiceAccountRequest {
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
    pub description: Option<String>,
    pub repository_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub token: String,
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenInfoResponse {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_expired: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListResponse {
    pub items: Vec<TokenInfoResponse>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn require_admin(auth: &AuthExtension) -> Result<()> {
    if !auth.is_admin {
        return Err(AppError::Authorization("Admin access required".to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all service accounts
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    responses(
        (status = 200, description = "List of service accounts", body = ServiceAccountListResponse),
        (status = 403, description = "Not admin"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_service_accounts(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ServiceAccountListResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let accounts = svc.list(true).await?;

    Ok(Json(ServiceAccountListResponse {
        items: accounts.into_iter().map(Into::into).collect(),
    }))
}

/// Create a new service account
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, description = "Service account created", body = ServiceAccountResponse),
        (status = 403, description = "Not admin"),
        (status = 400, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateServiceAccountRequest>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc
        .create(&payload.name, payload.description.as_deref())
        .await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Get a service account by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account details", body = ServiceAccountResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc.get(id).await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Update a service account
#[utoipa::path(
    patch,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    request_body = UpdateServiceAccountRequest,
    responses(
        (status = 200, description = "Updated", body = ServiceAccountResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateServiceAccountRequest>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc
        .update(id, payload.display_name.as_deref(), payload.is_active)
        .await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Delete a service account
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    svc.delete(id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// List tokens for a service account
#[utoipa::path(
    get,
    path = "/{id}/tokens",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Token list", body = TokenListResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<TokenListResponse>> {
    require_admin(&auth)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let token_svc = TokenService::new(state.db.clone(), Arc::new(state.config.clone()));
    let tokens = token_svc.list_tokens(id).await?;

    Ok(Json(TokenListResponse {
        items: tokens
            .into_iter()
            .map(|t| TokenInfoResponse {
                id: t.id,
                name: t.name,
                token_prefix: t.token_prefix,
                scopes: t.scopes,
                expires_at: t.expires_at,
                last_used_at: t.last_used_at,
                created_at: t.created_at,
                is_expired: t.is_expired,
            })
            .collect(),
    }))
}

/// Create a token for a service account
#[utoipa::path(
    post,
    path = "/{id}/tokens",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "Token created (value shown once)", body = CreateTokenResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>> {
    require_admin(&auth)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(id, &payload.name, payload.scopes, payload.expires_in_days)
        .await?;

    // If repository restrictions specified, insert them
    if let Some(repo_ids) = &payload.repository_ids {
        for repo_id in repo_ids {
            sqlx::query!(
                "INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)",
                token_id,
                repo_id
            )
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
    }

    // Update the created_by_user_id and description
    sqlx::query!(
        "UPDATE api_tokens SET created_by_user_id = $1, description = $2 WHERE id = $3",
        auth.user_id,
        payload.description,
        token_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(CreateTokenResponse {
        id: token_id,
        token,
        name: payload.name,
    }))
}

/// Revoke a token from a service account
#[utoipa::path(
    delete,
    path = "/{id}/tokens/{token_id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID"),
        ("token_id" = Uuid, Path, description = "Token ID"),
    ),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode> {
    require_admin(&auth)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service.revoke_api_token(token_id, id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        list_service_accounts,
        create_service_account,
        get_service_account,
        update_service_account,
        delete_service_account,
        list_tokens,
        create_token,
        revoke_token,
    ),
    components(schemas(
        CreateServiceAccountRequest,
        ServiceAccountResponse,
        ServiceAccountListResponse,
        ServiceAccountSummaryResponse,
        UpdateServiceAccountRequest,
        CreateTokenRequest,
        CreateTokenResponse,
        TokenInfoResponse,
        TokenListResponse,
    )),
    tags(
        (name = "service_accounts", description = "Service account management"),
    )
)]
pub struct ServiceAccountsApiDoc;
