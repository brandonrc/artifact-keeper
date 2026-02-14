//! VS Code Extensions (VSIX Marketplace) API handlers.
//!
//! Implements a VS Code Marketplace-compatible API for extension hosting.
//!
//! Routes are mounted at `/vscode/{repo_key}/...`:
//!   GET  /vscode/{repo_key}/api/extensionquery                              - Query extensions
//!   GET  /vscode/{repo_key}/extensions/{publisher}/{name}/{version}/download - Download VSIX
//!   POST /vscode/{repo_key}/api/extensions                                  - Publish extension
//!   GET  /vscode/{repo_key}/api/extensions/{publisher}/{name}/latest         - Latest version info

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Query extensions (marketplace API)
        .route("/:repo_key/api/extensionquery", get(query_extensions))
        // Download VSIX
        .route(
            "/:repo_key/extensions/:publisher/:name/:version/download",
            get(download_vsix),
        )
        // Publish extension
        .route("/:repo_key/api/extensions", post(publish_extension))
        // Latest version info
        .route(
            "/:repo_key/api/extensions/:publisher/:name/latest",
            get(latest_version),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"vscode\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"vscode\"")
                .body(Body::from("Invalid credentials"))
                .unwrap()
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_vscode_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        r#"SELECT id, storage_path, format::text as "format!", repo_type::text as "repo_type!", upstream_url
        FROM repositories WHERE key = $1"#,
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt = repo.format.to_lowercase();
    if fmt != "vscode" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a VS Code extension repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/api/extensionquery — Query extensions
// ---------------------------------------------------------------------------

async fn query_extensions(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(a.name)) a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY LOWER(a.name), a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let extensions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let publisher = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("publisher"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let ext_name = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("extension_name"))
                .and_then(|v| v.as_str())
                .unwrap_or(&a.name);
            let version = a.version.clone().unwrap_or_default();

            serde_json::json!({
                "publisher": { "publisherName": publisher },
                "extensionName": ext_name,
                "versions": [{
                    "version": version,
                    "assetUri": format!(
                        "/vscode/{}/extensions/{}/{}/{}/download",
                        repo_key, publisher, ext_name, version
                    ),
                }],
            })
        })
        .collect();

    let result = serde_json::json!({
        "results": [{
            "extensions": extensions,
            "resultMetadata": [{
                "metadataType": "ResultCount",
                "metadataItems": [{ "name": "TotalCount", "count": extensions.len() }],
            }],
        }],
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&result).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/extensions/{publisher}/{name}/{version}/download
// ---------------------------------------------------------------------------

async fn download_vsix(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name, version)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let extension_id = format!("{}.{}", publisher, name);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        extension_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("extensions/{}/{}/{}/download", publisher, name, version);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let upstream_path =
                    format!("extensions/{}/{}/{}/download", publisher, name, version);
                let vname = extension_id.clone();
                let vversion = version.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                member_id,
                                &storage_path,
                                &vname,
                                &vversion,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let filename = format!("{}.{}-{}.vsix", publisher, name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vsix")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /vscode/{repo_key}/api/extensions — Publish extension (auth required)
// ---------------------------------------------------------------------------

async fn publish_extension(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty VSIX file").into_response());
    }

    // Extract publisher/name/version from VSIX headers or require them as query params.
    // For simplicity, extract from the Content-Disposition header or require metadata headers.
    let publisher = headers
        .get("x-publisher")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing x-publisher header").into_response())?;

    let ext_name = headers
        .get("x-extension-name")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing x-extension-name header").into_response()
        })?;

    let ext_version = headers
        .get("x-extension-version")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing x-extension-version header",
            )
                .into_response()
        })?;

    let extension_id = format!("{}.{}", publisher, ext_name);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let filename = format!("{}-{}.vsix", extension_id, ext_version);
    let artifact_path = format!("{}/{}/{}", publisher, ext_name, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Extension version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("vscode/{}/{}/{}", publisher, ext_name, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let vscode_metadata = serde_json::json!({
        "publisher": publisher,
        "extension_name": ext_name,
        "version": ext_version,
        "filename": filename,
    });

    let size_bytes = body.len() as i64;

    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        extension_id,
        ext_version,
        size_bytes,
        computed_sha256,
        "application/vsix",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'vscode', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        vscode_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "VS Code extension publish: {} {} to repo {}",
        extension_id, ext_version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "publisher": publisher,
                "name": ext_name,
                "version": ext_version,
                "message": "Successfully published extension",
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/api/extensions/{publisher}/{name}/latest
// ---------------------------------------------------------------------------

async fn latest_version(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let extension_id = format!("{}.{}", publisher, name);

    let artifact = sqlx::query!(
        r#"
        SELECT a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        extension_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension not found").into_response())?;

    let version = artifact.version.clone().unwrap_or_default();

    let json = serde_json::json!({
        "publisher": publisher,
        "name": name,
        "version": version,
        "sha256": artifact.checksum_sha256,
        "size": artifact.size_bytes,
        "downloadUrl": format!(
            "/vscode/{}/extensions/{}/{}/{}/download",
            repo_key, publisher, name, version
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_credentials — Bearer token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-pat-token"),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(
            creds,
            Some(("token".to_string(), "my-pat-token".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-pat-token"),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(
            creds,
            Some(("token".to_string(), "my-pat-token".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // extract_credentials — Basic auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_basic() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(
            creds,
            Some(("admin".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic_lowercase() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(creds, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_colon_in_password() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p@ss:word:123");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(
            creds,
            Some(("user".to_string(), "p@ss:word:123".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // extract_credentials — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_credentials_invalid_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Token abc123"),
        );
        assert!(extract_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic ===invalid==="),
        );
        assert!(extract_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // Extension ID format (publisher.name pattern)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extension_id_format() {
        let publisher = "ms-python";
        let name = "python";
        let extension_id = format!("{}.{}", publisher, name);
        assert_eq!(extension_id, "ms-python.python");
    }

    #[test]
    fn test_extension_id_format_complex() {
        let publisher = "esbenp";
        let name = "prettier-vscode";
        let extension_id = format!("{}.{}", publisher, name);
        assert_eq!(extension_id, "esbenp.prettier-vscode");
    }

    // -----------------------------------------------------------------------
    // Filename format (publisher.name-version.vsix)
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_format() {
        let publisher = "ms-python";
        let name = "python";
        let version = "2024.1.0";
        let extension_id = format!("{}.{}", publisher, name);
        let filename = format!("{}-{}.vsix", extension_id, version);
        assert_eq!(filename, "ms-python.python-2024.1.0.vsix");
    }

    // -----------------------------------------------------------------------
    // Artifact path format
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_path_format() {
        let publisher = "ms-python";
        let ext_name = "python";
        let ext_version = "2024.1.0";
        let extension_id = format!("{}.{}", publisher, ext_name);
        let filename = format!("{}-{}.vsix", extension_id, ext_version);
        let artifact_path = format!("{}/{}/{}", publisher, ext_name, filename);
        assert_eq!(
            artifact_path,
            "ms-python/python/ms-python.python-2024.1.0.vsix"
        );
    }

    // -----------------------------------------------------------------------
    // Storage key format
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_key_format() {
        let publisher = "esbenp";
        let ext_name = "prettier-vscode";
        let ext_version = "10.1.0";
        let extension_id = format!("{}.{}", publisher, ext_name);
        let filename = format!("{}-{}.vsix", extension_id, ext_version);
        let storage_key = format!("vscode/{}/{}/{}", publisher, ext_name, filename);
        assert_eq!(
            storage_key,
            "vscode/esbenp/prettier-vscode/esbenp.prettier-vscode-10.1.0.vsix"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (same pattern used in publish_extension)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let data = b"fake VSIX content";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        assert_eq!(hash.len(), 64);

        // Same data produces same hash
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let hash2 = format!("{:x}", hasher2.finalize());
        assert_eq!(hash, hash2);
    }

    // -----------------------------------------------------------------------
    // Metadata JSON format
    // -----------------------------------------------------------------------

    #[test]
    fn test_vscode_metadata_json() {
        let publisher = "ms-python";
        let ext_name = "python";
        let ext_version = "2024.1.0";
        let extension_id = format!("{}.{}", publisher, ext_name);
        let filename = format!("{}-{}.vsix", extension_id, ext_version);

        let metadata = serde_json::json!({
            "publisher": publisher,
            "extension_name": ext_name,
            "version": ext_version,
            "filename": filename,
        });

        assert_eq!(metadata["publisher"], "ms-python");
        assert_eq!(metadata["extension_name"], "python");
        assert_eq!(metadata["version"], "2024.1.0");
        assert_eq!(metadata["filename"], "ms-python.python-2024.1.0.vsix");
    }

    // -----------------------------------------------------------------------
    // Download URL format
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_url_format() {
        let repo_key = "vscode-local";
        let publisher = "ms-vscode";
        let ext_name = "cpptools";
        let version = "1.18.0";
        let url = format!(
            "/vscode/{}/extensions/{}/{}/{}/download",
            repo_key, publisher, ext_name, version
        );
        assert_eq!(
            url,
            "/vscode/vscode-local/extensions/ms-vscode/cpptools/1.18.0/download"
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/vscode-local".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.storage_path, "/data/vscode-local");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/vscode-remote".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some(
                "https://marketplace.visualstudio.com/_apis/public/gallery".to_string(),
            ),
        };
        assert_eq!(repo.repo_type, "remote");
        assert!(repo.upstream_url.is_some());
    }

    // -----------------------------------------------------------------------
    // Content-Disposition header format for downloads
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_content_disposition() {
        let publisher = "redhat";
        let name = "vscode-yaml";
        let version = "1.14.0";
        let filename = format!("{}.{}-{}.vsix", publisher, name, version);
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(
            header,
            "attachment; filename=\"redhat.vscode-yaml-1.14.0.vsix\""
        );
    }
}
