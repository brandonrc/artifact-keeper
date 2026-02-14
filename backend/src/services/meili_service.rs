//! Meilisearch integration service for full-text search indexing.

use chrono::{DateTime, Utc};
use meilisearch_sdk::client::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

const ARTIFACTS_INDEX: &str = "artifacts";
const REPOSITORIES_INDEX: &str = "repositories";
const BATCH_SIZE: usize = 1000;

/// Document representing an artifact in the search index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDocument {
    pub id: String,
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub format: String,
    pub repository_id: String,
    pub repository_key: String,
    pub repository_name: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: i64,
}

/// Document representing a repository in the search index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryDocument {
    pub id: String,
    pub name: String,
    pub key: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: bool,
    pub created_at: i64,
}

/// Search results wrapper.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResults<T> {
    pub hits: Vec<T>,
    pub total_hits: usize,
    pub processing_time_ms: usize,
    pub query: String,
}

/// Meilisearch service for indexing and searching artifacts and repositories.
pub struct MeiliService {
    client: Client,
}

impl MeiliService {
    /// Create a new MeiliService connected to the given Meilisearch instance.
    pub fn new(url: &str, api_key: &str) -> Self {
        let client = Client::new(url, Some(api_key)).unwrap();
        Self { client }
    }

    /// Configure indexes with appropriate searchable, filterable, and sortable attributes.
    pub async fn configure_indexes(&self) -> Result<()> {
        // Configure artifacts index
        let artifacts_index = self.client.index(ARTIFACTS_INDEX);

        artifacts_index
            .set_searchable_attributes([
                "name",
                "path",
                "version",
                "repository_key",
                "repository_name",
                "content_type",
            ])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts searchable attributes: {}",
                    e
                ))
            })?;

        artifacts_index
            .set_filterable_attributes([
                "format",
                "repository_key",
                "repository_id",
                "content_type",
                "size_bytes",
                "created_at",
            ])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts filterable attributes: {}",
                    e
                ))
            })?;

        artifacts_index
            .set_sortable_attributes(["created_at", "size_bytes", "name", "download_count"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts sortable attributes: {}",
                    e
                ))
            })?;

        // Configure repositories index
        let repos_index = self.client.index(REPOSITORIES_INDEX);

        repos_index
            .set_searchable_attributes(["name", "key", "description", "format"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set repositories searchable attributes: {}",
                    e
                ))
            })?;

        repos_index
            .set_filterable_attributes(["format", "repo_type", "is_public"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set repositories filterable attributes: {}",
                    e
                ))
            })?;

        tracing::info!("Meilisearch indexes configured successfully");
        Ok(())
    }

    /// Index a single artifact document.
    pub async fn index_artifact(&self, doc: &ArtifactDocument) -> Result<()> {
        self.client
            .index(ARTIFACTS_INDEX)
            .add_documents(&[doc], Some("id"))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index artifact: {}", e)))?;
        Ok(())
    }

    /// Index a single repository document.
    pub async fn index_repository(&self, doc: &RepositoryDocument) -> Result<()> {
        self.client
            .index(REPOSITORIES_INDEX)
            .add_documents(&[doc], Some("id"))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index repository: {}", e)))?;
        Ok(())
    }

    /// Remove an artifact from the search index.
    pub async fn remove_artifact(&self, artifact_id: &str) -> Result<()> {
        self.client
            .index(ARTIFACTS_INDEX)
            .delete_document(artifact_id)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove artifact from index: {}", e))
            })?;
        Ok(())
    }

    /// Remove a repository from the search index.
    pub async fn remove_repository(&self, repository_id: &str) -> Result<()> {
        self.client
            .index(REPOSITORIES_INDEX)
            .delete_document(repository_id)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove repository from index: {}", e))
            })?;
        Ok(())
    }

    /// Search artifacts by query string with optional filters.
    pub async fn search_artifacts(
        &self,
        query: &str,
        filter: Option<&str>,
        sort: Option<&[&str]>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<ArtifactDocument>> {
        let index = self.client.index(ARTIFACTS_INDEX);
        let mut search = index.search();
        search.with_query(query);
        search.with_limit(limit);
        search.with_offset(offset);

        if let Some(f) = filter {
            search.with_filter(f);
        }
        if let Some(s) = sort {
            search.with_sort(s);
        }

        let results = search
            .execute::<ArtifactDocument>()
            .await
            .map_err(|e| AppError::Internal(format!("Artifact search failed: {}", e)))?;

        let hits: Vec<ArtifactDocument> = results.hits.into_iter().map(|hit| hit.result).collect();

        Ok(SearchResults {
            total_hits: results.estimated_total_hits.unwrap_or(hits.len()),
            processing_time_ms: results.processing_time_ms,
            query: query.to_string(),
            hits,
        })
    }

    /// Search repositories by query string with optional filters.
    pub async fn search_repositories(
        &self,
        query: &str,
        filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<RepositoryDocument>> {
        let index = self.client.index(REPOSITORIES_INDEX);
        let mut search = index.search();
        search.with_query(query);
        search.with_limit(limit);
        search.with_offset(offset);

        if let Some(f) = filter {
            search.with_filter(f);
        }

        let results = search
            .execute::<RepositoryDocument>()
            .await
            .map_err(|e| AppError::Internal(format!("Repository search failed: {}", e)))?;

        let hits: Vec<RepositoryDocument> =
            results.hits.into_iter().map(|hit| hit.result).collect();

        Ok(SearchResults {
            total_hits: results.estimated_total_hits.unwrap_or(hits.len()),
            processing_time_ms: results.processing_time_ms,
            query: query.to_string(),
            hits,
        })
    }

    /// Check if the artifacts index is empty (used to trigger initial reindex).
    pub async fn is_index_empty(&self) -> Result<bool> {
        let stats = self
            .client
            .index(ARTIFACTS_INDEX)
            .get_stats()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get index stats: {}", e)))?;

        Ok(stats.number_of_documents == 0)
    }

    /// Reindex all artifacts from the database into Meilisearch.
    ///
    /// Joins artifacts with repositories and download statistics to build
    /// complete search documents. Processes in batches of 1000.
    pub async fn full_reindex_artifacts(&self, db: &PgPool) -> Result<()> {
        tracing::info!("Starting full artifact reindex");

        let rows = sqlx::query_as::<_, ArtifactRow>(
            r#"
            SELECT
                a.id,
                a.name,
                a.path,
                a.version,
                a.content_type,
                a.size_bytes,
                a.created_at,
                r.id AS repository_id,
                r.key AS repository_key,
                r.name AS repository_name,
                r.format::text AS format,
                COALESCE(ds.download_count, 0) AS download_count
            FROM artifacts a
            INNER JOIN repositories r ON a.repository_id = r.id
            LEFT JOIN (
                SELECT artifact_id, COUNT(*) AS download_count
                FROM download_statistics
                GROUP BY artifact_id
            ) ds ON a.id = ds.artifact_id
            WHERE a.is_deleted = false
            ORDER BY a.id
            "#,
        )
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(format!("Failed to fetch artifacts for reindex: {}", e)))?;

        let total = rows.len();
        tracing::info!("Reindexing {} artifacts", total);

        let documents: Vec<ArtifactDocument> = rows
            .into_iter()
            .map(|row| ArtifactDocument {
                id: row.id.to_string(),
                name: row.name,
                path: row.path,
                version: row.version,
                format: row.format,
                repository_id: row.repository_id.to_string(),
                repository_key: row.repository_key,
                repository_name: row.repository_name,
                content_type: row.content_type,
                size_bytes: row.size_bytes,
                download_count: row.download_count,
                created_at: row.created_at.timestamp(),
            })
            .collect();

        let index = self.client.index(ARTIFACTS_INDEX);

        for chunk in documents.chunks(BATCH_SIZE) {
            index.add_documents(chunk, Some("id")).await.map_err(|e| {
                AppError::Internal(format!("Failed to batch index artifacts: {}", e))
            })?;
        }

        tracing::info!("Artifact reindex complete: {} documents indexed", total);
        Ok(())
    }

    /// Reindex all repositories from the database into Meilisearch.
    ///
    /// Processes in batches of 1000.
    pub async fn full_reindex_repositories(&self, db: &PgPool) -> Result<()> {
        tracing::info!("Starting full repository reindex");

        let rows = sqlx::query_as::<_, RepositoryRow>(
            r#"
            SELECT
                id,
                name,
                key,
                description,
                format::text AS format,
                repo_type::text AS repo_type,
                is_public,
                created_at
            FROM repositories
            ORDER BY id
            "#,
        )
        .fetch_all(db)
        .await
        .map_err(|e| {
            AppError::Database(format!("Failed to fetch repositories for reindex: {}", e))
        })?;

        let total = rows.len();
        tracing::info!("Reindexing {} repositories", total);

        let documents: Vec<RepositoryDocument> = rows
            .into_iter()
            .map(|row| RepositoryDocument {
                id: row.id.to_string(),
                name: row.name,
                key: row.key,
                description: row.description,
                format: row.format,
                repo_type: row.repo_type,
                is_public: row.is_public,
                created_at: row.created_at.timestamp(),
            })
            .collect();

        let index = self.client.index(REPOSITORIES_INDEX);

        for chunk in documents.chunks(BATCH_SIZE) {
            index.add_documents(chunk, Some("id")).await.map_err(|e| {
                AppError::Internal(format!("Failed to batch index repositories: {}", e))
            })?;
        }

        tracing::info!("Repository reindex complete: {} documents indexed", total);
        Ok(())
    }

    /// Run a full reindex of both artifacts and repositories.
    pub async fn full_reindex(&self, db: &PgPool) -> Result<()> {
        self.full_reindex_artifacts(db).await?;
        self.full_reindex_repositories(db).await?;
        tracing::info!("Full reindex complete");
        Ok(())
    }
}

/// Internal row type for artifact reindex queries.
#[derive(Debug, sqlx::FromRow)]
struct ArtifactRow {
    id: Uuid,
    name: String,
    path: String,
    version: Option<String>,
    content_type: String,
    size_bytes: i64,
    created_at: DateTime<Utc>,
    repository_id: Uuid,
    repository_key: String,
    repository_name: String,
    format: String,
    download_count: i64,
}

/// Internal row type for repository reindex queries.
#[derive(Debug, sqlx::FromRow)]
struct RepositoryRow {
    id: Uuid,
    name: String,
    key: String,
    description: Option<String>,
    format: String,
    repo_type: String,
    is_public: bool,
    created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(ARTIFACTS_INDEX, "artifacts");
        assert_eq!(REPOSITORIES_INDEX, "repositories");
        assert_eq!(BATCH_SIZE, 1000);
    }

    // -----------------------------------------------------------------------
    // ArtifactDocument serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_document_serialization() {
        let doc = ArtifactDocument {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            name: "my-artifact".to_string(),
            path: "com/example/my-artifact/1.0.0/my-artifact-1.0.0.jar".to_string(),
            version: Some("1.0.0".to_string()),
            format: "maven".to_string(),
            repository_id: "repo-id-123".to_string(),
            repository_key: "maven-central".to_string(),
            repository_name: "Maven Central".to_string(),
            content_type: "application/java-archive".to_string(),
            size_bytes: 1024 * 1024,
            download_count: 42,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"name\":\"my-artifact\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"format\":\"maven\""));
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1048576"));
    }

    #[test]
    fn test_artifact_document_deserialization() {
        let json_val = json!({
            "id": "abc-123",
            "name": "pkg",
            "path": "pkg/1.0",
            "version": null,
            "format": "npm",
            "repository_id": "repo-1",
            "repository_key": "npm-local",
            "repository_name": "NPM Local",
            "content_type": "application/gzip",
            "size_bytes": 512,
            "download_count": 0,
            "created_at": 1700000000
        });

        let doc: ArtifactDocument = serde_json::from_value(json_val).unwrap();
        assert_eq!(doc.id, "abc-123");
        assert_eq!(doc.name, "pkg");
        assert!(doc.version.is_none());
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.size_bytes, 512);
        assert_eq!(doc.download_count, 0);
    }

    #[test]
    fn test_artifact_document_roundtrip() {
        let doc = ArtifactDocument {
            id: "test-id".to_string(),
            name: "test-name".to_string(),
            path: "test/path".to_string(),
            version: Some("2.0.0".to_string()),
            format: "docker".to_string(),
            repository_id: "repo".to_string(),
            repository_key: "docker-local".to_string(),
            repository_name: "Docker Local".to_string(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size_bytes: 0,
            download_count: 100,
            created_at: 1234567890,
        };

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: ArtifactDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(doc.id, deserialized.id);
        assert_eq!(doc.name, deserialized.name);
        assert_eq!(doc.path, deserialized.path);
        assert_eq!(doc.version, deserialized.version);
        assert_eq!(doc.format, deserialized.format);
        assert_eq!(doc.repository_id, deserialized.repository_id);
        assert_eq!(doc.repository_key, deserialized.repository_key);
        assert_eq!(doc.repository_name, deserialized.repository_name);
        assert_eq!(doc.content_type, deserialized.content_type);
        assert_eq!(doc.size_bytes, deserialized.size_bytes);
        assert_eq!(doc.download_count, deserialized.download_count);
        assert_eq!(doc.created_at, deserialized.created_at);
    }

    #[test]
    fn test_artifact_document_clone() {
        let doc = ArtifactDocument {
            id: "id".to_string(),
            name: "name".to_string(),
            path: "path".to_string(),
            version: None,
            format: "generic".to_string(),
            repository_id: "repo".to_string(),
            repository_key: "key".to_string(),
            repository_name: "name".to_string(),
            content_type: "application/octet-stream".to_string(),
            size_bytes: 100,
            download_count: 0,
            created_at: 0,
        };
        let cloned = doc.clone();
        assert_eq!(doc.id, cloned.id);
        assert_eq!(doc.name, cloned.name);
    }

    // -----------------------------------------------------------------------
    // RepositoryDocument serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_document_serialization() {
        let doc = RepositoryDocument {
            id: "repo-id".to_string(),
            name: "My Repository".to_string(),
            key: "my-repo".to_string(),
            description: Some("A test repository".to_string()),
            format: "maven".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"name\":\"My Repository\""));
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"is_public\":true"));
        assert!(json.contains("\"format\":\"maven\""));
        assert!(json.contains("\"repo_type\":\"local\""));
    }

    #[test]
    fn test_repository_document_deserialization() {
        let json_val = json!({
            "id": "repo-1",
            "name": "NPM Repo",
            "key": "npm-local",
            "description": null,
            "format": "npm",
            "repo_type": "remote",
            "is_public": false,
            "created_at": 1700000000
        });

        let doc: RepositoryDocument = serde_json::from_value(json_val).unwrap();
        assert_eq!(doc.name, "NPM Repo");
        assert_eq!(doc.key, "npm-local");
        assert!(doc.description.is_none());
        assert!(!doc.is_public);
    }

    #[test]
    fn test_repository_document_roundtrip() {
        let doc = RepositoryDocument {
            id: "test".to_string(),
            name: "Test".to_string(),
            key: "test-key".to_string(),
            description: Some("desc".to_string()),
            format: "docker".to_string(),
            repo_type: "virtual".to_string(),
            is_public: false,
            created_at: 999,
        };
        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: RepositoryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc.id, deserialized.id);
        assert_eq!(doc.name, deserialized.name);
        assert_eq!(doc.key, deserialized.key);
        assert_eq!(doc.description, deserialized.description);
        assert_eq!(doc.format, deserialized.format);
        assert_eq!(doc.repo_type, deserialized.repo_type);
        assert_eq!(doc.is_public, deserialized.is_public);
        assert_eq!(doc.created_at, deserialized.created_at);
    }

    #[test]
    fn test_repository_document_clone() {
        let doc = RepositoryDocument {
            id: "id".to_string(),
            name: "name".to_string(),
            key: "key".to_string(),
            description: None,
            format: "pypi".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: 0,
        };
        let cloned = doc.clone();
        assert_eq!(doc.id, cloned.id);
        assert_eq!(doc.is_public, cloned.is_public);
    }

    // -----------------------------------------------------------------------
    // SearchResults serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_results_serialization_empty() {
        let results: SearchResults<ArtifactDocument> = SearchResults {
            hits: vec![],
            total_hits: 0,
            processing_time_ms: 5,
            query: "test".to_string(),
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"hits\":[]"));
        assert!(json.contains("\"total_hits\":0"));
        assert!(json.contains("\"processing_time_ms\":5"));
        assert!(json.contains("\"query\":\"test\""));
    }

    #[test]
    fn test_search_results_serialization_with_hits() {
        let doc = ArtifactDocument {
            id: "1".to_string(),
            name: "artifact1".to_string(),
            path: "a/b".to_string(),
            version: Some("1.0".to_string()),
            format: "npm".to_string(),
            repository_id: "r".to_string(),
            repository_key: "k".to_string(),
            repository_name: "n".to_string(),
            content_type: "application/gzip".to_string(),
            size_bytes: 100,
            download_count: 10,
            created_at: 0,
        };

        let results = SearchResults {
            hits: vec![doc],
            total_hits: 1,
            processing_time_ms: 12,
            query: "artifact".to_string(),
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"total_hits\":1"));
        assert!(json.contains("\"name\":\"artifact1\""));
    }

    #[test]
    fn test_search_results_clone() {
        let results: SearchResults<RepositoryDocument> = SearchResults {
            hits: vec![],
            total_hits: 0,
            processing_time_ms: 0,
            query: "q".to_string(),
        };
        let cloned = results.clone();
        assert_eq!(results.total_hits, cloned.total_hits);
        assert_eq!(results.query, cloned.query);
    }

    // -----------------------------------------------------------------------
    // ArtifactRow construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_row_to_document_conversion() {
        // Mirrors the mapping in full_reindex_artifacts
        let now = Utc::now();
        let id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();

        let row = ArtifactRow {
            id,
            name: "my-lib".to_string(),
            path: "org/my-lib/1.0/my-lib-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            content_type: "application/java-archive".to_string(),
            size_bytes: 2048,
            created_at: now,
            repository_id: repo_id,
            repository_key: "maven-local".to_string(),
            repository_name: "Maven Local".to_string(),
            format: "maven".to_string(),
            download_count: 7,
        };

        let doc = ArtifactDocument {
            id: row.id.to_string(),
            name: row.name.clone(),
            path: row.path.clone(),
            version: row.version.clone(),
            format: row.format.clone(),
            repository_id: row.repository_id.to_string(),
            repository_key: row.repository_key.clone(),
            repository_name: row.repository_name.clone(),
            content_type: row.content_type.clone(),
            size_bytes: row.size_bytes,
            download_count: row.download_count,
            created_at: row.created_at.timestamp(),
        };

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.name, "my-lib");
        assert_eq!(doc.version, Some("1.0".to_string()));
        assert_eq!(doc.repository_key, "maven-local");
        assert_eq!(doc.download_count, 7);
        assert_eq!(doc.created_at, now.timestamp());
    }

    // -----------------------------------------------------------------------
    // RepositoryRow to document conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_row_to_document_conversion() {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let row = RepositoryRow {
            id,
            name: "Docker Local".to_string(),
            key: "docker-local".to_string(),
            description: Some("Local docker repo".to_string()),
            format: "docker".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: now,
        };

        let doc = RepositoryDocument {
            id: row.id.to_string(),
            name: row.name.clone(),
            key: row.key.clone(),
            description: row.description.clone(),
            format: row.format.clone(),
            repo_type: row.repo_type.clone(),
            is_public: row.is_public,
            created_at: row.created_at.timestamp(),
        };

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.name, "Docker Local");
        assert_eq!(doc.key, "docker-local");
        assert_eq!(doc.description, Some("Local docker repo".to_string()));
        assert!(doc.is_public);
    }
}
