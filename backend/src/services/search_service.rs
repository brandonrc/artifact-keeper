//! Search service for artifact discovery.
//!
//! Provides full-text search across artifacts with faceted filtering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Search result item
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub format: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
    pub download_count: i64,
    pub score: f32,
}

/// Search query
#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    /// Free-text query
    pub q: Option<String>,
    /// Filter by format
    pub format: Option<String>,
    /// Filter by name pattern
    pub name: Option<String>,
    /// Offset for pagination
    pub offset: Option<i64>,
    /// Limit for pagination
    pub limit: Option<i64>,
}

/// Search response with pagination and facets
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub items: Vec<SearchResult>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
    pub facets: SearchFacets,
}

/// Faceted search counts
#[derive(Debug, Serialize, Default)]
pub struct SearchFacets {
    pub formats: Vec<FacetCount>,
    pub repositories: Vec<FacetCount>,
    pub content_types: Vec<FacetCount>,
}

/// Count for a facet value
#[derive(Debug, Serialize)]
pub struct FacetCount {
    pub value: String,
    pub count: i64,
}

/// Search service
pub struct SearchService {
    db: PgPool,
}

impl SearchService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Execute a search query
    pub async fn search(&self, query: SearchQuery) -> Result<SearchResponse> {
        let offset = query.offset.unwrap_or(0).max(0);
        let limit = query.limit.unwrap_or(20).clamp(1, 100);

        let items = self.execute_search(&query, offset, limit).await?;
        let total = self.count_results(&query).await?;
        let facets = self.get_facets().await?;

        Ok(SearchResponse {
            items,
            total,
            offset,
            limit,
            facets,
        })
    }

    async fn execute_search(
        &self,
        query: &SearchQuery,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<SearchResult>> {
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        let name_filter = query.name.as_ref().map(|n| n.replace('*', "%"));

        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) as "download_count!",
                1.0::real as score
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
            ORDER BY a.created_at DESC
            OFFSET $4
            LIMIT $5
            "#,
            q_filter,
            query.format,
            name_filter,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score.unwrap_or(1.0),
            })
            .collect())
    }

    async fn count_results(&self, query: &SearchQuery) -> Result<i64> {
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        let name_filter = query.name.as_ref().map(|n| n.replace('*', "%"));

        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
            "#,
            q_filter,
            query.format,
            name_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(count)
    }

    async fn get_facets(&self) -> Result<SearchFacets> {
        // Format facets
        let format_facets = sqlx::query!(
            r#"
            SELECT r.format::text as "value!", COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            GROUP BY r.format
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Repository facets
        let repo_facets = sqlx::query!(
            r#"
            SELECT r.key as "value!", COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            GROUP BY r.key
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Content type facets
        let ct_facets = sqlx::query!(
            r#"
            SELECT a.content_type as "value!", COUNT(*) as "count!"
            FROM artifacts a
            WHERE a.is_deleted = false
            GROUP BY a.content_type
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(SearchFacets {
            formats: format_facets
                .into_iter()
                .map(|r| FacetCount {
                    value: r.value,
                    count: r.count,
                })
                .collect(),
            repositories: repo_facets
                .into_iter()
                .map(|r| FacetCount {
                    value: r.value,
                    count: r.count,
                })
                .collect(),
            content_types: ct_facets
                .into_iter()
                .map(|r| FacetCount {
                    value: r.value,
                    count: r.count,
                })
                .collect(),
        })
    }

    /// Suggest completions for search terms
    pub async fn suggest(&self, prefix: &str, limit: i64) -> Result<Vec<String>> {
        let pattern = format!("{}%", prefix);

        let suggestions = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT name
            FROM artifacts
            WHERE name ILIKE $1 AND is_deleted = false
            ORDER BY name
            LIMIT $2
            "#,
            pattern,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(suggestions)
    }

    /// Get trending artifacts (most downloaded recently)
    pub async fn trending(&self, days: i32, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COUNT(ds.id) as "download_count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN download_statistics ds ON ds.artifact_id = a.id
                AND ds.downloaded_at >= NOW() - make_interval(days => $1)
            WHERE a.is_deleted = false
            GROUP BY a.id, r.id
            ORDER BY 11 DESC
            LIMIT $2
            "#,
            days,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: 1.0,
            })
            .collect())
    }

    /// Get recently added artifacts
    pub async fn recent(&self, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) as "download_count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            ORDER BY a.created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: 1.0,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SearchQuery default and deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_default() {
        let query = SearchQuery::default();
        assert!(query.q.is_none());
        assert!(query.format.is_none());
        assert!(query.name.is_none());
        assert!(query.offset.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_search_query_deserialization() {
        let json = r#"{"q": "my-artifact", "format": "maven", "offset": 10, "limit": 50}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.q.as_deref(), Some("my-artifact"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.offset, Some(10));
        assert_eq!(query.limit, Some(50));
        assert!(query.name.is_none());
    }

    #[test]
    fn test_search_query_deserialization_partial() {
        let json = r#"{"q": "test"}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.q.as_deref(), Some("test"));
        assert!(query.format.is_none());
        assert!(query.offset.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_search_query_deserialization_empty() {
        let json = r#"{}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(query.q.is_none());
    }

    #[test]
    fn test_search_query_with_name_filter() {
        let json = r#"{"name": "my-lib*"}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.name.as_deref(), Some("my-lib*"));
    }

    // -----------------------------------------------------------------------
    // SearchQuery pagination value normalization (tested via logic extraction)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_offset_normalization() {
        // The search method normalizes: offset = query.offset.unwrap_or(0).max(0)
        let offset_none: Option<i64> = None;
        assert_eq!(offset_none.unwrap_or(0).max(0), 0);

        let offset_negative: Option<i64> = Some(-5);
        assert_eq!(offset_negative.unwrap_or(0).max(0), 0);

        let offset_positive: Option<i64> = Some(20);
        assert_eq!(offset_positive.unwrap_or(0).max(0), 20);
    }

    #[test]
    fn test_pagination_limit_normalization() {
        // The search method normalizes: limit = query.limit.unwrap_or(20).clamp(1, 100)
        let limit_none: Option<i64> = None;
        assert_eq!(limit_none.unwrap_or(20).clamp(1, 100), 20);

        let limit_zero: Option<i64> = Some(0);
        assert_eq!(limit_zero.unwrap_or(20).clamp(1, 100), 1);

        let limit_over: Option<i64> = Some(500);
        assert_eq!(limit_over.unwrap_or(20).clamp(1, 100), 100);

        let limit_normal: Option<i64> = Some(50);
        assert_eq!(limit_normal.unwrap_or(20).clamp(1, 100), 50);

        let limit_negative: Option<i64> = Some(-10);
        assert_eq!(limit_negative.unwrap_or(20).clamp(1, 100), 1);
    }

    // -----------------------------------------------------------------------
    // Query filter building logic (replicated from execute_search/count_results)
    // -----------------------------------------------------------------------

    #[test]
    fn test_q_filter_construction_single_word() {
        let q = Some("artifact".to_string());
        let q_filter = q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });
        assert_eq!(q_filter.as_deref(), Some("artifact:*"));
    }

    #[test]
    fn test_q_filter_construction_multiple_words() {
        let q = Some("my awesome artifact".to_string());
        let q_filter = q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });
        assert_eq!(q_filter.as_deref(), Some("my:* & awesome:* & artifact:*"));
    }

    #[test]
    fn test_q_filter_construction_none() {
        let q: Option<String> = None;
        let q_filter = q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });
        assert!(q_filter.is_none());
    }

    #[test]
    fn test_name_filter_wildcard_replacement() {
        let name = Some("my-lib*".to_string());
        let name_filter = name.as_ref().map(|n| n.replace('*', "%"));
        assert_eq!(name_filter.as_deref(), Some("my-lib%"));
    }

    #[test]
    fn test_name_filter_multiple_wildcards() {
        let name = Some("*my*lib*".to_string());
        let name_filter = name.as_ref().map(|n| n.replace('*', "%"));
        assert_eq!(name_filter.as_deref(), Some("%my%lib%"));
    }

    #[test]
    fn test_name_filter_none() {
        let name: Option<String> = None;
        let name_filter = name.as_ref().map(|n| n.replace('*', "%"));
        assert!(name_filter.is_none());
    }

    // -----------------------------------------------------------------------
    // SearchResult construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_result_serialization() {
        let result = SearchResult {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "maven-central".to_string(),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib".to_string(),
            version: Some("1.0".to_string()),
            format: "maven".to_string(),
            size_bytes: 1024,
            content_type: "application/java-archive".to_string(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            download_count: 42,
            score: 1.0,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "lib");
        assert_eq!(json["version"], "1.0");
        assert_eq!(json["format"], "maven");
        assert_eq!(json["size_bytes"], 1024);
        assert_eq!(json["download_count"], 42);
        assert_eq!(json["score"], 1.0);
    }

    #[test]
    fn test_search_result_version_none() {
        let result = SearchResult {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "generic".to_string(),
            path: "files/readme.txt".to_string(),
            name: "readme.txt".to_string(),
            version: None,
            format: "generic".to_string(),
            size_bytes: 256,
            content_type: "text/plain".to_string(),
            created_at: Utc::now(),
            download_count: 0,
            score: 0.5,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["version"].is_null());
    }

    // -----------------------------------------------------------------------
    // SearchFacets
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_facets_default() {
        let facets = SearchFacets::default();
        assert!(facets.formats.is_empty());
        assert!(facets.repositories.is_empty());
        assert!(facets.content_types.is_empty());
    }

    #[test]
    fn test_facet_count_serialization() {
        let facet = FacetCount {
            value: "maven".to_string(),
            count: 100,
        };
        let json = serde_json::to_value(&facet).unwrap();
        assert_eq!(json["value"], "maven");
        assert_eq!(json["count"], 100);
    }

    // -----------------------------------------------------------------------
    // SearchResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_response_serialization() {
        let response = SearchResponse {
            items: vec![],
            total: 0,
            offset: 0,
            limit: 20,
            facets: SearchFacets::default(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["total"], 0);
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 20);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Suggest pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_suggest_pattern_construction() {
        let prefix = "my-lib";
        let pattern = format!("{}%", prefix);
        assert_eq!(pattern, "my-lib%");
    }

    #[test]
    fn test_suggest_pattern_empty_prefix() {
        let prefix = "";
        let pattern = format!("{}%", prefix);
        assert_eq!(pattern, "%");
    }
}
