//! Shared repository selector service.
//!
//! Provides the `RepoSelector` type and resolution logic used by both
//! sync policies (to select which repos to replicate) and service account
//! tokens (to restrict which repos a token can access).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Repository selector: determines which repositories match a set of criteria.
///
/// Used by sync policies and token repository scoping. All non-empty fields
/// are combined with AND semantics (a repo must pass every active filter).
/// Within `match_formats`, items use OR semantics (any format matches).
/// Within `match_labels`, items use AND semantics (all labels must match).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoSelector {
    /// Label key-value pairs that must all match (AND semantics).
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    /// Repository format types to include (e.g. "docker", "maven"). OR semantics.
    #[serde(default)]
    pub match_formats: Vec<String>,
    /// Glob-like name pattern (e.g. "libs-*"). Only `*` wildcard supported,
    /// translated to SQL `LIKE` with `%`.
    #[serde(default)]
    pub match_pattern: Option<String>,
    /// Explicit repository UUIDs to include.
    #[serde(default)]
    pub match_repos: Vec<Uuid>,
}

/// A repository matched by a selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRepo {
    pub id: Uuid,
    pub key: String,
    pub format: String,
}

// Internal row types for sqlx queries.
#[derive(Debug, sqlx::FromRow)]
struct RepoRow {
    id: Uuid,
    key: String,
    format: String,
}

#[derive(Debug, sqlx::FromRow)]
struct LabelRow {
    repository_id: Uuid,
    label_key: String,
    label_value: String,
}

/// Service for resolving repository selectors to concrete repository lists.
pub struct RepoSelectorService {
    db: PgPool,
}

impl RepoSelectorService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if a selector is empty (would match nothing).
    pub fn is_empty(selector: &RepoSelector) -> bool {
        selector.match_labels.is_empty()
            && selector.match_formats.is_empty()
            && selector.match_pattern.is_none()
            && selector.match_repos.is_empty()
    }

    /// Resolve repositories matching a selector. Returns matched repo details.
    pub async fn resolve(&self, selector: &RepoSelector) -> Result<Vec<MatchedRepo>> {
        let rows = self.resolve_rows(selector).await?;
        Ok(rows
            .into_iter()
            .map(|r| MatchedRepo {
                id: r.id,
                key: r.key,
                format: r.format,
            })
            .collect())
    }

    /// Resolve just the IDs (convenience for the auth path).
    pub async fn resolve_ids(&self, selector: &RepoSelector) -> Result<Vec<Uuid>> {
        let rows = self.resolve_rows(selector).await?;
        Ok(rows.into_iter().map(|r| r.id).collect())
    }

    /// Core resolution logic.
    async fn resolve_rows(&self, selector: &RepoSelector) -> Result<Vec<RepoRow>> {
        // If explicit repo IDs are given, use them directly
        if !selector.match_repos.is_empty() {
            let repos: Vec<RepoRow> = sqlx::query_as(
                r#"
                SELECT id, key, format::TEXT
                FROM repositories
                WHERE id = ANY($1)
                "#,
            )
            .bind(&selector.match_repos)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(repos);
        }

        // Start with all repositories
        let mut all_repos: Vec<RepoRow> =
            sqlx::query_as("SELECT id, key, format::TEXT FROM repositories ORDER BY key")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let has_any_filter = !selector.match_labels.is_empty()
            || !selector.match_formats.is_empty()
            || selector.match_pattern.is_some();

        // Empty selector with no filters matches nothing
        if !has_any_filter {
            return Ok(vec![]);
        }

        // Filter by format (OR semantics)
        if !selector.match_formats.is_empty() {
            let formats: Vec<String> = selector
                .match_formats
                .iter()
                .map(|f| f.to_lowercase())
                .collect();
            all_repos.retain(|r| formats.contains(&r.format.to_lowercase()));
        }

        // Filter by name pattern (glob: * -> %)
        if let Some(pattern) = &selector.match_pattern {
            let sql_pattern = pattern.replace('*', "%");
            all_repos.retain(|r| sql_like_match(&r.key, &sql_pattern));
        }

        // Filter by labels (AND semantics: all label pairs must match)
        if !selector.match_labels.is_empty() {
            let label_repo_ids = self.resolve_repos_by_labels(&selector.match_labels).await?;
            all_repos.retain(|r| label_repo_ids.contains(&r.id));
        }

        Ok(all_repos)
    }

    /// Find repository IDs that have all the given labels.
    async fn resolve_repos_by_labels(&self, labels: &HashMap<String, String>) -> Result<Vec<Uuid>> {
        if labels.is_empty() {
            return Ok(vec![]);
        }

        let all_labels: Vec<LabelRow> =
            sqlx::query_as("SELECT repository_id, label_key, label_value FROM repository_labels")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        // Group labels by repository
        let mut repo_labels: HashMap<Uuid, Vec<(&str, &str)>> = HashMap::new();
        for row in &all_labels {
            repo_labels
                .entry(row.repository_id)
                .or_default()
                .push((&row.label_key, &row.label_value));
        }

        // Find repos that have ALL required labels
        let mut matching: Vec<Uuid> = Vec::new();
        for (repo_id, repo_label_list) in &repo_labels {
            let all_match = labels
                .iter()
                .all(|(k, v)| repo_label_list.iter().any(|(lk, lv)| lk == k && lv == v));
            if all_match {
                matching.push(*repo_id);
            }
        }

        Ok(matching)
    }
}

/// Simple SQL LIKE pattern matching for in-memory filtering.
/// Supports `%` as wildcard (matches zero or more characters).
pub fn sql_like_match(value: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('%').collect();

    if parts.len() == 1 {
        // No wildcards: exact match
        return value == pattern;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Must start with this prefix
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Must end with this suffix
            if !value[pos..].ends_with(part) {
                return false;
            }
            pos = value.len();
        } else {
            // Must contain this part somewhere after pos
            match value[pos..].find(part) {
                Some(found) => pos += found + part.len(),
                None => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_selector_is_empty() {
        assert!(RepoSelectorService::is_empty(&RepoSelector::default()));
    }

    #[test]
    fn test_selector_with_formats_is_not_empty() {
        let sel = RepoSelector {
            match_formats: vec!["docker".to_string()],
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_labels_is_not_empty() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        let sel = RepoSelector {
            match_labels: labels,
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_pattern_is_not_empty() {
        let sel = RepoSelector {
            match_pattern: Some("libs-*".to_string()),
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_selector_with_repos_is_not_empty() {
        let sel = RepoSelector {
            match_repos: vec![Uuid::new_v4()],
            ..Default::default()
        };
        assert!(!RepoSelectorService::is_empty(&sel));
    }

    #[test]
    fn test_repo_selector_serde_roundtrip() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "production".to_string());
        labels.insert("team".to_string(), "platform".to_string());

        let sel = RepoSelector {
            match_labels: labels,
            match_formats: vec!["docker".to_string(), "npm".to_string()],
            match_pattern: Some("libs-*".to_string()),
            match_repos: vec![],
        };

        let json = serde_json::to_value(&sel).unwrap();
        let deserialized: RepoSelector = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.match_labels.len(), 2);
        assert_eq!(deserialized.match_formats.len(), 2);
        assert_eq!(deserialized.match_pattern.as_deref(), Some("libs-*"));
        assert!(deserialized.match_repos.is_empty());
    }

    #[test]
    fn test_sql_like_match_exact() {
        assert!(sql_like_match("hello", "hello"));
        assert!(!sql_like_match("hello", "world"));
    }

    #[test]
    fn test_sql_like_match_prefix() {
        assert!(sql_like_match("libs-docker-prod", "libs-%"));
        assert!(!sql_like_match("test-docker", "libs-%"));
    }

    #[test]
    fn test_sql_like_match_suffix() {
        assert!(sql_like_match("libs-docker-prod", "%-prod"));
        assert!(!sql_like_match("libs-docker-dev", "%-prod"));
    }

    #[test]
    fn test_sql_like_match_contains() {
        assert!(sql_like_match("libs-docker-prod", "%docker%"));
        assert!(!sql_like_match("libs-maven-prod", "%docker%"));
    }

    #[test]
    fn test_sql_like_match_wildcard_all() {
        assert!(sql_like_match("anything", "%"));
    }
}
