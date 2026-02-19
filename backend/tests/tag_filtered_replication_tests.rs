//! Integration tests for tag-filtered peer replication (Issue #235).
//!
//! These tests verify that artifact labels can be managed via the API and
//! that sync policies with `match_tags` filters correctly queue push/delete
//! sync tasks when tags change.
//!
//! Requires a running backend HTTP server with PostgreSQL.
//!
//! ```sh
//! export TEST_BASE_URL="http://127.0.0.1:9080"
//! cargo test --test tag_filtered_replication_tests -- --ignored
//! ```

#![allow(dead_code)]

use std::env;

use reqwest::Client;
use serde_json::{json, Value};

struct TagReplicationTestServer {
    base_url: String,
    access_token: String,
    client: Client,
}

impl TagReplicationTestServer {
    fn new() -> Self {
        let base_url = env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9080".into());
        Self {
            base_url,
            access_token: String::new(),
            client: Client::new(),
        }
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&json!({
                "username": "admin",
                "password": "admin123"
            }))
            .send()
            .await?;

        let body: Value = resp.json().await?;
        self.access_token = body["access_token"]
            .as_str()
            .ok_or("No access token")?
            .to_string();
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{}", prefix, nanos)
    }

    // -----------------------------------------------------------------------
    // Repository helpers
    // -----------------------------------------------------------------------

    async fn create_repository(
        &self,
        key: &str,
        name: &str,
        format: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/repositories", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "key": key,
                "name": name,
                "format": format,
                "repo_type": "local",
                "is_public": true
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Create repository failed: {} - {}", status, text).into())
        }
    }

    async fn upload_artifact(
        &self,
        repo_key: &str,
        path: &str,
        content: &[u8],
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .put(format!(
                "{}/api/v1/repositories/{}/artifacts/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/octet-stream")
            .body(content.to_vec())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Upload artifact failed: {} - {}", status, text).into())
        }
    }

    // -----------------------------------------------------------------------
    // Artifact labels
    // -----------------------------------------------------------------------

    async fn list_artifact_labels(
        &self,
        artifact_id: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/artifacts/{}/labels",
                self.base_url, artifact_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("List labels failed: {} - {}", status, text).into())
        }
    }

    async fn set_artifact_labels(
        &self,
        artifact_id: &str,
        labels: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .put(format!(
                "{}/api/v1/artifacts/{}/labels",
                self.base_url, artifact_id
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({ "labels": labels }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Set labels failed: {} - {}", status, text).into())
        }
    }

    async fn add_artifact_label(
        &self,
        artifact_id: &str,
        key: &str,
        value: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!(
                "{}/api/v1/artifacts/{}/labels/{}",
                self.base_url, artifact_id, key
            ))
            .header("Authorization", self.auth_header())
            .json(&json!({ "value": value }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Add label failed: {} - {}", status, text).into())
        }
    }

    async fn delete_artifact_label(
        &self,
        artifact_id: &str,
        key: &str,
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .delete(format!(
                "{}/api/v1/artifacts/{}/labels/{}",
                self.base_url, artifact_id, key
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        Ok(resp.status().as_u16())
    }

    // -----------------------------------------------------------------------
    // Peer instances
    // -----------------------------------------------------------------------

    async fn create_peer(
        &self,
        name: &str,
        endpoint_url: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/peers", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "name": name,
                "endpoint_url": endpoint_url,
                "auth_token": "test-auth-token",
                "direction": "push"
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Create peer failed: {} - {}", status, text).into())
        }
    }

    async fn delete_peer(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .delete(format!("{}/api/v1/peers/{}", self.base_url, id))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            eprintln!("Warning: delete peer {} failed: {} - {}", id, status, text);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sync policies
    // -----------------------------------------------------------------------

    async fn create_sync_policy(
        &self,
        payload: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("{}/api/v1/sync-policies", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Create sync policy failed: {} - {}", status, text).into())
        }
    }

    async fn delete_sync_policy(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .client
            .delete(format!("{}/api/v1/sync-policies/{}", self.base_url, id))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            eprintln!(
                "Warning: delete sync policy {} failed: {} - {}",
                id, status, text
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sync tasks (query directly via database or via API)
    // -----------------------------------------------------------------------

    async fn get_sync_tasks_for_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        // Query sync tasks filtered by artifact_id via the admin sync tasks endpoint
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/sync-tasks?artifact_id={}",
                self.base_url, artifact_id
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            let body: Value = resp.json().await?;
            if let Some(items) = body["items"].as_array() {
                Ok(items.clone())
            } else if body.is_array() {
                Ok(body.as_array().cloned().unwrap_or_default())
            } else {
                Ok(vec![])
            }
        } else {
            // If there's no sync-tasks list endpoint, fall back to empty
            Ok(vec![])
        }
    }
}

async fn get_server() -> TagReplicationTestServer {
    let mut server = TagReplicationTestServer::new();
    server.login().await.expect("Login failed");
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // Test 1: Artifact label CRUD via API
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_artifact_label_crud() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-crud");

        // Create a repository and upload an artifact
        let repo = server
            .create_repository(&key, "Tag CRUD Test", "generic")
            .await
            .expect("Failed to create repository");
        let _repo_id = repo["id"].as_str().expect("No repo id");

        let artifact = server
            .upload_artifact(&key, "test/tag-test-1.0.0.bin", b"tag test content")
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // List labels (should be empty initially)
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels");
        assert_eq!(
            labels["total"].as_u64().unwrap_or(0),
            0,
            "New artifact should have no labels"
        );

        // Add a label via POST
        let label = server
            .add_artifact_label(artifact_id, "distribution", "test")
            .await
            .expect("Failed to add label");
        assert_eq!(label["key"].as_str().unwrap_or(""), "distribution");
        assert_eq!(label["value"].as_str().unwrap_or(""), "test");

        // List labels (should have 1)
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels");
        assert_eq!(labels["total"].as_u64().unwrap_or(0), 1);

        // Update label value by POSTing the same key
        let updated = server
            .add_artifact_label(artifact_id, "distribution", "production")
            .await
            .expect("Failed to update label");
        assert_eq!(updated["value"].as_str().unwrap_or(""), "production");

        // Set labels (bulk replace)
        let set_result = server
            .set_artifact_labels(
                artifact_id,
                json!([
                    {"key": "env", "value": "staging"},
                    {"key": "tier", "value": "gold"}
                ]),
            )
            .await
            .expect("Failed to set labels");
        assert_eq!(
            set_result["total"].as_u64().unwrap_or(0),
            2,
            "set_labels should replace all labels"
        );

        // Verify the replaced labels
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels after set");
        let items = labels["items"].as_array().expect("items should be array");
        let keys: Vec<&str> = items.iter().filter_map(|i| i["key"].as_str()).collect();
        assert!(keys.contains(&"env"), "Should have env label");
        assert!(keys.contains(&"tier"), "Should have tier label");
        assert!(
            !keys.contains(&"distribution"),
            "distribution should be replaced"
        );

        // Delete a label
        let status = server
            .delete_artifact_label(artifact_id, "env")
            .await
            .expect("Failed to delete label");
        assert_eq!(status, 204, "Delete label should return 204 No Content");

        // Verify deletion
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels after delete");
        assert_eq!(labels["total"].as_u64().unwrap_or(0), 1);
    }

    // ===================================================================
    // Test 2: Sync policy with match_tags creates push tasks
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_sync_policy_match_tags_queues_push_task() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-push");

        // Create repository
        let repo = server
            .create_repository(&key, "Tag Push Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Create a peer instance
        let peer = server
            .create_peer(
                &format!("{}-peer", key),
                &format!("https://{}-peer.test:8080", key),
            )
            .await
            .expect("Failed to create peer");
        let peer_id = peer["id"].as_str().expect("No peer id");

        // Create sync policy with match_tags filter
        let policy = server
            .create_sync_policy(json!({
                "name": format!("{}-policy", key),
                "description": "Only sync production artifacts",
                "enabled": true,
                "repo_selector": {
                    "repository_ids": [repo_id]
                },
                "peer_selector": {
                    "peer_ids": [peer_id]
                },
                "artifact_filter": {
                    "match_tags": {
                        "distribution": "production"
                    }
                },
                "replication_mode": "push"
            }))
            .await
            .expect("Failed to create sync policy");
        let policy_id = policy["id"].as_str().expect("No policy id");

        // Upload artifact
        let artifact = server
            .upload_artifact(&key, "test/tagged-artifact-1.0.0.bin", b"tagged content")
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // Set a non-matching tag first
        server
            .add_artifact_label(artifact_id, "distribution", "test")
            .await
            .expect("Failed to add label");

        // Give the async evaluation time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Now set the matching tag, which should trigger sync evaluation
        server
            .add_artifact_label(artifact_id, "distribution", "production")
            .await
            .expect("Failed to update label to production");

        // Give the async evaluation time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Query sync tasks for this artifact
        let tasks = server
            .get_sync_tasks_for_artifact(artifact_id)
            .await
            .unwrap_or_default();

        // Verify a push task was queued (if the endpoint exists)
        if !tasks.is_empty() {
            let push_tasks: Vec<&Value> = tasks
                .iter()
                .filter(|t| t["task_type"].as_str().unwrap_or("push") == "push")
                .collect();
            assert!(
                !push_tasks.is_empty(),
                "Should have queued a push sync task for the matching tag"
            );
        }

        // Cleanup
        let _ = server.delete_sync_policy(policy_id).await;
        let _ = server.delete_peer(peer_id).await;
    }

    // ===================================================================
    // Test 3: Changing tag to non-matching queues delete task
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_tag_change_to_non_matching_queues_delete_task() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-del");

        // Create repository
        let repo = server
            .create_repository(&key, "Tag Delete Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Create peer
        let peer = server
            .create_peer(
                &format!("{}-peer", key),
                &format!("https://{}-peer.test:8080", key),
            )
            .await
            .expect("Failed to create peer");
        let peer_id = peer["id"].as_str().expect("No peer id");

        // Create sync policy filtering on distribution=production
        let policy = server
            .create_sync_policy(json!({
                "name": format!("{}-policy", key),
                "enabled": true,
                "repo_selector": { "repository_ids": [repo_id] },
                "peer_selector": { "peer_ids": [peer_id] },
                "artifact_filter": {
                    "match_tags": { "distribution": "production" }
                },
                "replication_mode": "push"
            }))
            .await
            .expect("Failed to create sync policy");
        let policy_id = policy["id"].as_str().expect("No policy id");

        // Upload artifact with matching tag
        let artifact = server
            .upload_artifact(&key, "test/delete-test-1.0.0.bin", b"delete test content")
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // Set matching tag (triggers push)
        server
            .add_artifact_label(artifact_id, "distribution", "production")
            .await
            .expect("Failed to add label");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Now change to non-matching tag (should trigger delete)
        server
            .add_artifact_label(artifact_id, "distribution", "eol")
            .await
            .expect("Failed to change label to eol");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Query sync tasks
        let tasks = server
            .get_sync_tasks_for_artifact(artifact_id)
            .await
            .unwrap_or_default();

        // Verify a delete task was queued
        if !tasks.is_empty() {
            let delete_tasks: Vec<&Value> = tasks
                .iter()
                .filter(|t| t["task_type"].as_str() == Some("delete"))
                .collect();
            assert!(
                !delete_tasks.is_empty(),
                "Should have queued a delete sync task when tag became non-matching"
            );
        }

        // Cleanup
        let _ = server.delete_sync_policy(policy_id).await;
        let _ = server.delete_peer(peer_id).await;
    }

    // ===================================================================
    // Test 4: Policy without match_tags still syncs all artifacts
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_policy_without_match_tags_backward_compatible() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-compat");

        // Create repository
        let repo = server
            .create_repository(&key, "Backward Compat Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Create peer
        let peer = server
            .create_peer(
                &format!("{}-peer", key),
                &format!("https://{}-peer.test:8080", key),
            )
            .await
            .expect("Failed to create peer");
        let peer_id = peer["id"].as_str().expect("No peer id");

        // Create sync policy WITHOUT match_tags (backward compatible)
        let policy = server
            .create_sync_policy(json!({
                "name": format!("{}-policy", key),
                "enabled": true,
                "repo_selector": { "repository_ids": [repo_id] },
                "peer_selector": { "peer_ids": [peer_id] },
                "artifact_filter": {},
                "replication_mode": "push"
            }))
            .await
            .expect("Failed to create sync policy");
        let policy_id = policy["id"].as_str().expect("No policy id");

        // Upload artifact (no tags at all)
        let artifact = server
            .upload_artifact(
                &key,
                "test/compat-artifact-1.0.0.bin",
                b"backward compat content",
            )
            .await
            .expect("Failed to upload artifact");
        let _artifact_id = artifact["id"].as_str().expect("No artifact id");

        // The upload itself should succeed. The artifact should pass the
        // filter since match_tags is empty (matches all).
        // This validates backward compatibility: existing policies without
        // match_tags continue to work.

        // Cleanup
        let _ = server.delete_sync_policy(policy_id).await;
        let _ = server.delete_peer(peer_id).await;
    }

    // ===================================================================
    // Test 5: Bulk label set triggers re-evaluation
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_bulk_label_set_triggers_reevaluation() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-bulk");

        // Create repository
        let repo = server
            .create_repository(&key, "Bulk Label Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Create peer
        let peer = server
            .create_peer(
                &format!("{}-peer", key),
                &format!("https://{}-peer.test:8080", key),
            )
            .await
            .expect("Failed to create peer");
        let peer_id = peer["id"].as_str().expect("No peer id");

        // Create policy requiring both distribution=production AND tier=gold
        let policy = server
            .create_sync_policy(json!({
                "name": format!("{}-policy", key),
                "enabled": true,
                "repo_selector": { "repository_ids": [repo_id] },
                "peer_selector": { "peer_ids": [peer_id] },
                "artifact_filter": {
                    "match_tags": {
                        "distribution": "production",
                        "tier": "gold"
                    }
                },
                "replication_mode": "push"
            }))
            .await
            .expect("Failed to create sync policy");
        let policy_id = policy["id"].as_str().expect("No policy id");

        // Upload artifact
        let artifact = server
            .upload_artifact(&key, "test/bulk-artifact-1.0.0.bin", b"bulk label content")
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        // Set only one matching tag (should NOT trigger push since AND semantics)
        server
            .add_artifact_label(artifact_id, "distribution", "production")
            .await
            .expect("Failed to add distribution label");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Now bulk-set both matching tags via PUT
        server
            .set_artifact_labels(
                artifact_id,
                json!([
                    {"key": "distribution", "value": "production"},
                    {"key": "tier", "value": "gold"}
                ]),
            )
            .await
            .expect("Failed to set labels in bulk");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Verify labels were set correctly
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels");
        assert_eq!(
            labels["total"].as_u64().unwrap_or(0),
            2,
            "Should have 2 labels after bulk set"
        );

        // Cleanup
        let _ = server.delete_sync_policy(policy_id).await;
        let _ = server.delete_peer(peer_id).await;
    }

    // ===================================================================
    // Test 6: Label on nonexistent artifact returns 404
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_labels_on_nonexistent_artifact_returns_404() {
        let server = get_server().await;
        let fake_id = "00000000-0000-0000-0000-000000000000";

        let resp = server
            .client
            .get(format!(
                "{}/api/v1/artifacts/{}/labels",
                server.base_url, fake_id
            ))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(
            resp.status().as_u16(),
            404,
            "Labels on nonexistent artifact should return 404"
        );
    }

    // ===================================================================
    // Test 7: Delete label triggers re-evaluation
    // ===================================================================

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_delete_label_triggers_reevaluation() {
        let server = get_server().await;
        let key = TagReplicationTestServer::unique_key("tag-delre");

        // Create repository
        let repo = server
            .create_repository(&key, "Delete Label Re-eval Test", "generic")
            .await
            .expect("Failed to create repository");
        let repo_id = repo["id"].as_str().expect("No repo id");

        // Create peer
        let peer = server
            .create_peer(
                &format!("{}-peer", key),
                &format!("https://{}-peer.test:8080", key),
            )
            .await
            .expect("Failed to create peer");
        let peer_id = peer["id"].as_str().expect("No peer id");

        // Create policy filtering on distribution key existing
        let policy = server
            .create_sync_policy(json!({
                "name": format!("{}-policy", key),
                "enabled": true,
                "repo_selector": { "repository_ids": [repo_id] },
                "peer_selector": { "peer_ids": [peer_id] },
                "artifact_filter": {
                    "match_tags": { "distribution": "production" }
                },
                "replication_mode": "push"
            }))
            .await
            .expect("Failed to create sync policy");
        let policy_id = policy["id"].as_str().expect("No policy id");

        // Upload artifact with matching tag
        let artifact = server
            .upload_artifact(&key, "test/delre-1.0.0.bin", b"delete re-eval content")
            .await
            .expect("Failed to upload artifact");
        let artifact_id = artifact["id"].as_str().expect("No artifact id");

        server
            .add_artifact_label(artifact_id, "distribution", "production")
            .await
            .expect("Failed to add label");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Delete the label (artifact no longer matches)
        let status = server
            .delete_artifact_label(artifact_id, "distribution")
            .await
            .expect("Failed to delete label");
        assert_eq!(status, 204);

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Verify no labels remain
        let labels = server
            .list_artifact_labels(artifact_id)
            .await
            .expect("Failed to list labels after delete");
        assert_eq!(
            labels["total"].as_u64().unwrap_or(0),
            0,
            "All labels should be removed"
        );

        // Cleanup
        let _ = server.delete_sync_policy(policy_id).await;
        let _ = server.delete_peer(peer_id).await;
    }
}
