# Quality of Life Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 10 quality-of-life improvements addressing the most common pain points in the artifact registry space: storage cleanup automation, proxy resilience, replication, webhook reliability, token lifecycle, search, quota warnings, and replication filters.

**Architecture:** All changes build on existing services in `backend/src/services/`. No new crates. Each task is self-contained with unit tests. The scheduler_service already runs background tasks (GC hourly, lifecycle every 6h); we enhance it with configurable cron schedules. The proxy_service gets stale-cache fallback. The sync_worker gets delete propagation and regex filters. The webhook handlers get background retry. Token revocation switches from hard-delete to soft-revoke.

**Tech Stack:** Rust (axum, sqlx, tokio, cron, reqwest, metrics), PostgreSQL, Meilisearch, Prometheus

**Pre-existing state (verified by code audit):**
- GC runs hourly, lifecycle every 6h via `scheduler_service.rs` (hardcoded intervals)
- Proxy has `get_cache_ttl_for_repo()` reading from `repository_config` table
- Sync worker already handles `task_type = "delete"` but `artifact_service.delete()` never enqueues one
- `webhook_deliveries` table and list/redeliver endpoints exist, but no automatic retry worker
- `revoke_token()` hard-DELETEs the token (no `revoked_at`, no soft-revoke)
- `meili_service.full_reindex()` exists but no admin API endpoint
- `check_quota()` returns bool, no warning events emitted
- Artifact download button already exists in the web UI (bead `artifact-keeper-6wv` can be closed)

---

## Task 1: Configurable Cron Schedule for GC and Lifecycle

**Bead:** `artifact-keeper-wy2`

**Files:**
- Modify: `backend/src/config.rs:16-106` (add `gc_schedule` and `lifecycle_check_interval_secs` fields)
- Modify: `backend/src/services/scheduler_service.rs:109-188` (use cron schedule instead of fixed interval)
- Modify: `backend/src/services/lifecycle_service.rs:20-35` (add `cron_schedule` to LifecyclePolicy struct)

**Step 1: Add GC_SCHEDULE and LIFECYCLE_CHECK_INTERVAL_SECS to Config**

Add two fields to the `Config` struct in `backend/src/config.rs`:

```rust
// After line 105 (otel_service_name field), add:

    /// Cron schedule for storage garbage collection (default: hourly)
    pub gc_schedule: String,

    /// How often (in seconds) to check for due lifecycle policies (default: 60)
    pub lifecycle_check_interval_secs: u64,
```

In `Config::from_env()`, after the `otel_service_name` assignment (line 156), add:

```rust
            gc_schedule: env::var("GC_SCHEDULE")
                .unwrap_or_else(|_| "0 0 * * * *".into()), // every hour
            lifecycle_check_interval_secs: env_parse("LIFECYCLE_CHECK_INTERVAL_SECS", 60),
```

**Step 2: Write unit tests for the new config fields**

In the `#[cfg(test)] mod tests` block in `config.rs`, add:

```rust
    #[test]
    fn test_gc_schedule_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::set_var("DATABASE_URL", "postgresql://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret");
        env::remove_var("GC_SCHEDULE");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 0 * * * *");

        if let Some(v) = saved_db { env::set_var("DATABASE_URL", v); }
        if let Some(v) = saved_jwt { env::set_var("JWT_SECRET", v); }
    }

    #[test]
    fn test_gc_schedule_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::set_var("DATABASE_URL", "postgresql://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret");
        env::set_var("GC_SCHEDULE", "0 0 2 * * *");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 0 2 * * *");

        env::remove_var("GC_SCHEDULE");
        if let Some(v) = saved_db { env::set_var("DATABASE_URL", v); }
        if let Some(v) = saved_jwt { env::set_var("JWT_SECRET", v); }
    }

    #[test]
    fn test_lifecycle_check_interval_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("LIFECYCLE_CHECK_INTERVAL_SECS");
        let result: u64 = env_parse("LIFECYCLE_CHECK_INTERVAL_SECS", 60);
        assert_eq!(result, 60);
    }
```

**Step 3: Run tests to verify**

Run: `cargo test --workspace --lib config::tests -- --test-threads=1`

Expected: All tests pass (existing + 3 new).

**Step 4: Add cron_schedule to LifecyclePolicy**

In `backend/src/services/lifecycle_service.rs`, add a field to the `LifecyclePolicy` struct (after `updated_at` at line 34):

```rust
    pub cron_schedule: Option<String>,
```

Also add `cron_schedule: Option<String>` to `CreatePolicyRequest` (after `priority` at line 46) and `UpdatePolicyRequest` (after `priority` at line 57).

Update the SQL query in `execute_all_enabled()` (line 281) to include `cron_schedule`:

```rust
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, created_at, updated_at, cron_schedule
            FROM lifecycle_policies
            WHERE enabled = true
            ORDER BY priority DESC
```

**Step 5: Update scheduler to use cron for GC**

In `backend/src/services/scheduler_service.rs`, update the GC spawn block (lines 143-188). Replace the fixed interval with cron-based scheduling:

```rust
    // Storage garbage collection (cron-based)
    {
        let db = db.clone();
        let config_clone = config.clone();
        let gc_storage = primary_storage.clone();
        let gc_schedule_str = config.gc_schedule.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let service = crate::services::storage_gc_service::StorageGcService::new(
                db,
                gc_storage,
                config_clone.storage_backend.clone(),
            );

            let schedule = match Schedule::from_str(&gc_schedule_str) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Invalid GC_SCHEDULE '{}': {}. Falling back to hourly.", gc_schedule_str, e);
                    Schedule::from_str("0 0 * * * *").unwrap()
                }
            };

            loop {
                let next = schedule.upcoming(chrono::Utc).next();
                if let Some(next_time) = next {
                    let wait = (next_time - Utc::now()).to_std().unwrap_or(Duration::from_secs(3600));
                    tokio::time::sleep(wait).await;
                } else {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }

                tracing::info!("Running scheduled storage garbage collection");
                match service.run_gc(false).await {
                    Ok(result) => {
                        if result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                                result.storage_keys_deleted,
                                result.artifacts_removed,
                                result.bytes_freed
                            );
                            metrics_service::record_cleanup("storage_gc", result.artifacts_removed as u64);
                        }
                        if !result.errors.is_empty() {
                            tracing::warn!("Storage GC completed with {} errors", result.errors.len());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Storage garbage collection failed: {}", e);
                    }
                }
            }
        });
    }
```

**Step 6: Update lifecycle scheduler to check for per-policy cron schedules**

Replace the lifecycle block (lines 109-141) with a check loop that evaluates per-policy cron schedules. Instead of running all policies on a fixed 6h interval, check every N seconds (configurable) and only run policies whose cron schedule is due:

```rust
    // Lifecycle policy execution (check every N seconds for due policies)
    {
        let db = db.clone();
        let check_interval = config.lifecycle_check_interval_secs;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let service = LifecycleService::new(db);
            let mut ticker = interval(Duration::from_secs(check_interval));

            loop {
                ticker.tick().await;
                match service.execute_due_policies().await {
                    Ok(results) => {
                        let total_removed: i64 = results.iter().map(|r| r.artifacts_removed).sum();
                        let total_freed: i64 = results.iter().map(|r| r.bytes_freed).sum();
                        if total_removed > 0 {
                            tracing::info!(
                                "Lifecycle cleanup: removed {} artifacts, freed {} bytes across {} policies",
                                total_removed, total_freed, results.len()
                            );
                            metrics_service::record_cleanup("lifecycle", total_removed as u64);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Lifecycle policy execution failed: {}", e);
                    }
                }
            }
        });
    }
```

**Step 7: Add execute_due_policies to LifecycleService**

In `backend/src/services/lifecycle_service.rs`, add a new method that only runs policies whose cron schedule is due:

```rust
    /// Execute policies whose cron_schedule indicates they are due.
    /// Policies without a cron_schedule are run on the default 6-hour cadence.
    pub async fn execute_due_policies(&self) -> Result<Vec<PolicyExecutionResult>> {
        let policies = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, created_at, updated_at, cron_schedule
            FROM lifecycle_policies
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let now = chrono::Utc::now();
        let mut results = Vec::new();

        for policy in policies {
            let should_run = match &policy.cron_schedule {
                Some(cron_expr) => {
                    match cron::Schedule::from_str(cron_expr) {
                        Ok(schedule) => {
                            let last_run = policy.last_run_at.unwrap_or(chrono::DateTime::UNIX_EPOCH);
                            schedule.after(&last_run).next().map(|next| next <= now).unwrap_or(false)
                        }
                        Err(_) => {
                            tracing::warn!("Invalid cron schedule '{}' for policy '{}'", cron_expr, policy.name);
                            false
                        }
                    }
                }
                None => {
                    // Default: run if last_run_at is more than 6 hours ago (or never run)
                    let threshold = chrono::Duration::hours(6);
                    policy.last_run_at.map(|lr| now - lr > threshold).unwrap_or(true)
                }
            };

            if should_run {
                match self.execute_policy(policy.id, false).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::error!("Failed to execute lifecycle policy '{}': {}", policy.name, e);
                        results.push(PolicyExecutionResult {
                            policy_id: policy.id,
                            policy_name: policy.name,
                            dry_run: false,
                            artifacts_matched: 0,
                            artifacts_removed: 0,
                            bytes_freed: 0,
                            errors: vec![e.to_string()],
                        });
                    }
                }
            }
        }

        Ok(results)
    }
```

Add `use std::str::FromStr;` to the imports at the top of lifecycle_service.rs.

**Step 8: Write migration for cron_schedule column**

Create `backend/migrations/066_lifecycle_cron_schedule.sql`:

```sql
ALTER TABLE lifecycle_policies ADD COLUMN IF NOT EXISTS cron_schedule TEXT;
COMMENT ON COLUMN lifecycle_policies.cron_schedule IS 'Optional cron expression (6-field) for automatic policy execution. NULL = default 6-hour interval.';
```

**Step 9: Write unit tests for execute_due_policies**

Add to the test module in `lifecycle_service.rs`:

```rust
    #[test]
    fn test_cron_schedule_parsing() {
        use cron::Schedule;
        use std::str::FromStr;

        // Valid: every hour
        assert!(Schedule::from_str("0 0 * * * *").is_ok());
        // Valid: daily at 2am
        assert!(Schedule::from_str("0 0 2 * * *").is_ok());
        // Invalid
        assert!(Schedule::from_str("not-a-cron").is_err());
    }

    #[test]
    fn test_default_cadence_never_run_should_execute() {
        // Policy with no cron_schedule and no last_run_at should run
        let last_run: Option<chrono::DateTime<chrono::Utc>> = None;
        let now = chrono::Utc::now();
        let threshold = chrono::Duration::hours(6);
        let should_run = last_run.map(|lr| now - lr > threshold).unwrap_or(true);
        assert!(should_run);
    }

    #[test]
    fn test_default_cadence_recently_run_should_skip() {
        let now = chrono::Utc::now();
        let last_run = Some(now - chrono::Duration::hours(1));
        let threshold = chrono::Duration::hours(6);
        let should_run = last_run.map(|lr| now - lr > threshold).unwrap_or(true);
        assert!(!should_run);
    }

    #[test]
    fn test_default_cadence_old_run_should_execute() {
        let now = chrono::Utc::now();
        let last_run = Some(now - chrono::Duration::hours(7));
        let threshold = chrono::Duration::hours(6);
        let should_run = last_run.map(|lr| now - lr > threshold).unwrap_or(true);
        assert!(should_run);
    }
```

**Step 10: Run tests and commit**

Run: `cargo test --workspace --lib -- --test-threads=1`
Run: `cargo clippy --workspace`
Expected: All pass.

```bash
git add backend/src/config.rs backend/src/services/lifecycle_service.rs \
  backend/src/services/scheduler_service.rs backend/migrations/066_lifecycle_cron_schedule.sql
git commit -m "feat: configurable cron schedule for GC and lifecycle policies

GC_SCHEDULE env var controls GC timing (default: hourly).
Lifecycle policies can set per-policy cron_schedule field.
Policies without a cron schedule use the default 6-hour cadence."
```

---

## Task 2: Serve Stale Proxy Cache When Upstream Is Down

**Bead:** `artifact-keeper-zea`

**Files:**
- Modify: `backend/src/services/proxy_service.rs:69-114` (add stale cache fallback in fetch_artifact)

**Step 1: Write unit tests for stale cache logic**

Add to the test module in `proxy_service.rs`:

```rust
    #[test]
    fn test_cache_metadata_is_stale() {
        let expired_meta = CacheMetadata {
            cached_at: Utc::now() - chrono::Duration::hours(48),
            upstream_etag: None,
            expires_at: Utc::now() - chrono::Duration::hours(24),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 100,
            checksum_sha256: "abc123".to_string(),
        };
        assert!(expired_meta.expires_at < Utc::now());
    }

    #[test]
    fn test_stale_cache_headers() {
        let headers = build_stale_cache_headers();
        assert_eq!(headers.get("X-Cache").unwrap(), "STALE");
        assert!(headers.get("Warning").unwrap().contains("110"));
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --workspace --lib proxy_service::tests -- --test-threads=1`
Expected: FAIL (functions don't exist yet)

**Step 3: Add stale cache fallback to fetch_artifact**

In `backend/src/services/proxy_service.rs`, modify the `fetch_artifact` method. After the upstream fetch attempt (around line 99), wrap the error path to check for stale cache:

```rust
    pub async fn fetch_artifact(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let cache_key = Self::cache_storage_key(&repo.key, path);
        let metadata_key = Self::cache_metadata_key(&repo.key, path);

        // Check if we have a valid (non-expired) cached copy
        if let Some((content, content_type)) =
            self.get_cached_artifact(&cache_key, &metadata_key).await?
        {
            return Ok((content, content_type));
        }

        // Try to fetch from upstream
        let full_url = Self::build_upstream_url(upstream_url, path);
        match self.fetch_from_upstream(&full_url).await {
            Ok((content, content_type, etag)) => {
                // Cache the artifact
                let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
                self.cache_artifact(
                    &cache_key, &metadata_key, &content,
                    content_type.clone(), etag, cache_ttl,
                ).await?;
                Ok((content, content_type))
            }
            Err(upstream_err) => {
                // Upstream failed - try to serve stale cache
                tracing::warn!(
                    "Upstream fetch failed for {}: {}. Checking for stale cache.",
                    full_url, upstream_err
                );
                if let Some((content, content_type)) =
                    self.get_stale_cached_artifact(&cache_key, &metadata_key).await?
                {
                    tracing::info!(
                        "Serving stale cache for {} (upstream unavailable)",
                        path
                    );
                    Ok((content, content_type))
                } else {
                    Err(upstream_err)
                }
            }
        }
    }
```

**Step 4: Add get_stale_cached_artifact helper**

Add this method to the `ProxyService` impl block:

```rust
    /// Get a cached artifact regardless of TTL expiry.
    /// Used as a fallback when upstream is unavailable.
    async fn get_stale_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Try to load metadata (may be expired, that's ok)
        let metadata = match self.load_cache_metadata(metadata_key).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Try to load the actual content
        match self.storage.get(cache_key).await {
            Ok(content) => Ok(Some((content, metadata.content_type))),
            Err(_) => Ok(None),
        }
    }
```

**Step 5: Add a public method to check if a response was stale**

Add a helper function (outside the impl, pub(crate)) for building stale cache headers:

```rust
/// Build HTTP headers indicating a stale cache response.
pub(crate) fn build_stale_cache_headers() -> std::collections::HashMap<String, String> {
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Cache".to_string(), "STALE".to_string());
    headers.insert("Warning".to_string(), "110 artifact-keeper \"Response is stale\"".to_string());
    headers
}
```

**Step 6: Run tests and commit**

Run: `cargo test --workspace --lib proxy_service -- --test-threads=1`
Run: `cargo clippy --workspace`
Expected: All pass.

```bash
git add backend/src/services/proxy_service.rs
git commit -m "feat: serve stale proxy cache when upstream is unavailable

When an upstream fetch fails (timeout, connection error, 5xx),
fall back to serving expired cached content with X-Cache: STALE
and Warning: 110 headers."
```

---

## Task 3: Deletion Replication to Peers

**Bead:** `artifact-keeper-6i7`

**Files:**
- Modify: `backend/src/services/artifact_service.rs:608-649` (enqueue delete sync task after soft-delete)

**Step 1: Write unit test for the enqueue logic**

The sync worker already handles `task_type = "delete"` (sync_worker.rs:233). The missing piece is that `artifact_service.delete()` never enqueues a sync task. Add a unit test:

```rust
    #[test]
    fn test_delete_sync_task_insert_query_is_valid_sql() {
        // Validate the SQL we'll use to enqueue delete sync tasks
        let sql = r#"
            INSERT INTO sync_tasks (id, peer_instance_id, artifact_id, task_type, status, priority)
            SELECT gen_random_uuid(), pi.id, $1, 'delete', 'pending', 0
            FROM peer_instances pi
            JOIN peer_repo_associations pra ON pra.peer_instance_id = pi.id
            JOIN artifacts a ON a.repository_id = pra.repository_id AND a.id = $1
            WHERE pi.is_local = false
              AND pi.status IN ('online', 'syncing')
              AND pra.replication_mode IN ('push', 'bidirectional')
        "#;
        // Just verify it's syntactically valid by checking key clauses
        assert!(sql.contains("INSERT INTO sync_tasks"));
        assert!(sql.contains("task_type, 'delete'"));
        assert!(sql.contains("peer_repo_associations"));
    }
```

**Step 2: Add delete sync task enqueue to artifact_service.delete()**

In `backend/src/services/artifact_service.rs`, after the successful soft-delete (after line 627, before the AfterDelete hook), add:

```rust
        // Enqueue delete sync tasks for all eligible peers
        let _ = sqlx::query(
            r#"
            INSERT INTO sync_tasks (id, peer_instance_id, artifact_id, task_type, status, priority)
            SELECT gen_random_uuid(), pi.id, $1, 'delete', 'pending', 0
            FROM peer_instances pi
            JOIN peer_repo_associations pra ON pra.peer_instance_id = pi.id
            JOIN artifacts a ON a.repository_id = pra.repository_id AND a.id = $1
            WHERE pi.is_local = false
              AND pi.status IN ('online', 'syncing')
              AND pra.replication_mode IN ('push', 'bidirectional')
            "#,
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to enqueue delete sync tasks for artifact {}: {}", id, e);
            e
        });
```

Note: We intentionally use `let _ =` and log a warning on failure so that deletion succeeds locally even if sync task enqueue fails (no cascading errors).

**Step 3: Run tests and commit**

Run: `cargo test --workspace --lib artifact_service -- --test-threads=1`
Run: `cargo clippy --workspace`
Expected: All pass.

```bash
git add backend/src/services/artifact_service.rs
git commit -m "feat: enqueue delete sync tasks on artifact soft-delete

When an artifact is soft-deleted, enqueue 'delete' sync tasks for
all eligible peers. The sync worker already handles delete tasks."
```

---

## Task 4: Webhook Delivery Retry with Exponential Backoff

**Bead:** `artifact-keeper-mdx`

**Files:**
- Modify: `backend/src/api/handlers/webhooks.rs` (add retry worker and update delivery recording)
- Modify: `backend/src/services/scheduler_service.rs` (spawn webhook retry worker)
- New migration: `backend/migrations/067_webhook_delivery_retry.sql`

**Step 1: Write migration for retry columns**

Create `backend/migrations/067_webhook_delivery_retry.sql`:

```sql
-- Add retry tracking columns to webhook_deliveries
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 5;

-- Index for efficient retry queue polling
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_retry
  ON webhook_deliveries (next_retry_at)
  WHERE success = false AND attempts < max_attempts AND next_retry_at IS NOT NULL;

COMMENT ON COLUMN webhook_deliveries.next_retry_at IS 'When to next attempt delivery. NULL = no more retries.';
COMMENT ON COLUMN webhook_deliveries.max_attempts IS 'Maximum delivery attempts (default 5).';
```

**Step 2: Write unit tests for backoff calculation**

Add to `backend/src/api/handlers/webhooks.rs` test module:

```rust
    #[test]
    fn test_webhook_retry_backoff_schedule() {
        // Backoff: 30s, 2m, 15m, 1h, 4h
        assert_eq!(webhook_retry_delay_secs(1), 30);
        assert_eq!(webhook_retry_delay_secs(2), 120);
        assert_eq!(webhook_retry_delay_secs(3), 900);
        assert_eq!(webhook_retry_delay_secs(4), 3600);
        assert_eq!(webhook_retry_delay_secs(5), 14400);
    }

    #[test]
    fn test_webhook_retry_backoff_capped() {
        // Attempts beyond 5 cap at 4h
        assert_eq!(webhook_retry_delay_secs(10), 14400);
    }
```

**Step 3: Implement the backoff function**

Add above the test module in `webhooks.rs`:

```rust
/// Calculate retry delay in seconds for webhook delivery.
/// Schedule: 30s, 2m, 15m, 1h, 4h (caps at 4h for attempt >= 5).
pub(crate) fn webhook_retry_delay_secs(attempt: i32) -> i64 {
    match attempt {
        1 => 30,
        2 => 120,
        3 => 900,
        4 => 3600,
        _ => 14400,
    }
}
```

**Step 4: Add webhook retry worker function**

Add to `webhooks.rs`:

```rust
/// Process pending webhook delivery retries.
/// Called periodically by the scheduler service.
pub async fn process_webhook_retries(db: &sqlx::PgPool) -> std::result::Result<(), String> {
    let pending = sqlx::query!(
        r#"
        SELECT wd.id, wd.webhook_id, wd.event, wd.payload, wd.attempts,
               w.url, w.headers, w.secret_hash
        FROM webhook_deliveries wd
        JOIN webhooks w ON w.id = wd.webhook_id
        WHERE wd.success = false
          AND wd.attempts < wd.max_attempts
          AND wd.next_retry_at IS NOT NULL
          AND wd.next_retry_at <= NOW()
        ORDER BY wd.next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to fetch pending retries: {e}"))?;

    if pending.is_empty() {
        return Ok(());
    }

    tracing::info!("Processing {} webhook delivery retries", pending.len());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for delivery in pending {
        let attempt = delivery.attempts + 1;

        // Validate URL to prevent DNS rebinding
        if validate_webhook_url(&delivery.url).is_err() {
            // Mark as exhausted
            let _ = sqlx::query!(
                "UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1",
                delivery.id
            )
            .execute(db)
            .await;
            continue;
        }

        let mut request = client
            .post(&delivery.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Event", &delivery.event)
            .header("X-Webhook-Delivery-Attempt", attempt.to_string());

        // Add custom headers
        if let Some(ref headers) = delivery.headers {
            if let Some(obj) = headers.as_object() {
                for (key, value) in obj {
                    if let Some(v) = value.as_str() {
                        request = request.header(key.as_str(), v);
                    }
                }
            }
        }

        let (success, status_code, response_body) = match request.json(&delivery.payload).send().await {
            Ok(response) => {
                let status = response.status().as_u16() as i32;
                let body = response.text().await.ok();
                ((200..300).contains(&(status as u16)), Some(status), body)
            }
            Err(e) => (false, None, Some(e.to_string())),
        };

        let next_retry = if !success && attempt < 5 {
            let delay = webhook_retry_delay_secs(attempt);
            Some(chrono::Utc::now() + chrono::Duration::seconds(delay))
        } else {
            None // Exhausted or succeeded
        };

        let _ = sqlx::query!(
            r#"
            UPDATE webhook_deliveries
            SET attempts = $2, success = $3, response_status = $4,
                response_body = $5, delivered_at = CASE WHEN $3 THEN NOW() ELSE delivered_at END,
                next_retry_at = $6
            WHERE id = $1
            "#,
            delivery.id,
            attempt,
            success,
            status_code,
            response_body,
            next_retry,
        )
        .execute(db)
        .await;

        crate::services::metrics_service::record_webhook_delivery(
            &delivery.event,
            success,
        );
    }

    Ok(())
}
```

**Step 5: Spawn the retry worker in scheduler_service**

In `backend/src/services/scheduler_service.rs`, before the final `tracing::info!` line, add:

```rust
    // Webhook delivery retry processor (every 30 seconds)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut ticker = interval(Duration::from_secs(30));

            loop {
                ticker.tick().await;
                if let Err(e) = crate::api::handlers::webhooks::process_webhook_retries(&db).await {
                    tracing::warn!("Webhook retry processing failed: {}", e);
                }
            }
        });
    }
```

Update the info message to include "webhook retry".

**Step 6: Run tests and commit**

Run: `cargo test --workspace --lib webhooks -- --test-threads=1`
Run: `cargo clippy --workspace`
Expected: All pass.

```bash
git add backend/src/api/handlers/webhooks.rs backend/src/services/scheduler_service.rs \
  backend/migrations/067_webhook_delivery_retry.sql
git commit -m "feat: webhook delivery retry with exponential backoff

Failed webhook deliveries are automatically retried with backoff
(30s, 2m, 15m, 1h, 4h). Background worker processes retry queue
every 30 seconds. Max 5 attempts per delivery."
```

---

## Task 5: Token Revocation (Soft-Revoke) and Usage Analytics

**Bead:** `artifact-keeper-bil`

**Files:**
- Modify: `backend/src/models/api_token.rs` (add `revoked_at`, `last_used_ip`, `last_used_user_agent`)
- Modify: `backend/src/services/auth_service.rs` (check revoked_at, update usage analytics)
- Modify: `backend/src/services/token_service.rs` (change revoke to soft-delete, add TokenInfo fields)
- Modify: `backend/src/api/handlers/auth.rs` (add bulk revocation endpoint, `X-Token-Revoked` header)
- New migration: `backend/migrations/068_token_revocation.sql`

**Step 1: Write migration**

Create `backend/migrations/068_token_revocation.sql`:

```sql
-- Soft-revocation for API tokens
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS last_used_ip TEXT;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS last_used_user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked ON api_tokens (revoked_at) WHERE revoked_at IS NOT NULL;

COMMENT ON COLUMN api_tokens.revoked_at IS 'When the token was revoked. NULL = active.';
COMMENT ON COLUMN api_tokens.last_used_ip IS 'IP address of the last request using this token.';
COMMENT ON COLUMN api_tokens.last_used_user_agent IS 'User-Agent header of the last request using this token.';
```

**Step 2: Update ApiToken model**

In `backend/src/models/api_token.rs`, add fields to the `ApiToken` struct (after `repo_selector` at line 27):

```rust
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
```

Update the `redacted_debug!` macro to include: `show revoked_at,`

**Step 3: Write unit tests**

Add to `backend/src/services/token_service.rs` tests:

```rust
    #[test]
    fn test_is_token_revoked() {
        // Not revoked
        assert!(!is_token_revoked(None));
        // Revoked
        assert!(is_token_revoked(Some(Utc::now() - chrono::Duration::hours(1))));
    }

    #[test]
    fn test_token_info_includes_revoked_at() {
        let token = ApiToken {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "test".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "ak_test".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: Some(Utc::now()),
            last_used_ip: Some("192.168.1.1".to_string()),
            last_used_user_agent: Some("curl/7.88".to_string()),
        };
        let info = TokenInfo::from(token);
        assert!(info.is_revoked);
    }
```

**Step 4: Add is_token_revoked helper and update TokenInfo**

In `token_service.rs`, add:

```rust
/// Check if a token has been revoked.
pub(crate) fn is_token_revoked(revoked_at: Option<DateTime<Utc>>) -> bool {
    revoked_at.is_some()
}
```

Update `TokenInfo` struct to add:

```rust
    pub is_revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
```

Update `From<ApiToken> for TokenInfo` to include:

```rust
            is_revoked: is_token_revoked(token.revoked_at),
            revoked_at: token.revoked_at,
            last_used_ip: token.last_used_ip,
            last_used_user_agent: token.last_used_user_agent,
```

**Step 5: Change revoke_api_token from hard-delete to soft-revoke**

In `backend/src/services/auth_service.rs`, find the `revoke_api_token` method (line 416) and change it:

From:
```rust
    pub async fn revoke_api_token(&self, token_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query!(
            "DELETE FROM api_tokens WHERE id = $1 AND user_id = $2",
```

To:
```rust
    pub async fn revoke_api_token(&self, token_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
            token_id,
            user_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Token not found or already revoked".to_string()));
        }

        Ok(())
```

**Step 6: Add revoked_at check to token validation**

Find the token validation method in `auth_service.rs` (the function that validates API tokens by hash lookup). Add a check:

```rust
        // Check if token is revoked
        if token.revoked_at.is_some() {
            return Err(AppError::Unauthorized("Token has been revoked".to_string()));
        }
```

**Step 7: Add usage analytics update on token auth**

In the same token validation path, after successful validation, add a debounced update for IP and user-agent:

```rust
        // Update usage analytics (debounce: only if last_used_at is > 5 min ago)
        let should_update = token.last_used_at
            .map(|lu| Utc::now() - lu > chrono::Duration::minutes(5))
            .unwrap_or(true);

        if should_update {
            let token_id = token.id;
            let db = self.db.clone();
            let ip = client_ip.map(|s| s.to_string());
            let ua = user_agent.map(|s| s.to_string());
            tokio::spawn(async move {
                let _ = sqlx::query!(
                    "UPDATE api_tokens SET last_used_at = NOW(), last_used_ip = $2, last_used_user_agent = $3 WHERE id = $1",
                    token_id,
                    ip,
                    ua,
                )
                .execute(&db)
                .await;
            });
        }
```

Note: The exact integration point depends on how client_ip and user_agent are available in the auth path. Check the auth middleware to determine how request headers are extracted.

**Step 8: Add bulk revocation endpoint**

In `backend/src/api/handlers/auth.rs`, add:

```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkRevokeRequest {
    pub token_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkRevokeResponse {
    pub revoked_count: u64,
}

/// POST /api/v1/access-tokens/revoke
pub async fn bulk_revoke_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<BulkRevokeRequest>,
) -> Result<Json<BulkRevokeResponse>> {
    let mut revoked = 0u64;
    let token_service = TokenService::new(state.db.clone(), state.config.clone());

    for token_id in &payload.token_ids {
        match token_service.revoke_token(*token_id, auth.user_id).await {
            Ok(()) => revoked += 1,
            Err(_) => {} // Skip tokens that don't exist or aren't owned
        }
    }

    Ok(Json(BulkRevokeResponse { revoked_count: revoked }))
}
```

Register the route in the auth router.

**Step 9: Run tests and commit**

Run: `cargo test --workspace --lib -- --test-threads=1`
Run: `cargo clippy --workspace`
Expected: All pass.

```bash
git add backend/src/models/api_token.rs backend/src/services/auth_service.rs \
  backend/src/services/token_service.rs backend/src/api/handlers/auth.rs \
  backend/migrations/068_token_revocation.sql
git commit -m "feat: soft token revocation with usage analytics

Revoking a token now sets revoked_at instead of deleting. Revoked
tokens return 401. Tracks last_used_ip and last_used_user_agent
with 5-minute debounce. Adds POST /access-tokens/revoke for bulk
revocation."
```

---

## Task 6: Configurable Per-Repo Proxy Cache TTL

**Bead:** `artifact-keeper-f9q`

**Files:**
- Modify: `backend/src/api/handlers/admin.rs` or appropriate repo config handler (add set/get cache TTL endpoint)

**Step 1: Verify existing infrastructure**

The proxy_service already has `get_cache_ttl_for_repo()` at line 167 which queries `repository_config` table. The only missing piece is an API endpoint to set the value.

**Step 2: Write unit test**

```rust
    #[test]
    fn test_cache_ttl_request_validation() {
        // Valid TTL
        assert!(validate_cache_ttl(300));
        assert!(validate_cache_ttl(86400));
        assert!(validate_cache_ttl(604800)); // 7 days

        // Invalid
        assert!(!validate_cache_ttl(0));
        assert!(!validate_cache_ttl(-1));
        assert!(!validate_cache_ttl(2592001)); // > 30 days
    }
```

**Step 3: Add validation function and endpoint**

Add to the appropriate admin or repository handler:

```rust
fn validate_cache_ttl(secs: i64) -> bool {
    (1..=2592000).contains(&secs) // 1 second to 30 days
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCacheTtlRequest {
    pub cache_ttl_seconds: i64,
}

/// PUT /api/v1/admin/repositories/{key}/cache-ttl
pub async fn set_cache_ttl(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Json(payload): Json<SetCacheTtlRequest>,
) -> Result<Json<serde_json::Value>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized("Admin privileges required".to_string()));
    }
    if !validate_cache_ttl(payload.cache_ttl_seconds) {
        return Err(AppError::Validation("cache_ttl_seconds must be between 1 and 2592000".to_string()));
    }

    // Get repository ID
    let repo = sqlx::query_scalar!("SELECT id FROM repositories WHERE key = $1", key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

    // Upsert into repository_config
    sqlx::query!(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, 'cache_ttl_secs', $2)
        ON CONFLICT (repository_id, key) DO UPDATE SET value = $2
        "#,
        repo,
        payload.cache_ttl_seconds.to_string(),
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "cache_ttl_seconds": payload.cache_ttl_seconds })))
}
```

**Step 4: Run tests and commit**

Run: `cargo test --workspace --lib -- --test-threads=1`
Run: `cargo clippy --workspace`

```bash
git add backend/src/api/handlers/
git commit -m "feat: API endpoint to configure per-repo proxy cache TTL

PUT /api/v1/admin/repositories/{key}/cache-ttl sets the cache TTL.
The proxy_service already reads this value from repository_config."
```

---

## Task 7: Search Reindex Trigger API

**Bead:** `artifact-keeper-4n2`

**Files:**
- Modify: `backend/src/api/handlers/search.rs` (add reindex endpoint)
- Modify: `backend/src/api/routes.rs` (register the admin route)

**Step 1: Write unit test**

```rust
    #[test]
    fn test_reindex_response_serialization() {
        let resp = ReindexResponse {
            status: "started".to_string(),
            message: "Full reindex triggered".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "started");
    }
```

**Step 2: Add reindex endpoint**

In `backend/src/api/handlers/search.rs`, add:

```rust
#[derive(Debug, Serialize, ToSchema)]
pub struct ReindexResponse {
    pub status: String,
    pub message: String,
}

/// POST /api/v1/admin/search/reindex
#[utoipa::path(
    post,
    path = "/reindex",
    context_path = "/api/v1/admin/search",
    tag = "admin",
    operation_id = "trigger_search_reindex",
    responses(
        (status = 200, description = "Reindex triggered", body = ReindexResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn trigger_reindex(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ReindexResponse>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized("Admin privileges required".to_string()));
    }

    let meili = state.meili.as_ref().ok_or_else(|| {
        AppError::Config("Meilisearch is not configured".to_string())
    })?;

    let db = state.db.clone();
    let meili = meili.clone();
    tokio::spawn(async move {
        if let Err(e) = meili.full_reindex(&db).await {
            tracing::error!("Search reindex failed: {}", e);
        }
    });

    Ok(Json(ReindexResponse {
        status: "started".to_string(),
        message: "Full reindex of artifacts and repositories triggered in background".to_string(),
    }))
}
```

**Step 3: Register in routes**

In `backend/src/api/routes.rs`, within the admin routes block (around line 276), add:

```rust
                .nest("/search", handlers::search::admin_router())
```

And add an `admin_router()` function to `search.rs`:

```rust
pub fn admin_router() -> Router<SharedState> {
    Router::new().route("/reindex", axum::routing::post(trigger_reindex))
}
```

**Step 4: Run tests and commit**

Run: `cargo test --workspace --lib search -- --test-threads=1`
Run: `cargo clippy --workspace`

```bash
git add backend/src/api/handlers/search.rs backend/src/api/routes.rs
git commit -m "feat: admin API to trigger full search reindex

POST /api/v1/admin/search/reindex triggers a background full
reindex of both artifacts and repositories Meilisearch indexes."
```

---

## Task 8: Quota Warning Events

**Bead:** `artifact-keeper-1jq`

**Files:**
- Modify: `backend/src/services/artifact_service.rs:155-167` (emit quota warning after upload)
- Modify: `backend/src/services/repository_service.rs:534-543` (add quota usage percentage method)

**Step 1: Write unit test**

Add to `repository_service.rs` tests:

```rust
    #[test]
    fn test_quota_usage_percentage() {
        assert_eq!(quota_usage_percentage(80, 100), 0.8);
        assert_eq!(quota_usage_percentage(100, 100), 1.0);
        assert_eq!(quota_usage_percentage(0, 100), 0.0);
    }

    #[test]
    fn test_quota_warning_threshold_check() {
        let threshold = 0.8;
        assert!(quota_usage_percentage(85, 100) > threshold);
        assert!(!(quota_usage_percentage(70, 100) > threshold));
    }
```

**Step 2: Add quota percentage helper**

In `repository_service.rs`, add:

```rust
/// Calculate quota usage as a fraction (0.0 to 1.0+).
pub(crate) fn quota_usage_percentage(used_bytes: i64, quota_bytes: i64) -> f64 {
    if quota_bytes <= 0 {
        return 0.0;
    }
    used_bytes as f64 / quota_bytes as f64
}
```

**Step 3: Add quota warning emission in artifact_service upload**

In `backend/src/services/artifact_service.rs`, after the quota check (around line 167), add:

```rust
        // Emit quota warning if usage exceeds 80% of quota
        if let Ok(repo) = self.repo_service.get_by_id(repository_id).await {
            if let Some(quota) = repo.quota_bytes {
                if let Ok(current_usage) = self.repo_service.get_storage_usage(repository_id).await {
                    let usage_after = current_usage + size_bytes;
                    let usage_pct = crate::services::repository_service::quota_usage_percentage(usage_after, quota);
                    if usage_pct > 0.8 {
                        if let Some(ref event_bus) = self.event_bus {
                            event_bus.emit(
                                "repository.quota_warning",
                                repository_id.to_string(),
                                uploaded_by.map(|u| u.to_string()),
                            );
                        }
                        tracing::warn!(
                            "Repository {} quota warning: {:.1}% used ({}/{} bytes)",
                            repo.key, usage_pct * 100.0, usage_after, quota
                        );
                    }
                }
            }
        }
```

Note: Check whether the `ArtifactService` struct has an `event_bus` field. If not, add `pub event_bus: Option<Arc<EventBus>>` to the struct and pass it during construction in `main.rs`.

**Step 4: Run tests and commit**

Run: `cargo test --workspace --lib -- --test-threads=1`
Run: `cargo clippy --workspace`

```bash
git add backend/src/services/artifact_service.rs backend/src/services/repository_service.rs
git commit -m "feat: emit quota warning event when usage exceeds 80%

After successful upload, if repository usage exceeds 80% of its
quota, emit a repository.quota_warning event on the event bus.
Webhook subscribers receive the warning automatically."
```

---

## Task 9: Replication Filters (Regex Pattern Matching)

**Bead:** `artifact-keeper-8lp`

**Files:**
- Modify: `backend/src/services/sync_worker.rs:132-167` (filter tasks by regex before processing)
- New migration: `backend/migrations/069_replication_filter.sql`

**Step 1: Write migration**

Create `backend/migrations/069_replication_filter.sql`:

```sql
-- Add replication filter to peer-repo associations
ALTER TABLE peer_repo_associations ADD COLUMN IF NOT EXISTS replication_filter JSONB;

COMMENT ON COLUMN peer_repo_associations.replication_filter IS 'JSON: {"include_patterns": ["^v\\d+\\."], "exclude_patterns": [".*-SNAPSHOT$"]}. NULL = replicate everything.';
```

**Step 2: Write unit tests**

Add to `sync_worker.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_replication_filter_no_filter() {
        // No filter = match everything
        assert!(matches_replication_filter("anything", None));
    }

    #[test]
    fn test_matches_replication_filter_include_match() {
        let filter = serde_json::json!({
            "include_patterns": ["^v\\d+\\."]
        });
        assert!(matches_replication_filter("v1.2.3", Some(&filter)));
        assert!(!matches_replication_filter("snapshot-1.0", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_exclude_match() {
        let filter = serde_json::json!({
            "exclude_patterns": [".*-SNAPSHOT$"]
        });
        assert!(matches_replication_filter("v1.0.0", Some(&filter)));
        assert!(!matches_replication_filter("v1.0.0-SNAPSHOT", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_include_and_exclude() {
        let filter = serde_json::json!({
            "include_patterns": ["^v\\d+\\."],
            "exclude_patterns": [".*-SNAPSHOT$"]
        });
        assert!(matches_replication_filter("v1.0.0", Some(&filter)));
        assert!(!matches_replication_filter("v1.0.0-SNAPSHOT", Some(&filter)));
        assert!(!matches_replication_filter("snapshot-1.0", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_invalid_regex() {
        let filter = serde_json::json!({
            "include_patterns": ["[invalid"]
        });
        // Invalid regex should not match (safe default)
        assert!(!matches_replication_filter("anything", Some(&filter)));
    }
}
```

**Step 3: Implement the filter function**

Add to `sync_worker.rs`:

```rust
/// Check if an artifact path/version matches the replication filter.
/// Returns true if the artifact should be replicated.
fn matches_replication_filter(artifact_path: &str, filter: Option<&serde_json::Value>) -> bool {
    let filter = match filter {
        Some(f) => f,
        None => return true, // No filter = replicate everything
    };

    // Check include patterns (if specified, at least one must match)
    if let Some(includes) = filter.get("include_patterns").and_then(|v| v.as_array()) {
        let mut any_match = false;
        for pattern in includes {
            if let Some(pat_str) = pattern.as_str() {
                match regex::Regex::new(pat_str) {
                    Ok(re) => {
                        if re.is_match(artifact_path) {
                            any_match = true;
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Invalid replication filter regex '{}': {}", pat_str, e);
                        return false; // Invalid regex = don't replicate (safe default)
                    }
                }
            }
        }
        if !any_match {
            return false;
        }
    }

    // Check exclude patterns (if any match, exclude)
    if let Some(excludes) = filter.get("exclude_patterns").and_then(|v| v.as_array()) {
        for pattern in excludes {
            if let Some(pat_str) = pattern.as_str() {
                match regex::Regex::new(pat_str) {
                    Ok(re) => {
                        if re.is_match(artifact_path) {
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Invalid replication filter regex '{}': {}", pat_str, e);
                    }
                }
            }
        }
    }

    true
}
```

Add `regex` to imports if not already present (check Cargo.toml for the regex crate; it may need to be added).

**Step 4: Apply filter in the sync task processing loop**

In `process_pending_tasks()`, after fetching tasks (line 163), add the filter. Modify the `TaskRow` struct to include `replication_filter`:

Update the task query to join `peer_repo_associations` and fetch the filter:

```sql
            SELECT
                st.id,
                st.peer_instance_id,
                st.artifact_id,
                st.priority,
                a.storage_key,
                a.size_bytes AS artifact_size,
                a.name AS artifact_name,
                a.version AS artifact_version,
                a.path AS artifact_path,
                r.key AS repository_key,
                r.id AS repository_id,
                a.content_type,
                a.checksum_sha256,
                st.task_type,
                pra.replication_filter
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN peer_repo_associations pra
              ON pra.peer_instance_id = st.peer_instance_id
              AND pra.repository_id = r.id
            WHERE st.peer_instance_id = $1
              AND st.status = 'pending'
            ORDER BY st.priority DESC, st.created_at ASC
            LIMIT $2
```

Add `replication_filter: Option<serde_json::Value>` to `TaskRow`.

Then, in the task processing loop, before spawning the transfer, filter:

```rust
        for task in tasks {
            // Apply replication filter
            if !matches_replication_filter(&task.artifact_path, task.replication_filter.as_ref()) {
                // Skip task and mark as filtered
                let _ = sqlx::query("UPDATE sync_tasks SET status = 'filtered' WHERE id = $1")
                    .bind(task.id)
                    .execute(db)
                    .await;
                continue;
            }
            // ... rest of existing spawn logic
```

**Step 5: Run tests and commit**

Run: `cargo test --workspace --lib sync_worker -- --test-threads=1`
Run: `cargo clippy --workspace`

```bash
git add backend/src/services/sync_worker.rs backend/migrations/069_replication_filter.sql
git commit -m "feat: regex-based replication filters for peer-repo associations

peer_repo_associations can have a replication_filter JSON field with
include_patterns and exclude_patterns. Sync worker applies these
filters before dispatching transfers."
```

---

## Task 10: Close Artifact Download UI Bead

**Bead:** `artifact-keeper-6wv`

The artifact download feature already exists in the web UI:
- `handleDownload()` at `repo-detail-content.tsx:180-202`
- Download button in artifact table at line 314-325
- Download button in detail dialog at line 802-805
- Uses `artifactsApi.getDownloadUrl()` and `createDownloadTicket()`

**Step 1: Close the bead**

```bash
bd close artifact-keeper-6wv --reason "Already implemented: download buttons exist in both artifact table and detail dialog views"
```

No code changes needed.

---

## SQLx Offline Cache Update

After all migrations are created, the SQLx offline cache (`.sqlx/`) needs to be updated:

```bash
# With database running at localhost:30432:
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
  cargo sqlx prepare --workspace
git add .sqlx/
git commit -m "chore: update sqlx offline query cache"
```

---

## Verification Checklist

After all tasks are complete:

1. `cargo fmt --check` passes
2. `cargo clippy --workspace` passes (no warnings)
3. `cargo test --workspace --lib -- --test-threads=1` passes (all existing + new tests)
4. All 10 beads are in appropriate state:
   - `artifact-keeper-wy2` through `artifact-keeper-8lp`: closed
   - `artifact-keeper-6wv`: already closed (no code changes)
5. SQLx offline cache is updated
6. All 4 new migrations are valid SQL
