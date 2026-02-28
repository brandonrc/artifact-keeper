# Quality of Life Improvements Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address the most common pain points in the artifact registry space by hardening Artifact Keeper's storage cleanup, proxy resilience, replication, webhook reliability, token lifecycle, and observability.

**Architecture:** All changes build on existing services (lifecycle_service, proxy_service, sync_worker, event_bus, token_service, metrics_service). No new crates or major architectural shifts. Each improvement is scoped to one or two files with corresponding unit tests and E2E coverage.

**Tech Stack:** Rust (backend), Next.js/TypeScript (web), PostgreSQL, Meilisearch, Prometheus

**Quality Gates:**
- Code coverage: 80%+ (currently 62.2%)
- Duplication: <3% (currently 6.6%)
- Every feature ships with unit tests and E2E test updates

---

## Theme 1: Storage and Cleanup Automation

### 1.1 Scheduled GC and Lifecycle Execution

**Problem:** GC and lifecycle policies exist but must be triggered manually via API. Production deployments need automated, scheduled execution.

**Approach:**
- Add a `cron_schedule` field to `LifecyclePolicy` (optional, default NULL = manual only)
- Add a background task in `lifecycle_service.rs` that checks for due policies every 60 seconds
- Use the existing `cron` crate (already in Cargo.toml) to parse schedule expressions
- GC gets a system-level schedule in config: `GC_SCHEDULE` env var (default: daily at 2am UTC)
- Both respect existing dry-run and priority mechanisms

**Files:**
- Modify: `backend/src/services/lifecycle_service.rs`
- Modify: `backend/src/services/storage_gc_service.rs`
- Modify: `backend/src/config.rs`
- Migration: Add `cron_schedule` column to `lifecycle_policies`

### 1.2 GC Progress and Reclaimable Space Estimation

**Problem:** No visibility into how much space can be reclaimed before running GC, or progress during execution.

**Approach:**
- Add `GET /api/v1/admin/storage-gc/estimate` endpoint that runs the orphan detection query in read-only mode and returns estimated reclaimable bytes
- During GC execution, update a progress record (items processed / total, bytes freed so far) queryable via `GET /api/v1/admin/storage-gc/status`
- Emit SSE events on the existing event bus for real-time progress

**Files:**
- Modify: `backend/src/api/handlers/storage_gc.rs`
- Modify: `backend/src/services/storage_gc_service.rs`

### 1.3 Quota Warnings

**Problem:** Only hard quota enforcement exists. No advance warning before hitting the limit.

**Approach:**
- Add `quota_warning_threshold` to repository config (default: 0.8 = 80%)
- On artifact upload, after successful quota check, if usage > threshold, emit a `QuotaWarning` event on the event bus
- Webhook subscribers receive the warning automatically via existing webhook infrastructure
- Include current usage and quota in the event payload

**Files:**
- Modify: `backend/src/services/artifact_service.rs`
- Modify: `backend/src/services/event_bus.rs`
- Migration: Add `quota_warning_threshold` column to `repositories`

---

## Theme 2: Proxy and Remote Repository Resilience

### 2.1 Serve Stale Cache When Upstream Is Down

**Problem:** Proxy repos fail when upstream is unreachable. Cached content should be served with a warning header.

**Approach:**
- In `proxy_service.rs`, when upstream fetch fails (timeout, connection refused, 5xx), check if a cached copy exists regardless of TTL expiry
- If stale cache exists, serve it with `X-Cache: STALE` and `Warning: 110 "Response is stale"` headers
- Log a warning-level event for monitoring
- Add `stale_if_error` boolean to remote repo config (default: true)

**Files:**
- Modify: `backend/src/services/proxy_service.rs`
- Modify: `backend/src/api/handlers/proxy_helpers.rs`
- Migration: Add `stale_if_error` column to `repositories`

### 2.2 Configurable Per-Repo Cache TTL

**Problem:** Cache TTL is hardcoded to 24 hours.

**Approach:**
- Add `cache_ttl_seconds` field to remote repository config (default: 86400)
- Use this value instead of the hardcoded constant in `proxy_service.rs`

**Files:**
- Modify: `backend/src/services/proxy_service.rs`
- Migration: Add `cache_ttl_seconds` column to `repositories`

### 2.3 Upstream Health Monitoring

**Problem:** No proactive health checking of upstream registries.

**Approach:**
- Add a periodic health check task (configurable interval, default 5 min) that pings each remote repo's upstream URL
- Store health status (healthy/degraded/unreachable) and last check timestamp
- Expose via `GET /api/v1/repositories/{key}/upstream-health`
- Surface in the existing `/health` endpoint under a new `remote_upstreams` check

**Files:**
- Modify: `backend/src/services/proxy_service.rs`
- Modify: `backend/src/api/handlers/health.rs`

### 2.4 Rate Limit Awareness

**Problem:** No backoff when upstream returns 429.

**Approach:**
- Parse `Retry-After` header from upstream 429 responses
- Cache the backoff deadline per upstream URL
- Return stale cache during backoff window (ties into 2.1)
- Log rate limit events for observability

**Files:**
- Modify: `backend/src/services/proxy_service.rs`

---

## Theme 3: Replication Improvements

### 3.1 Deletion Replication

**Problem:** Deletes don't propagate to peers.

**Approach:**
- When an artifact is soft-deleted, enqueue a `SyncTask` with a new `task_type = "delete"` variant
- The sync worker sends a `DELETE /api/v1/artifacts/{id}` to the peer
- Respect existing `replication_mode` config (only replicate deletes if mode allows writes)
- Add `replicate_deletes` boolean to peer-repo association (default: true)

**Files:**
- Modify: `backend/src/services/artifact_service.rs` (enqueue delete task)
- Modify: `backend/src/services/sync_worker.rs` (handle delete task type)
- Modify: `backend/src/models/sync_task.rs` (add Delete variant)
- Migration: Add `replicate_deletes` column, add `task_type` to `sync_tasks`

### 3.2 Replication Filters

**Problem:** No way to filter which artifacts get replicated (regex, semver).

**Approach:**
- Add `replication_filter` JSON field to peer-repo association
- Filter schema: `{ "include_patterns": ["^v\\d+\\."], "exclude_patterns": [".*-SNAPSHOT$"] }`
- Apply filter in sync worker before enqueuing transfer tasks
- Reuse the regex matching from lifecycle policies (already proven)

**Files:**
- Modify: `backend/src/services/sync_worker.rs`
- Modify: `backend/src/api/handlers/sync_policies.rs`
- Migration: Add `replication_filter` column

### 3.3 Exponential Backoff on Sync Failures

**Problem:** No visible backoff strategy for failed sync tasks.

**Approach:**
- Add `retry_count` and `next_retry_at` to `sync_tasks`
- Backoff formula: `min(300, 10 * 2^retry_count)` seconds (10s, 20s, 40s, 80s, 160s, 300s cap)
- Max retries: 10 (configurable)
- After max retries, mark task as `Failed` with final error

**Files:**
- Modify: `backend/src/services/sync_worker.rs`
- Modify: `backend/src/models/sync_task.rs`
- Migration: Add `retry_count`, `next_retry_at` columns

---

## Theme 4: Webhook Reliability

### 4.1 Delivery Retry with Exponential Backoff

**Problem:** Failed webhook deliveries are lost.

**Approach:**
- Add `webhook_deliveries` table: `id, webhook_id, event_id, attempt, status_code, response_body, created_at, next_retry_at`
- On delivery failure (non-2xx or timeout), schedule retry with backoff: 30s, 2m, 15m, 1h, 4h (5 attempts max)
- Background task processes the retry queue

**Files:**
- Modify: `backend/src/api/handlers/webhooks.rs`
- Modify: `backend/src/services/event_bus.rs`
- New migration: `webhook_deliveries` table

### 4.2 Delivery Dashboard and Dead-Letter

**Problem:** No visibility into webhook delivery success/failure rates.

**Approach:**
- `GET /api/v1/webhooks/{id}/deliveries` returns paginated delivery history
- `POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/redeliver` replays a failed delivery
- Deliveries that exhaust retries are kept as dead-letter records (queryable, redeliverable)
- Add `ak_webhook_deliveries_total` and `ak_webhook_delivery_failures_total` metrics

**Files:**
- Modify: `backend/src/api/handlers/webhooks.rs`
- Modify: `backend/src/api/routes.rs`

---

## Theme 5: Token Lifecycle

### 5.1 Token Revocation

**Problem:** No way to invalidate a leaked token before expiry.

**Approach:**
- Add `revoked_at` timestamp to `api_tokens` table
- `DELETE /api/v1/access-tokens/{id}` sets `revoked_at = now()`
- Token validation in `auth_service.rs` checks `revoked_at IS NULL`
- Revoked tokens return 401 with `X-Token-Revoked: true` header for debuggability
- Bulk revocation: `POST /api/v1/access-tokens/revoke` with list of IDs

**Files:**
- Modify: `backend/src/services/token_service.rs`
- Modify: `backend/src/services/auth_service.rs`
- Modify: `backend/src/api/handlers/auth.rs`
- Migration: Add `revoked_at` column

### 5.2 Token Usage Analytics

**Problem:** No tracking of where/how tokens are used.

**Approach:**
- Add `last_used_ip`, `last_used_user_agent` fields to `api_tokens`
- Update on each successful token authentication (debounce: at most once per 5 minutes to avoid write amplification)
- `GET /api/v1/access-tokens/{id}` response includes usage metadata

**Files:**
- Modify: `backend/src/services/auth_service.rs`
- Modify: `backend/src/models/api_token.rs`
- Migration: Add `last_used_ip`, `last_used_user_agent` columns

---

## Theme 6: Search Enhancements

### 6.1 Reindex Trigger API

**Problem:** No admin endpoint to force a full search reindex.

**Approach:**
- `POST /api/v1/admin/search/reindex` triggers a full reindex of both `artifacts` and `repositories` indexes
- Returns a job ID for progress tracking
- Reuses existing `bulk_index_*` methods in `meili_service.rs`

**Files:**
- Modify: `backend/src/api/handlers/search.rs` (or new admin handler)
- Modify: `backend/src/services/meili_service.rs`

### 6.2 Search Suggestions/Autocomplete

**Problem:** No typeahead endpoint.

**Approach:**
- `GET /api/v1/search/suggest?q=<prefix>` returns top 10 matching artifact names and repo names
- Uses Meilisearch's built-in prefix search (already fast)
- Results grouped by type: `{ artifacts: [...], repositories: [...] }`

**Files:**
- Modify: `backend/src/api/handlers/search.rs`
- Modify: `backend/src/services/search_service.rs`

---

## Theme 7: Monitoring Additions

### 7.1 GC and Lifecycle Metrics

**Problem:** No metrics for cleanup operations.

**Approach:**
- Add `ak_gc_runs_total`, `ak_gc_duration_seconds`, `ak_gc_bytes_reclaimed`
- Add `ak_lifecycle_runs_total`, `ak_lifecycle_items_removed`, `ak_lifecycle_duration_seconds`
- Emit from existing GC and lifecycle service code

**Files:**
- Modify: `backend/src/services/storage_gc_service.rs`
- Modify: `backend/src/services/lifecycle_service.rs`
- Modify: `backend/src/services/metrics_service.rs`

### 7.2 Structured JSON Logging

**Problem:** Ensure structured logs are available for log aggregation.

**Approach:**
- Already have `tracing-subscriber` with JSON feature. Verify the `LOG_FORMAT=json` env var enables JSON output.
- Document in deployment guide.

**Files:**
- Verify: `backend/src/main.rs` (tracing setup)

---

## Theme 8: OCI Compliance Audit

### 8.1 Tag Pagination Compliance

**Problem:** Ensure `/v2/<name>/tags/list` returns correct `Link` headers.

**Approach:**
- Audit the Docker/OCI handler's tag list endpoint
- Ensure `Link: </v2/<name>/tags/list?n=<page_size>&last=<last_tag>>; rel="next"` header is set correctly
- Add E2E test with 100+ tags validating pagination

**Files:**
- Audit/modify: `backend/src/api/handlers/oci.rs`

### 8.2 Large Layer Upload Resilience

**Problem:** Verify chunked uploads handle 1GB+ layers without timeouts.

**Approach:**
- Audit chunk upload handler timeout settings
- Ensure `Content-Range` header processing is correct for resumed uploads
- Add E2E test with a large (500MB+) synthetic layer

**Files:**
- Audit/modify: `backend/src/api/handlers/oci.rs`

---

## Theme 9: Web Frontend Improvements

### 9.1 Artifact Download from Web UI

**Problem:** Users can't download artifacts from the browser.

**Approach:**
- Add a download button to the artifact detail view
- Calls the existing `GET /api/v1/artifacts/{id}/download` endpoint
- Uses `Content-Disposition: attachment` header (already set by backend)

**Files:**
- Modify: `artifact-keeper-web/src/app/(app)/repositories/[key]/artifacts/[id]/page.tsx`

### 9.2 GC/Lifecycle Dashboard

**Problem:** No visibility into cleanup operations from the UI.

**Approach:**
- New page at `/lifecycle` showing:
  - Last GC run results (items removed, bytes freed, duration)
  - Estimated reclaimable space (calls the new estimate endpoint)
  - Lifecycle policy list with last run stats
  - Run GC / Run Policy buttons (dry-run toggle)
- Uses existing sidebar entry (already has "Lifecycle" nav item)

**Files:**
- Modify: `artifact-keeper-web/src/app/(app)/lifecycle/page.tsx`
- New API client: `artifact-keeper-web/src/lib/api/lifecycle.ts`

### 9.3 Guided Setup Wizard

**Problem:** Initial configuration friction for new deployments.

**Approach:**
- Detect first-run state (no repositories, no users beyond admin)
- Show a step-by-step wizard: Create first repo, configure storage, set up access token, optional webhook
- Dismissible, does not block normal navigation
- Stores `setup_completed` in user preferences

**Files:**
- New: `artifact-keeper-web/src/components/setup/setup-wizard.tsx`
- Modify: `artifact-keeper-web/src/app/(app)/page.tsx` (dashboard, show wizard)

---

## Theme 10: Coverage and Duplication

### 10.1 Coverage Push to 80%

**Current:** 62.2% (43,593 uncovered lines of 115,310 coverable)
**Target:** 80% (need to cover ~20,500 additional lines)

**Strategy:**
- Each QoL feature above ships with unit tests (adds coverage naturally)
- Identify the largest uncovered files and add targeted test suites
- Focus on handlers and services with the most uncovered branches

### 10.2 Duplication Reduction to <3%

**Current:** 6.6%
**Target:** <3%

**Strategy:**
- Run SonarCloud duplication report to identify top duplicated blocks
- Extract shared logic into helpers/utilities
- Deduplicate format handler boilerplate (many format handlers share similar patterns)

---

## Dependency Graph

```
Theme 1.1 (Scheduled GC) -- no deps
Theme 1.2 (GC Progress) -- no deps
Theme 1.3 (Quota Warnings) -- no deps
Theme 2.1 (Stale Cache) -- no deps
Theme 2.2 (Cache TTL) -- no deps
Theme 2.3 (Upstream Health) -- no deps
Theme 2.4 (Rate Limit) -- depends on 2.1
Theme 3.1 (Delete Replication) -- no deps
Theme 3.2 (Replication Filters) -- no deps
Theme 3.3 (Sync Backoff) -- no deps
Theme 4.1 (Webhook Retry) -- no deps
Theme 4.2 (Webhook Dashboard) -- depends on 4.1
Theme 5.1 (Token Revocation) -- no deps
Theme 5.2 (Token Analytics) -- no deps
Theme 6.1 (Reindex API) -- no deps
Theme 6.2 (Autocomplete) -- no deps
Theme 7.1 (GC Metrics) -- no deps
Theme 7.2 (JSON Logging) -- no deps
Theme 8.1 (Tag Pagination) -- no deps
Theme 8.2 (Large Upload) -- no deps
Theme 9.1 (Download Button) -- no deps
Theme 9.2 (Lifecycle Dashboard) -- depends on 1.1, 1.2
Theme 9.3 (Setup Wizard) -- no deps
Theme 10.1 (Coverage) -- parallel with all above
Theme 10.2 (Duplication) -- parallel with all above
```
