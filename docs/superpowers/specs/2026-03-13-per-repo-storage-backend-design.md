# Per-Repository Storage Backend Selection

**Date:** 2026-03-13
**GitHub Issue:** [#428](https://github.com/artifact-keeper/artifact-keeper/issues/428)
**Status:** Approved

## Problem

Storage backend selection is currently global: a single `STORAGE_BACKEND` environment variable determines whether all repositories use filesystem, S3, Azure, or GCS. Users want different repos to use different backends. For example, a cache repo on local filesystem (ephemeral, cheap) vs. production artifacts on S3 (durable, replicated).

The database schema already stores `storage_backend` and `storage_path` per repository, but the routing logic ignores the per-repo field and always uses the global config.

## Design Decisions

- **Immutable after creation.** A repo's storage backend is set when the repo is created and cannot be changed. No artifact migration logic.
- **Shared credentials.** All S3 repos share the instance-level S3 bucket and credentials, differentiated by key prefix. Same for Azure and GCS. No per-repo credential management.
- **Reject at creation time.** If a user requests a backend whose credentials are not configured on the instance, the API returns 400. No silent fallback, no deferred failure.
- **Backwards compatible.** New repos default to the global `STORAGE_BACKEND` env var unless the create request explicitly specifies a different backend. Existing repos are unaffected since their `storage_backend` DB field already matches the global setting.

## Architecture

### StorageRegistry

A new struct that holds all initialized backend instances, keyed by type name:

```rust
pub struct StorageRegistry {
    backends: HashMap<String, Arc<dyn StorageBackend>>,
    default_backend: String,
}
```

**Initialization (in main.rs):** At startup, the registry attempts to initialize each backend whose credentials are present in the environment. Filesystem is always available (handled inline by `backend_for()`, not stored in the map). S3/Azure/GCS are added to the map only if their respective env vars (`S3_BUCKET`, `AZURE_CONTAINER_NAME`, `GCS_BUCKET`) are set. The registry logs which backends were initialized at startup for operator visibility.

**Key methods:**

- `backend_for(repo_storage_backend, repo_storage_path) -> Result<Arc<dyn StorageBackend>>`: Returns the correct backend instance. For filesystem, creates a per-repo `FilesystemStorage` using the repo's `storage_path`. For cloud backends, returns the shared instance from the map. Returns an error if the requested backend is not available.
- `is_available(backend) -> bool`: Checks whether a backend type can be used. Filesystem is always available. Cloud backends are available only if initialized in the map. Used during repo creation validation.
- `default_backend() -> &str`: Returns the instance default backend name (from `STORAGE_BACKEND` env var).

**Location:** `backend/src/storage/registry.rs`, re-exported from `backend/src/storage/mod.rs`.

### AppState Changes

`AppState` gains a `storage_registry: Arc<StorageRegistry>` field. The existing `storage: Arc<dyn StorageBackend>` field is kept as the default backend instance.

`storage_for_repo()` changes signature from:

```rust
pub fn storage_for_repo(&self, repo_storage_path: &str) -> Arc<dyn StorageBackend>
```

to:

```rust
pub fn storage_for_repo(&self, repo_storage_backend: &str, repo_storage_path: &str) -> Arc<dyn StorageBackend>
```

The implementation delegates to `storage_registry.backend_for()`, falling back to the default backend on error (defensive, should not happen if creation validation is correct).

### Handler Call Sites

Approximately 94 call sites across 37 handler files change from:

```rust
let storage = state.storage_for_repo(&repo.storage_path);
```

to:

```rust
let storage = state.storage_for_repo(&repo.storage_backend, &repo.storage_path);
```

This is a mechanical change. Every call site already has the `repo` object in scope with both fields available.

### Virtual Repository and Proxy Helper Changes

The `resolve_virtual_download` function in `proxy_helpers.rs` passes `(member_id, storage_path)` to a `local_fetch` callback. The callback signature must change to also receive `storage_backend`:

```rust
// Before: Fn(Uuid, String) -> Fut
// After:  Fn(Uuid, String, String) -> Fut  // (id, storage_backend, storage_path)
```

`fetch_virtual_members()` already queries the full `Repository` struct (including `storage_backend`), so the data is available. The callback signature change propagates to ~31 handler call sites that use `resolve_virtual_download`.

The `local_fetch_by_path`, `local_fetch_by_name_version`, and `local_fetch_by_path_suffix` helper functions in `proxy_helpers.rs` also accept `storage_path: &str` and call `state.storage_for_repo()`. Their signatures change to accept `storage_backend: &str` as an additional parameter.

### Cross-Backend Artifact Promotion

The promotion handler (`promotion.rs`) resolves source and target storage independently:

```rust
let source_storage = state.storage_for_repo(&source_repo.storage_backend, &source_repo.storage_path);
let target_storage = state.storage_for_repo(&target_repo.storage_backend, &target_repo.storage_path);
```

Content is read into memory as `Bytes` and written to the target, so cross-backend promotion (e.g., filesystem to S3) works naturally without special handling. The approval handler follows the same pattern.

### Service Changes

**ScannerService:** Replace `storage_backend_type: String` with `storage_registry: Arc<StorageRegistry>`. Update `resolve_repo_storage()` to query both `storage_backend` and `storage_path` from the DB (currently only queries `storage_path`) and delegate to the registry:

```sql
-- Before:
SELECT storage_path FROM repositories WHERE id = $1

-- After:
SELECT storage_backend, storage_path FROM repositories WHERE id = $1
```

**StorageGcService:** Replace `storage_backend_type: String` with `storage_registry: Arc<StorageRegistry>`. Update `run_gc()` SQL query to also select `r.storage_backend` alongside `r.storage_path` from the joined artifacts/repositories tables. Update `storage_for_path()` to accept the backend type and delegate to the registry.

### Repository Creation

The `CreateRepositoryRequest` HTTP payload gains an optional field:

```rust
pub storage_backend: Option<String>,  // "filesystem", "s3", "azure", "gcs"
```

Validation logic in the create handler:

1. If `storage_backend` is `None`, use `config.storage_backend` (the instance default).
2. If provided, validate against `storage_registry.is_available(backend)`. Return 400 if unavailable.
3. Compute `storage_path`:
   - Filesystem: `{config.storage_path}/{repo_key}`
   - Cloud: `{repo_key}` (key prefix within the shared bucket/container)

The `UpdateRepositoryRequest` does not accept `storage_backend`. Immutable after creation.

### CachedRepo Changes

The `CachedRepo` struct (used by repo-visibility middleware) gains a `storage_backend: String` field so handlers can access it without a DB round-trip when using the cache.

The following locations that construct `CachedRepo` must be updated to populate the new field:

1. **Auth middleware** (`backend/src/api/middleware/auth.rs`): The DB query that populates `CachedRepo` must add `SELECT r.storage_backend`.
2. **Cargo handler** (`backend/src/api/handlers/cargo.rs`): Manual cache population must include `storage_backend`.

### OpenAPI/utoipa

- Add `storage_backend` field to the `CreateRepositoryRequest` schema with enum constraint (`filesystem`, `s3`, `azure`, `gcs`).
- Document it as optional, defaulting to the instance setting.
- Add a new `GET /api/v1/system/storage-backends` endpoint that returns the list of available backends on the instance. This lets the UI show a dropdown during repo creation. Accessible to any authenticated user (not admin-only).

## Testing

**Unit tests (no database):**

- `StorageRegistry::backend_for()` returns correct backend type for each variant
- `StorageRegistry::is_available()` returns true for configured backends, false for unconfigured
- `StorageRegistry::backend_for()` returns error for unavailable backend
- `storage_for_repo()` routes correctly based on repo's `storage_backend` field

**Existing test compatibility:**

All existing tests use `storage_backend = "filesystem"` (the default). Filesystem routing is unchanged (still creates per-repo `FilesystemStorage` instances), so existing tests pass without modification.

**Integration tests:**

- Create a repo with explicit `storage_backend: "filesystem"`, verify artifacts are stored in the expected directory
- Attempt to create a repo with an unavailable backend, verify 400 response
- Verify default backend is applied when `storage_backend` is omitted
- Cross-backend promotion: promote an artifact between repos with different backends, verify content integrity

## Files Changed

| File | Change |
|------|--------|
| `backend/src/storage/registry.rs` | New: `StorageRegistry` struct |
| `backend/src/storage/mod.rs` | Re-export `StorageRegistry` |
| `backend/src/main.rs` | Build `StorageRegistry` at startup |
| `backend/src/api/mod.rs` | Add `storage_registry` to `AppState`, update `storage_for_repo()`, add `storage_backend` to `CachedRepo` |
| `backend/src/api/handlers/repositories.rs` | Validate `storage_backend` on create, add system endpoint |
| `backend/src/api/handlers/proxy_helpers.rs` | Update `resolve_virtual_download` callback signature, update `local_fetch_*` helper signatures |
| `backend/src/api/handlers/*.rs` (~37 files, ~94 call sites) | Update `storage_for_repo()` call sites |
| `backend/src/api/middleware/auth.rs` | Add `storage_backend` to `CachedRepo` DB query and construction |
| `backend/src/api/handlers/cargo.rs` | Add `storage_backend` to manual `CachedRepo` population |
| `backend/src/services/scanner_service.rs` | Use `StorageRegistry`, update `resolve_repo_storage()` SQL to select both columns |
| `backend/src/services/storage_gc_service.rs` | Use `StorageRegistry`, update `run_gc()` SQL to select `storage_backend` |

## Non-Goals

- Per-repo credentials or bucket configuration. All repos sharing a backend type share the instance-level credentials and bucket.
- Changing a repo's backend after creation (artifact migration).
- UI changes. The frontend can use the new system endpoint to populate a dropdown, but UI work is out of scope for this spec.
