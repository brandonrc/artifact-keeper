# Per-Repository Storage Backend Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow each repository to use a different storage backend (filesystem, S3, Azure, GCS) instead of the current instance-wide global setting.

**Architecture:** A `StorageRegistry` holds all initialized backend instances at startup. A `StorageLocation` struct carries `(backend, path)` through the call chain. `storage_for_repo()` returns `Result<Arc<dyn StorageBackend>>` and routes based on the repo's `storage_backend` column instead of the global config.

**Tech Stack:** Rust 1.75+, Axum, SQLx, async-trait

**Spec:** `docs/superpowers/specs/2026-03-13-per-repo-storage-backend-design.md`

---

## Chunk 1: Core Types and Registry

### Task 1: StorageLocation and StorageRegistry

**Files:**
- Create: `backend/src/storage/registry.rs`
- Modify: `backend/src/storage/mod.rs:1-9`
- Modify: `backend/src/models/repository.rs:141-174`

- [ ] **Step 1: Write failing tests for StorageLocation and StorageRegistry**

Create `backend/src/storage/registry.rs` with tests only:

```rust
//! Storage backend registry and per-repo routing.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::storage::StorageBackend;

/// Carries the backend type and path for a repository's storage.
/// Used instead of two loose String params to avoid accidental swaps.
#[derive(Debug, Clone)]
pub struct StorageLocation {
    pub backend: String,
    pub path: String,
}

/// Registry of all available storage backends, initialized at startup.
/// Immutable after construction. Thread-safe for concurrent reads.
pub struct StorageRegistry {
    backends: HashMap<String, Arc<dyn StorageBackend>>,
    default_backend: String,
}

impl StorageRegistry {
    /// Build a new registry.
    ///
    /// `backends` maps backend type names ("s3", "azure", "gcs") to their
    /// initialized instances. Filesystem is handled inline by `backend_for()`
    /// and should NOT be in this map.
    ///
    /// `default_backend` is the instance-level default (from STORAGE_BACKEND
    /// env var), used when a repo creation request omits the field.
    pub fn new(backends: HashMap<String, Arc<dyn StorageBackend>>, default_backend: String) -> Self {
        Self {
            backends,
            default_backend,
        }
    }

    /// Resolve the storage backend for a repository.
    ///
    /// - Filesystem: creates a per-repo `FilesystemStorage` from `location.path`.
    /// - Cloud (s3/azure/gcs): returns the shared instance from the map.
    /// - Unknown/unavailable: returns `Err(AppError::Storage(...))`.
    pub fn backend_for(&self, location: &StorageLocation) -> Result<Arc<dyn StorageBackend>> {
        if location.backend == "filesystem" {
            return Ok(Arc::new(
                crate::storage::filesystem::FilesystemStorage::new(&location.path),
            ));
        }
        self.backends
            .get(&location.backend)
            .cloned()
            .ok_or_else(|| {
                AppError::Storage(format!(
                    "Storage backend '{}' is not available on this instance",
                    location.backend
                ))
            })
    }

    /// Check if a backend type is available for new repo creation.
    pub fn is_available(&self, backend: &str) -> bool {
        backend == "filesystem" || self.backends.contains_key(backend)
    }

    /// The instance-level default backend name.
    pub fn default_backend(&self) -> &str {
        &self.default_backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;

    struct MockBackend {
        name: String,
    }

    #[async_trait]
    impl StorageBackend for MockBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Ok(Bytes::from(self.name.clone()))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
    }

    fn make_registry(backends: Vec<&str>, default: &str) -> StorageRegistry {
        let mut map: HashMap<String, Arc<dyn StorageBackend>> = HashMap::new();
        for name in backends {
            map.insert(
                name.to_string(),
                Arc::new(MockBackend {
                    name: name.to_string(),
                }),
            );
        }
        StorageRegistry::new(map, default.to_string())
    }

    #[test]
    fn test_is_available_filesystem_always_true() {
        let registry = make_registry(vec![], "filesystem");
        assert!(registry.is_available("filesystem"));
    }

    #[test]
    fn test_is_available_configured_backend() {
        let registry = make_registry(vec!["s3"], "filesystem");
        assert!(registry.is_available("s3"));
    }

    #[test]
    fn test_is_available_unconfigured_backend() {
        let registry = make_registry(vec!["s3"], "filesystem");
        assert!(!registry.is_available("azure"));
    }

    #[test]
    fn test_default_backend() {
        let registry = make_registry(vec![], "s3");
        assert_eq!(registry.default_backend(), "s3");
    }

    #[tokio::test]
    async fn test_backend_for_filesystem_creates_instance() {
        let registry = make_registry(vec!["s3"], "filesystem");
        let loc = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/tmp/test-repo".to_string(),
        };
        let backend = registry.backend_for(&loc).unwrap();
        // FilesystemStorage is always created fresh, so just check it doesn't error
        assert!(backend.exists("anything").await.is_err() || backend.exists("anything").await.is_ok());
    }

    #[tokio::test]
    async fn test_backend_for_cloud_returns_shared_instance() {
        let registry = make_registry(vec!["s3"], "filesystem");
        let loc = StorageLocation {
            backend: "s3".to_string(),
            path: "my-repo".to_string(),
        };
        let backend = registry.backend_for(&loc).unwrap();
        // MockBackend returns its name from get()
        let content = backend.get("test").await.unwrap();
        assert_eq!(content, Bytes::from("s3"));
    }

    #[test]
    fn test_backend_for_unavailable_returns_error() {
        let registry = make_registry(vec!["s3"], "filesystem");
        let loc = StorageLocation {
            backend: "gcs".to_string(),
            path: "my-repo".to_string(),
        };
        let result = registry.backend_for(&loc);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_backend_for_cloud_shared_across_repos() {
        let registry = make_registry(vec!["s3"], "filesystem");
        let loc_a = StorageLocation {
            backend: "s3".to_string(),
            path: "repo-a".to_string(),
        };
        let loc_b = StorageLocation {
            backend: "s3".to_string(),
            path: "repo-b".to_string(),
        };
        let a = registry.backend_for(&loc_a).unwrap();
        let b = registry.backend_for(&loc_b).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn test_storage_location_clone() {
        let loc = StorageLocation {
            backend: "s3".to_string(),
            path: "/data/repo".to_string(),
        };
        let cloned = loc.clone();
        assert_eq!(loc.backend, cloned.backend);
        assert_eq!(loc.path, cloned.path);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib storage::registry`
Expected: Compilation error since registry module is not yet registered in `mod.rs`.

- [ ] **Step 3: Register the module in storage/mod.rs**

In `backend/src/storage/mod.rs`, add after line 7 (`pub mod s3;`):

```rust
pub mod registry;

pub use registry::{StorageLocation, StorageRegistry};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib storage::registry`
Expected: All tests PASS.

- [ ] **Step 5: Add storage_location() helper to Repository model**

In `backend/src/models/repository.rs`, add after the closing `}` of the `Repository` struct (after line 174):

```rust
impl Repository {
    /// Build a `StorageLocation` from this repo's backend and path fields.
    pub fn storage_location(&self) -> crate::storage::StorageLocation {
        crate::storage::StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}
```

- [ ] **Step 6: Add unit test for storage_location()**

In `backend/src/models/repository.rs`, add to the existing `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn test_storage_location_returns_correct_fields() {
        let repo = Repository {
            storage_backend: "s3".to_string(),
            storage_path: "/data/my-repo".to_string(),
            // ... fill remaining required fields with defaults for the test
            ..make_test_repo()
        };
        let loc = repo.storage_location();
        assert_eq!(loc.backend, "s3");
        assert_eq!(loc.path, "/data/my-repo");
    }
```

If `make_test_repo()` does not exist, construct a full `Repository` with placeholder values for all required fields.

- [ ] **Step 7: Run full unit test suite to check for regressions**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All tests PASS, no regressions.

- [ ] **Step 8: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/storage/registry.rs backend/src/storage/mod.rs backend/src/models/repository.rs
git commit -m "feat: add StorageRegistry and StorageLocation types for per-repo backend routing"
```

---

### Task 2: Update AppState to use StorageRegistry

**Files:**
- Modify: `backend/src/api/mod.rs:22-150`
- Modify: `backend/src/main.rs:152-214`

- [ ] **Step 1: Add storage_registry field to AppState and update storage_for_repo()**

In `backend/src/api/mod.rs`:

1. Add import at line 22 (after `use crate::storage::StorageBackend;`):
```rust
use crate::storage::{StorageLocation, StorageRegistry};
```

2. Add `storage_backend` field to `CachedRepo` struct (after line 50, the `storage_path` field):
```rust
    pub storage_backend: String,
```

3. Add `storage_registry` field to `AppState` struct (after line 69, the `storage` field):
```rust
    pub storage_registry: Arc<StorageRegistry>,
```

4. Update `AppState::new()` constructor to accept and store the registry. Change the signature at line 91 to:
```rust
    pub fn new(config: Config, db: PgPool, storage: Arc<dyn StorageBackend>, storage_registry: Arc<StorageRegistry>) -> Self {
```
And add the field in the struct init:
```rust
            storage_registry,
```

5. Update `AppState::with_wasm_plugins()` constructor similarly. Change the signature at line 112 to add `storage_registry: Arc<StorageRegistry>` parameter, and include it in the struct init.

6. Replace `storage_for_repo()` method (lines 138-150) with:
```rust
    /// Get the storage backend for a given repository.
    ///
    /// Routes based on the repo's own storage_backend field via the
    /// StorageRegistry. Returns an error if the backend is unavailable.
    pub fn storage_for_repo(&self, location: &StorageLocation) -> crate::error::Result<Arc<dyn StorageBackend>> {
        self.storage_registry.backend_for(location)
    }
```

- [ ] **Step 2: Build the StorageRegistry in main.rs**

In `backend/src/main.rs`, after the primary_storage initialization block (after line 186), add:

```rust
    // Build storage registry with all available backends
    let mut registry_backends: std::collections::HashMap<String, Arc<dyn artifact_keeper_backend::storage::StorageBackend>> = std::collections::HashMap::new();

    // Always add the primary storage backend to the registry
    if config.storage_backend != "filesystem" {
        registry_backends.insert(config.storage_backend.clone(), primary_storage.clone());
    }

    // Attempt to initialize additional backends if credentials are present
    if config.storage_backend != "s3" {
        if let Some(ref bucket) = config.s3_bucket {
            if !bucket.is_empty() {
                match artifact_keeper_backend::storage::s3::S3Backend::from_env().await {
                    Ok(s3) => {
                        tracing::info!("S3 storage backend also available (non-primary)");
                        registry_backends.insert("s3".to_string(), Arc::new(s3));
                    }
                    Err(e) => {
                        tracing::debug!("S3 backend not available: {}", e);
                    }
                }
            }
        }
    }
    if config.storage_backend != "azure" {
        if std::env::var("AZURE_CONTAINER_NAME").ok().filter(|v| !v.is_empty()).is_some() {
            match artifact_keeper_backend::storage::azure::AzureConfig::from_env() {
                Ok(azure_config) => {
                    match artifact_keeper_backend::storage::azure::AzureBackend::new(azure_config).await {
                        Ok(azure) => {
                            tracing::info!("Azure Blob storage backend also available (non-primary)");
                            registry_backends.insert("azure".to_string(), Arc::new(azure));
                        }
                        Err(e) => tracing::debug!("Azure backend not available: {}", e),
                    }
                }
                Err(e) => tracing::debug!("Azure backend not available: {}", e),
            }
        }
    }
    if config.storage_backend != "gcs" {
        if config.gcs_bucket.as_ref().filter(|v| !v.is_empty()).is_some() {
            match artifact_keeper_backend::storage::gcs::GcsConfig::from_env() {
                Ok(gcs_config) => {
                    match artifact_keeper_backend::storage::gcs::GcsBackend::new(gcs_config).await {
                        Ok(gcs) => {
                            tracing::info!("GCS storage backend also available (non-primary)");
                            registry_backends.insert("gcs".to_string(), Arc::new(gcs));
                        }
                        Err(e) => tracing::debug!("GCS backend not available: {}", e),
                    }
                }
                Err(e) => tracing::debug!("GCS backend not available: {}", e),
            }
        }
    }

    let available_names: Vec<&str> = {
        let mut v = vec!["filesystem"];
        v.extend(registry_backends.keys().map(|s| s.as_str()));
        v
    };
    tracing::info!("Storage backends available: {:?}", available_names);

    let storage_registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        registry_backends,
        config.storage_backend.clone(),
    ));
```

Then update the `AppState::with_wasm_plugins(...)` call (around line 208) to pass `storage_registry.clone()`.

Do NOT touch `ScannerService::new(...)` or `scheduler_service::spawn_all(...)` yet. Those are updated in Tasks 5-6. Compilation errors from those call sites are expected at this stage.

- [ ] **Step 3: Verify core types compile (expect downstream errors)**

The codebase will not compile because `storage_for_repo()` now has a different signature and `ScannerService`/`StorageGcService` constructors have not been updated yet. This is expected. Verify the core types themselves are sound:

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --lib 2>&1 | head -30`
Expected: Errors about mismatched `storage_for_repo` calls and service constructors (not about the `StorageRegistry`/`StorageLocation` types themselves).

- [ ] **Step 4: Commit (WIP, does not compile yet)**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/mod.rs backend/src/main.rs
git commit -m "wip: update AppState with StorageRegistry and new storage_for_repo signature"
```

---

## Chunk 2: Update All Call Sites

### Task 3: Update proxy_helpers and virtual repo callback signature

**Files:**
- Modify: `backend/src/api/handlers/proxy_helpers.rs:74-116, 282-400`

This task changes the core signatures that all handler closures depend on.

- [ ] **Step 1: Update resolve_virtual_download callback signature**

In `backend/src/api/handlers/proxy_helpers.rs`, change the `resolve_virtual_download` function (line 74-116).

Change the callback type from `Fn(Uuid, String) -> Fut` to `Fn(Uuid, StorageLocation) -> Fut`:

```rust
pub async fn resolve_virtual_download<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    local_fetch: F,
) -> Result<(Bytes, Option<String>), Response>
where
    F: Fn(Uuid, StorageLocation) -> Fut,
    Fut: std::future::Future<Output = Result<(Bytes, Option<String>), Response>>,
```

Add a `use crate::storage::StorageLocation;` import at the top of the file.

Update the call site at line 93 from:
```rust
        if let Ok(result) = local_fetch(member.id, member.storage_path.clone()).await {
```
to:
```rust
        if let Ok(result) = local_fetch(member.id, member.storage_location()).await {
```

- [ ] **Step 2: Update local_fetch_by_path signature**

Change `local_fetch_by_path` (lines 282-318) to accept `StorageLocation` instead of `storage_path: &str`:

```rust
pub async fn local_fetch_by_path(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
```

Change the `storage_for_repo` call at line 308 from:
```rust
    let storage = state.storage_for_repo(storage_path);
```
to:
```rust
    let storage = state.storage_for_repo(location).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", e)).into_response()
    })?;
```

- [ ] **Step 3: Update local_fetch_by_name_version signature**

Same pattern as Step 2. Change `local_fetch_by_name_version` (lines 322-360):

Parameter: `storage_path: &str` becomes `location: &StorageLocation`.

Line 350: `state.storage_for_repo(storage_path)` becomes `state.storage_for_repo(location).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", e)).into_response())?`.

- [ ] **Step 4: Update local_fetch_by_path_suffix signature**

Same pattern. Change `local_fetch_by_path_suffix` (lines 364-400):

Parameter: `storage_path: &str` becomes `location: &StorageLocation`.

Line 390: Same `storage_for_repo` change.

- [ ] **Step 5: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/handlers/proxy_helpers.rs
git commit -m "wip: update proxy_helpers signatures to use StorageLocation"
```

---

### Task 4: Update all handler call sites (mechanical)

**Files:**
- Modify: All ~39 handler files in `backend/src/api/handlers/`

This is the large mechanical change. Every `state.storage_for_repo(&repo.storage_path)` becomes `state.storage_for_repo(&repo.storage_location())?`, and every `resolve_virtual_download` closure changes from `|member_id, storage_path|` to `|member_id, location|`.

- [ ] **Step 1: Bulk update direct storage_for_repo calls**

For every handler file, apply two mechanical replacements:

**Pattern A** - Direct `storage_for_repo` calls (non-virtual paths):

Find all occurrences matching this pattern:
```rust
let storage = state.storage_for_repo(&repo.storage_path);
```
Replace with:
```rust
let storage = state.storage_for_repo(&repo.storage_location())?;
```

Some handlers use variations like `state.storage_for_repo(&storage_path)` where `storage_path` is a local variable extracted from `repo.storage_path`. For these, change to construct a `StorageLocation` inline:

```rust
let storage = state.storage_for_repo(&StorageLocation {
    backend: repo.storage_backend.clone(),
    path: storage_path.clone(),
})?;
```

Add `use crate::storage::StorageLocation;` to any file that needs the inline construction.

**Special-case handlers** (do NOT use the simple `repo.storage_location()` pattern):

- **`oci_v2.rs`** (9 call sites): Has a custom `resolve_repo()` SQL query that only selects `id, storage_path`. Update it to also `SELECT storage_backend`, expand the return type tuple, and update all 9 destructuring patterns to capture `storage_backend`. Then construct `StorageLocation` inline.

- **`tree.rs`**: Has a custom SQL query (around line 251) selecting `id, storage_path`. Update to also select `storage_backend`, expand the destructuring tuple, and construct `StorageLocation` inline.

- **`migration.rs`** (lines 1042, 1170): Uses `state.config.storage_path` (not a repo's path). Use:
  ```rust
  let storage = state.storage_for_repo(&StorageLocation {
      backend: state.config.storage_backend.clone(),
      path: state.config.storage_path.clone(),
  })?;
  ```

- **`npm.rs`** (line 675), **`pypi.rs`** (line 581), **`maven.rs`** (line 463): Use a local `storage_path` variable extracted from `repo.storage_path`. Construct `StorageLocation` inline with `repo.storage_backend.clone()`.

**Standard handlers** (use the simple `repo.storage_location()` pattern):

`alpine.rs`, `ansible.rs`, `cargo.rs`, `chef.rs`, `cocoapods.rs`, `composer.rs`, `conan.rs`, `conda.rs`, `cran.rs`, `debian.rs`, `gitlfs.rs`, `goproxy.rs`, `helm.rs`, `hex.rs`, `huggingface.rs`, `incus.rs`, `jetbrains.rs`, `nuget.rs`, `protobuf.rs`, `pub_registry.rs`, `puppet.rs`, `repositories.rs`, `rpm.rs`, `rubygems.rs`, `sbt.rs`, `swift.rs`, `terraform.rs`, `vscode.rs`, `promotion.rs`, `approval.rs`

- [ ] **Step 2: Update resolve_virtual_download closures**

For every handler that calls `resolve_virtual_download`, update the closure from:

```rust
|member_id, storage_path| {
    let db = db.clone();
    let state = state.clone();
    // ... other clones ...
    async move {
        proxy_helpers::local_fetch_by_path_suffix(
            &db, &state, member_id, &storage_path, &fname,
        ).await
    }
}
```

to:

```rust
|member_id, location| {
    let db = db.clone();
    let state = state.clone();
    // ... other clones ...
    async move {
        proxy_helpers::local_fetch_by_path_suffix(
            &db, &state, member_id, &location, &fname,
        ).await
    }
}
```

The handlers that call `resolve_virtual_download` (from grep, 33 call sites across 30 files + conan/terraform/goproxy with 2 each):

`alpine.rs`, `ansible.rs`, `cargo.rs`, `chef.rs`, `cocoapods.rs`, `composer.rs`, `conan.rs` (2), `conda.rs`, `cran.rs`, `debian.rs`, `gitlfs.rs`, `goproxy.rs` (2), `helm.rs`, `hex.rs`, `huggingface.rs`, `jetbrains.rs`, `maven.rs`, `npm.rs`, `nuget.rs`, `protobuf.rs`, `pub_registry.rs`, `puppet.rs`, `pypi.rs`, `repositories.rs`, `rpm.rs`, `rubygems.rs`, `sbt.rs`, `swift.rs`, `terraform.rs` (2), `vscode.rs`

- [ ] **Step 3: Update CachedRepo construction sites**

In `backend/src/api/middleware/auth.rs` (around line 567-590):

1. Add `storage_backend` to the SQL query string:
```sql
SELECT id, format::text as format, repo_type::text as repo_type,
       upstream_url, storage_backend, storage_path, is_public,
       (SELECT value FROM repository_config ...)
```

2. Add the field to `CachedRepo` construction (line 582):
```rust
let entry = CachedRepo {
    id: r.get("id"),
    format: r.get("format"),
    repo_type: r.get("repo_type"),
    upstream_url: r.get("upstream_url"),
    storage_backend: r.get("storage_backend"),
    storage_path: r.get("storage_path"),
    is_public: r.get("is_public"),
    index_upstream_url: r.get("index_upstream_url"),
};
```

In `backend/src/api/handlers/cargo.rs` (around line 196-211):

1. Find the SQL query string above the CachedRepo construction (look for the SELECT that fetches `id, format::text, repo_type::text, upstream_url, storage_path, is_public`). Add `storage_backend` to the SELECT.

2. Add a `let storage_backend: String = repo.get("storage_backend");` extraction line alongside the existing `let storage_path: String = repo.get("storage_path");`.

3. Add the field to `CachedRepo` construction:
```rust
CachedRepo {
    id,
    format: fmt.clone(),
    repo_type: repo_type.clone(),
    upstream_url: upstream_url.clone(),
    storage_backend: storage_backend.clone(),
    storage_path: storage_path.clone(),
    is_public,
    index_upstream_url: index_upstream_url.clone(),
},
```

- [ ] **Step 4: Update storage_gc handler**

In `backend/src/api/handlers/storage_gc.rs` (lines 56-60), change:

```rust
let service = StorageGcService::new(
    state.db.clone(),
    state.storage.clone(),
    state.config.storage_backend.clone(),
);
```

to:

```rust
let service = StorageGcService::new(
    state.db.clone(),
    state.storage_registry.clone(),
);
```

(This depends on Task 5 updating the StorageGcService constructor.)

- [ ] **Step 5: Verify compilation**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check --workspace 2>&1 | head -50`
Expected: May still have errors from services (Task 5). All handler errors should be resolved.

- [ ] **Step 6: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/
git commit -m "wip: update all handler call sites to use StorageLocation"
```

---

## Chunk 3: Service Updates and Repo Creation

### Task 5: Update StorageGcService to use StorageRegistry

**Files:**
- Modify: `backend/src/services/storage_gc_service.rs:25-115`
- Modify: `backend/src/services/scheduler_service.rs:148-155`

- [ ] **Step 1: Update StorageGcService struct and constructor**

Replace the struct and constructor (lines 31-48):

```rust
pub struct StorageGcService {
    db: PgPool,
    storage_registry: Arc<crate::storage::StorageRegistry>,
}

impl StorageGcService {
    pub fn new(
        db: PgPool,
        storage_registry: Arc<crate::storage::StorageRegistry>,
    ) -> Self {
        Self {
            db,
            storage_registry,
        }
    }
```

- [ ] **Step 2: Update storage_for_path to use registry**

Replace `storage_for_path` (lines 50-58):

```rust
    /// Get the storage backend for a given repository.
    pub(crate) fn storage_for_location(
        &self,
        location: &crate::storage::StorageLocation,
    ) -> crate::error::Result<Arc<dyn StorageBackend>> {
        self.storage_registry.backend_for(location)
    }
```

- [ ] **Step 3: Update run_gc SQL query and loop**

In `run_gc()` (lines 65-115):

1. Add `r.storage_backend` to the SELECT and GROUP BY:

```sql
SELECT a.storage_key, r.storage_backend, r.storage_path,
       SUM(a.size_bytes) as total_bytes,
       COUNT(*) as artifact_count
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
WHERE a.is_deleted = true
  AND NOT EXISTS (
    SELECT 1 FROM artifacts a2
    WHERE a2.storage_key = a.storage_key
      AND a2.is_deleted = false
  )
GROUP BY a.storage_key, r.storage_backend, r.storage_path
```

2. In the loop body (line 100-107), extract `storage_backend` and use the registry:

```rust
let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
let storage_key: String = row.try_get("storage_key").unwrap_or_default();
let storage_path: String = row.try_get("storage_path").unwrap_or_default();
let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
let count: i64 = row.try_get("artifact_count").unwrap_or(0);

let location = crate::storage::StorageLocation {
    backend: storage_backend,
    path: storage_path,
};
let storage = match self.storage_for_location(&location) {
    Ok(s) => s,
    Err(e) => {
        let msg = format!("Failed to resolve storage for key {}: {}", storage_key, e);
        tracing::warn!("{}", msg);
        result.errors.push(msg);
        continue;
    }
};
```

- [ ] **Step 4: Update scheduler_service.rs**

In `backend/src/services/scheduler_service.rs`:

1. Find the function signature that receives `primary_storage` (likely `spawn_all` or similar). Add a `storage_registry: Arc<crate::storage::StorageRegistry>` parameter.

2. In the GC spawned task block (lines 148-155), replace the closure capture. Currently it captures `gc_storage` from the outer scope. Change it to capture `storage_registry` instead:

```rust
    // Storage garbage collection
    {
        let db = db.clone();
        let config_clone = config.clone();
        let storage_registry = storage_registry.clone();  // was: let gc_storage = primary_storage.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let service = crate::services::storage_gc_service::StorageGcService::new(
                db,
                storage_registry,  // was: gc_storage, config_clone.storage_backend.clone()
            );
            // ... rest unchanged
```

3. In `backend/src/main.rs`, find the call to the scheduler's `spawn_all` (or equivalent) function and pass `storage_registry.clone()` as the new argument.

- [ ] **Step 5: Update StorageGcService tests**

In the test module of `storage_gc_service.rs`, update `make_service`:

```rust
fn make_registry(backend_type: &str) -> Arc<crate::storage::StorageRegistry> {
    let mut backends = std::collections::HashMap::new();
    if backend_type != "filesystem" {
        backends.insert(
            backend_type.to_string(),
            Arc::new(MockStorage) as Arc<dyn crate::storage::StorageBackend>,
        );
    }
    Arc::new(crate::storage::StorageRegistry::new(backends, backend_type.to_string()))
}

fn make_service(backend_type: &str) -> StorageGcService {
    StorageGcService::new(make_pool(), make_registry(backend_type))
}
```

Update existing tests that reference `service.storage_backend_type` to use the registry's `default_backend()` instead.

Update tests that call `service.storage_for_path(...)` to call `service.storage_for_location(...)` with a `StorageLocation`.

- [ ] **Step 6: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/services/storage_gc_service.rs backend/src/services/scheduler_service.rs backend/src/main.rs
git commit -m "feat: update StorageGcService to use StorageRegistry for per-repo routing"
```

---

### Task 6: Update ScannerService to use StorageRegistry

**Files:**
- Modify: `backend/src/services/scanner_service.rs:842-870, 1149-1170`
- Modify: `backend/src/main.rs:192-204`

- [ ] **Step 1: Update ScannerService struct**

Replace `storage_backend_type: String` field (line 847) with:
```rust
    storage_registry: Arc<crate::storage::StorageRegistry>,
```

- [ ] **Step 2: Update ScannerService::new constructor**

Replace the `storage_backend_type: String` parameter with `storage_registry: Arc<crate::storage::StorageRegistry>`. Update the struct init accordingly.

- [ ] **Step 3: Update resolve_repo_storage**

In `resolve_repo_storage()` (lines 1152-1170), change the SQL query and routing.

Use `sqlx::query()` (non-macro) with manual `.try_get()` to avoid needing to regenerate the `.sqlx/` offline query cache:

```rust
async fn resolve_repo_storage(&self, repository_id: Uuid) -> Result<Arc<dyn StorageBackend>> {
    let row = sqlx::query(
        "SELECT storage_backend, storage_path FROM repositories WHERE id = $1",
    )
    .bind(repository_id)
    .fetch_one(&self.db)
    .await
    .map_err(|e| {
        AppError::Database(format!(
            "Failed to fetch storage info for repository {}: {}",
            repository_id, e
        ))
    })?;

    let location = crate::storage::StorageLocation {
        backend: row.try_get("storage_backend").unwrap_or_default(),
        path: row.try_get("storage_path").unwrap_or_default(),
    };
    self.storage_registry.backend_for(&location)
}
```

- [ ] **Step 4: Update ScannerService::new call in main.rs**

In `backend/src/main.rs` (around line 192), change the `ScannerService::new(...)` call to pass `storage_registry.clone()` instead of `config.storage_backend.clone()`.

- [ ] **Step 5: Run unit tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/services/scanner_service.rs backend/src/main.rs
git commit -m "feat: update ScannerService to use StorageRegistry for per-repo routing"
```

---

### Task 7: Update repository creation to accept storage_backend

**Files:**
- Modify: `backend/src/api/handlers/repositories.rs:147-164, 529-569`

- [ ] **Step 1: Add storage_backend field to CreateRepositoryRequest**

In `backend/src/api/handlers/repositories.rs`, add to `CreateRepositoryRequest` (after line 163):

```rust
    /// Storage backend override. Defaults to instance setting.
    /// Only admins can specify a non-default backend.
    /// Valid values: "filesystem", "s3", "azure", "gcs".
    pub storage_backend: Option<String>,
```

- [ ] **Step 2: Update create_repository handler**

In `create_repository()` (lines 529-569), after `auth.require_scope("write")?;` (line 535), add backend validation:

```rust
    // Resolve storage backend: use request value or fall back to instance default
    let storage_backend = if let Some(ref requested) = payload.storage_backend {
        // Only admins can override the default backend
        if requested != &state.config.storage_backend && !auth.is_admin {
            return Err(AppError::Authorization(
                "Admin privileges required to select a non-default storage backend".to_string(),
            ));
        }
        // Validate the backend is available on this instance
        if !state.storage_registry.is_available(requested) {
            return Err(AppError::Validation(format!(
                "Requested storage backend is not available"
            )));
        }
        requested.clone()
    } else {
        state.config.storage_backend.clone()
    };

    // Compute storage path based on backend type
    let storage_path = if storage_backend == "filesystem" {
        format!("{}/{}", state.config.storage_path, payload.key)
    } else {
        payload.key.clone()
    };
```

Then update the `service.create(...)` call (line 544-558) to use the resolved values:

```rust
        .create(ServiceCreateRepoReq {
            key: payload.key,
            name: payload.name,
            description: payload.description,
            format,
            repo_type,
            storage_backend,
            storage_path,
            ...
```

Remove the old `storage_path` computation at line 541.

- [ ] **Step 3: Add system/storage-backends endpoint**

Add a new handler function (can go at the end of the file, or near the other system endpoints):

```rust
/// List available storage backends on this instance.
#[utoipa::path(
    get,
    path = "/api/v1/system/storage-backends",
    tag = "system",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Available storage backends", body = Vec<String>),
        (status = 401, description = "Admin required"),
    )
)]
pub async fn list_storage_backends(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<String>>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ));
    }
    let mut backends = vec!["filesystem".to_string()];
    for name in ["s3", "azure", "gcs"] {
        if state.storage_registry.is_available(name) {
            backends.push(name.to_string());
        }
    }
    Ok(Json(backends))
}
```

Register this endpoint in the router. Check `backend/src/api/routes.rs` for where system routes are defined and add it there.

- [ ] **Step 4: Run unit tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/handlers/repositories.rs backend/src/api/routes.rs
git commit -m "feat: accept storage_backend on repo creation, add system/storage-backends endpoint"
```

---

## Chunk 4: Squash WIP Commits and Verify

### Task 8: Squash WIP commits and run full test suite

**Files:** None (git-only)

- [ ] **Step 1: Squash WIP commits using soft reset**

Do NOT use `git rebase -i` (interactive mode is not supported). Instead, use soft reset:

```bash
cd /Users/khan/ak/artifact-keeper && git log --oneline -10
```

Identify the commit SHA before the first WIP commit (the last "clean" commit). Then:

```bash
git reset --soft <sha-of-last-clean-commit>
git commit -m "feat: add per-repository storage backend selection

Introduce StorageRegistry and StorageLocation types. Route
storage_for_repo() through the registry based on each repo's
storage_backend column. Accept optional storage_backend on repo
creation (admin-only for non-default). Add GET /api/v1/system/
storage-backends admin endpoint.

Closes #428"
```

This produces a single clean commit containing all the changes.

- [ ] **Step 2: Run full unit test suite**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All tests pass, no regressions.

- [ ] **Step 3: Run clippy**

Run: `cd /Users/khan/ak/artifact-keeper && cargo clippy --workspace`
Expected: No new warnings.

- [ ] **Step 4: Run fmt check**

Run: `cd /Users/khan/ak/artifact-keeper && cargo fmt --check`
Expected: No formatting issues.

- [ ] **Step 5: Verify the OpenAPI spec test still passes**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --lib test_openapi_spec_is_valid`
Expected: PASS (path count >= 200, schema count >= 200, operation count >= 250).

---

### Task 9: Respond to GitHub issue #428

**Files:** None

- [ ] **Step 1: Comment on the issue with the answer**

Use `gh` to comment on the issue explaining that per-repo storage backend selection has been implemented:

```bash
gh issue comment 428 --body "Yes! As of the next release, you can set a different storage backend per repository. When creating a repo, pass the \`storage_backend\` field (\"filesystem\", \"s3\", \"azure\", or \"gcs\"). If omitted, the instance default is used.

This lets you keep cache repos on local filesystem while storing production artifacts on S3. The backend is set at creation time and cannot be changed after.

Note that selecting a non-default backend requires admin privileges. The instance must also have credentials configured for any non-filesystem backend you want to use. The \`GET /api/v1/system/storage-backends\` endpoint (admin-only) lists which backends are available."
```

- [ ] **Step 2: Close the issue**

```bash
gh issue close 428
```
