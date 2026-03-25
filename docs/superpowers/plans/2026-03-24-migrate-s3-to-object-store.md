# Migrate S3 Backend to object_store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `rust-s3` crate with Apache `object_store` to gain custom CA certificate support and fix issue #567.

**Architecture:** Single-file rewrite of `backend/src/storage/s3.rs`. The `StorageBackend` trait in `mod.rs` and all callers are unchanged. The `S3Backend` struct keeps the same public API but uses `object_store::aws::AmazonS3` internally instead of `s3::bucket::Bucket`.

**Tech Stack:** Rust, `object_store` 0.13 (aws feature), `futures` 0.3 (already in workspace), `reqwest` (transitive)

**Spec:** `docs/superpowers/specs/2026-03-24-migrate-s3-to-object-store-design.md`

**Worktree:** `/Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls/`

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `Cargo.toml` (workspace root) | Swap `rust-s3` for `object_store` |
| Modify | `backend/Cargo.toml` | Update dependency reference |
| Rewrite | `backend/src/storage/s3.rs` | S3 backend implementation (all changes live here) |
| Modify | `.env.example` | Add `S3_CA_CERT_PATH` and `S3_INSECURE_TLS` docs |

No new files created. No other files modified.

---

### Task 1: Swap Dependencies in Cargo.toml

**Files:**
- Modify: `Cargo.toml:44` (workspace deps)
- Modify: `backend/Cargo.toml` (member deps)

- [ ] **Step 1: Replace rust-s3 with object_store in workspace Cargo.toml**

In `Cargo.toml`, replace:
```toml
rust-s3 = { version = "0.37", default-features = false, features = ["tokio-rustls-tls", "fail-on-err"] }
```
With:
```toml
object_store = { version = "0.13", features = ["aws"] }
```

- [ ] **Step 2: Replace rust-s3 with object_store in backend/Cargo.toml**

In `backend/Cargo.toml`, replace:
```toml
rust-s3.workspace = true
```
With:
```toml
object_store.workspace = true
```

Also verify `http` is available as a workspace dep (needed for `http::Method` in presigned URLs). If not present in `backend/Cargo.toml`, add:
```toml
http.workspace = true
```

- [ ] **Step 3: Verify dependency resolves**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo check --workspace 2>&1 | head -20`

Expected: Dependency resolution succeeds, compilation errors from s3.rs (expected since we haven't rewritten it yet). You should see `Compiling object_store` in the output and errors about `s3::bucket::Bucket` not found.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml backend/Cargo.toml Cargo.lock
git commit -m "chore: swap rust-s3 dependency for object_store 0.13"
```

---

### Task 2: Rewrite S3Config with New TLS Fields

**Files:**
- Modify: `backend/src/storage/s3.rs:1-197` (S3Config struct, from_env, builders)

- [ ] **Step 1: Replace imports**

Replace lines 1-36 of `backend/src/storage/s3.rs` (the entire header and imports block) with:

```rust
//! S3 storage backend using the `object_store` crate (Apache Arrow project).
//!
//! Supports AWS S3 and S3-compatible services (MinIO, Ceph RGW, R2, etc.).
//! Configuration via environment variables:
//! - S3_BUCKET: Bucket name (required)
//! - S3_REGION: AWS region (default: us-east-1)
//! - S3_ENDPOINT: Custom endpoint URL for S3-compatible services
//! - S3_ACCESS_KEY_ID: Access key (preferred, falls back to AWS_ACCESS_KEY_ID)
//! - S3_SECRET_ACCESS_KEY: Secret key (preferred, falls back to AWS_SECRET_ACCESS_KEY)
//!
//! For TLS configuration:
//! - S3_CA_CERT_PATH: Path to PEM file with custom CA certificate(s)
//! - S3_INSECURE_TLS: Disable TLS certificate verification (default: false)
//!
//! For redirect downloads (302 to presigned URLs):
//! - S3_REDIRECT_DOWNLOADS: Enable 302 redirects (default: false)
//! - S3_PRESIGN_EXPIRY_SECS: URL expiry in seconds (default: 3600)
//!
//! For CloudFront CDN:
//! - CLOUDFRONT_DISTRIBUTION_URL: CloudFront distribution URL (optional)
//! - CLOUDFRONT_KEY_PAIR_ID: CloudFront key pair ID for signing
//! - CLOUDFRONT_PRIVATE_KEY_PATH: Path to CloudFront private key PEM file
//!
//! For Artifactory migration:
//! - STORAGE_PATH_FORMAT: Storage path format (default: native)
//!   - "native": 2-level sharding {sha[0:2]}/{sha[2:4]}/{sha}
//!   - "artifactory": 1-level sharding {sha[0:2]}/{sha} (JFrog Artifactory format)
//!   - "migration": Write native, read from both (for zero-downtime migration)

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use std::time::Duration;

// Note: `http` crate needed for presigned URL Method type.
// Add `http.workspace = true` to backend/Cargo.toml if not already present.

use super::{PresignedUrl, PresignedUrlSource, StoragePathFormat};
use crate::error::{AppError, Result};
```

- [ ] **Step 2: Rewrite S3Config struct**

Replace the `S3Config` struct (lines 38-61) with:

```rust
/// S3 storage backend configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// Custom endpoint URL (for MinIO compatibility)
    pub endpoint: Option<String>,
    /// Optional key prefix for all objects
    pub prefix: Option<String>,
    /// Enable redirect downloads via presigned URLs
    pub redirect_downloads: bool,
    /// Presigned URL expiry duration
    pub presign_expiry: Duration,
    /// CloudFront configuration (optional)
    pub cloudfront: Option<CloudFrontConfig>,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
    /// Dedicated access key for presigned URL signing (optional)
    pub presign_access_key: Option<String>,
    /// Dedicated secret key for presigned URL signing (optional)
    pub presign_secret_key: Option<String>,
    /// Path to a PEM file containing custom CA certificate(s) for S3 connections
    pub ca_cert_path: Option<String>,
    /// Disable TLS certificate verification (for dev/test with self-signed certs)
    pub insecure_tls: bool,
}
```

- [ ] **Step 3: Rewrite from_env() to include new fields**

In the `from_env()` method, add after the `presign_secret_key` line (line 100):

```rust
        // TLS configuration
        let ca_cert_path = std::env::var("S3_CA_CERT_PATH").ok();
        let insecure_tls = std::env::var("S3_INSECURE_TLS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
```

And add to the `Ok(Self { ... })` return:
```rust
            ca_cert_path,
            insecure_tls,
```

- [ ] **Step 4: Update S3Config::new() and add builder methods**

In `S3Config::new()` (around line 154-172), add the new fields with defaults:

```rust
            ca_cert_path: None,
            insecure_tls: false,
```

Add two new builder methods after the existing `with_cloudfront`:

```rust
    /// Set custom CA certificate path
    pub fn with_ca_cert_path(mut self, path: String) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    /// Enable insecure TLS (skip certificate verification)
    pub fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }
```

- [ ] **Step 5: Verify compilation of config changes**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo check --workspace 2>&1 | grep "error" | head -10`

Expected: Errors only about `Bucket`, `Credentials`, `Region`, `S3Error`, `ResponseData` types in the implementation section (not in S3Config).

- [ ] **Step 6: Commit**

```bash
git add backend/src/storage/s3.rs
git commit -m "refactor: rewrite S3Config imports and add TLS config fields"
```

---

### Task 3: Rewrite S3Backend Struct and Constructor

**Files:**
- Modify: `backend/src/storage/s3.rs:199-320` (S3Backend struct, new(), from_env(), helpers)

- [ ] **Step 1: Rewrite the S3Backend struct**

Replace the `S3Backend` struct (lines 199-218) with:

```rust
/// S3-compatible storage backend
pub struct S3Backend {
    store: AmazonS3,
    prefix: Option<String>,
    /// Enable redirect downloads via presigned URLs
    redirect_downloads: bool,
    /// Default presigned URL expiry
    presign_expiry: Duration,
    /// CloudFront configuration (optional)
    cloudfront: Option<CloudFrontConfig>,
    /// Storage path format (for Artifactory compatibility)
    path_format: StoragePathFormat,
    /// Separate AmazonS3 instance with dedicated presign credentials
    signing_store: Option<AmazonS3>,
}
```

- [ ] **Step 2: Write the build_store helper**

Add this function inside the `impl S3Backend` block, before `new()`:

```rust
    /// Build an AmazonS3 instance from config with TLS settings applied.
    fn build_store(config: &S3Config, access_key: Option<&str>, secret_key: Option<&str>) -> Result<AmazonS3> {
        let mut client_opts = object_store::ClientOptions::new();

        // Only allow HTTP when the endpoint explicitly uses it (MinIO dev setups)
        if config.endpoint.as_ref().is_some_and(|e| e.starts_with("http://")) {
            client_opts = client_opts.with_allow_http(true);
        }

        // Custom CA certificate
        if let Some(ca_path) = &config.ca_cert_path {
            let pem = std::fs::read(ca_path)
                .map_err(|e| AppError::Config(format!("Failed to read CA cert '{}': {}", ca_path, e)))?;
            let certs = object_store::Certificate::from_pem_bundle(&pem)
                .map_err(|e| AppError::Config(format!("Invalid CA cert PEM '{}': {}", ca_path, e)))?;
            for cert in certs {
                client_opts = client_opts.with_root_certificate(cert);
            }
            tracing::info!(path = %ca_path, "Loaded custom CA certificate(s) for S3");
        }

        // Insecure TLS (skip all verification)
        if config.insecure_tls {
            client_opts = client_opts.with_allow_invalid_certificates(true);
            tracing::warn!("S3 TLS certificate verification is DISABLED (S3_INSECURE_TLS=true)");
        }

        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_client_options(client_opts);

        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }

        // Use provided credentials, or fall back to env/instance metadata
        if let Some(ak) = access_key {
            if let Some(sk) = secret_key {
                builder = builder
                    .with_access_key_id(ak)
                    .with_secret_access_key(sk);
            }
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("S3_ACCESS_KEY_ID"),
            std::env::var("S3_SECRET_ACCESS_KEY"),
        ) {
            tracing::info!("Using S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY for S3 credentials");
            builder = builder
                .with_access_key_id(&ak)
                .with_secret_access_key(&sk);
        }
        // If no explicit creds, AmazonS3Builder falls through to AWS_ACCESS_KEY_ID,
        // instance metadata, IRSA, EKS Pod Identity, etc.

        builder.build().map_err(|e| AppError::Config(format!("Failed to build S3 client: {}", e)))
    }
```

- [ ] **Step 3: Rewrite S3Backend::new()**

Replace the current `new()` method (lines 221-314) with:

```rust
    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        let store = Self::build_store(&config, None, None)?;

        // Build dedicated signing store if explicit presign credentials are provided
        let signing_store = match (&config.presign_access_key, &config.presign_secret_key) {
            (Some(ak), Some(sk)) => {
                let ss = Self::build_store(&config, Some(ak), Some(sk))?;
                tracing::info!("Using dedicated credentials for presigned URL signing");
                Some(ss)
            }
            _ => None,
        };

        if config.redirect_downloads {
            tracing::info!(
                bucket = %config.bucket,
                cloudfront = config.cloudfront.is_some(),
                expiry_secs = config.presign_expiry.as_secs(),
                dedicated_signing_creds = signing_store.is_some(),
                "S3 redirect downloads enabled"
            );
        }

        if config.path_format != StoragePathFormat::Native {
            tracing::info!(
                path_format = %config.path_format,
                "S3 storage path format configured"
            );
        }

        Ok(Self {
            store,
            prefix: config.prefix,
            redirect_downloads: config.redirect_downloads,
            presign_expiry: config.presign_expiry,
            cloudfront: config.cloudfront,
            path_format: config.path_format,
            signing_store,
        })
    }

    /// Create S3 backend from environment variables
    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }
```

- [ ] **Step 4: Keep helper methods unchanged**

The following methods stay the same (they only do string operations):
- `full_key()` (line 322-328)
- `strip_prefix()` (line 330-341)
- `try_artifactory_fallback()` (line 343-359)

Remove the following methods that are no longer needed (they matched on HTTP status codes from rust-s3):
- `is_not_found_error()` (line 361-363)
- `is_head_not_found_error()` (line 365-369)
- `classify_put_status()` (line 371-392)
- `classify_get_response()` (line 394-411)
- `classify_get_error_is_not_found()` (line 413-426)
- `classify_head_status()` (line 428-444)
- `classify_delete_status()` (line 446-457)
- `classify_fallback_get_result()` (line 459-493)

Rewrite `try_fallback_get()` (line 495-517) to use object_store:

```rust
    async fn try_fallback_get(&self, key: &str, reason: &'static str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }

        let Some(fallback_key) = self.try_artifactory_fallback(key) else {
            return Ok(None);
        };

        let fallback_full_key = self.full_key(&fallback_key);
        tracing::debug!(
            original = %key,
            fallback = %fallback_key,
            reason,
            "Trying Artifactory fallback path"
        );

        let path: ObjectPath = fallback_full_key.into();
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read fallback '{}': {}", fallback_key, e))
                })?;
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    size = bytes.len(),
                    "Found artifact at Artifactory fallback path"
                );
                Ok(Some(bytes))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get fallback object '{}' for '{}': {}",
                fallback_key, key, e
            ))),
        }
    }
```

- [ ] **Step 5: Commit**

```bash
git add backend/src/storage/s3.rs
git commit -m "refactor: rewrite S3Backend struct and constructor for object_store"
```

---

### Task 4: Rewrite StorageBackend Trait Implementation

**Files:**
- Modify: `backend/src/storage/s3.rs:520-808` (trait impl)

- [ ] **Step 1: Rewrite put()**

```rust
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.clone().into();

        self.store
            .put(&path, content.into())
            .await
            .map_err(|e| {
                tracing::error!(key = %key, full_key = %full_key, error = %e, "S3 put_object failed");
                AppError::Storage(format!("Failed to put object '{}': {}", key, e))
            })?;

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }
```

- [ ] **Step 2: Rewrite get()**

```rust
    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read object '{}': {}", key, e))
                })?;
                tracing::debug!(key = %key, size = bytes.len(), "S3 get object successful");
                Ok(bytes)
            }
            Err(object_store::Error::NotFound { .. }) => {
                if let Some(bytes) = self.try_fallback_get(key, "primary not found").await? {
                    return Ok(bytes);
                }
                Err(AppError::NotFound(format!("Storage key not found: {}", key)))
            }
            Err(e) => Err(AppError::Storage(format!("Failed to get object '{}': {}", key, e))),
        }
    }
```

- [ ] **Step 3: Rewrite exists()**

```rust
    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(_) => return Ok(true),
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => {
                return Err(AppError::Storage(format!(
                    "Failed to check existence of '{}': {}",
                    key, e
                )));
            }
        }

        // Primary not found: try Artifactory fallback
        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_full_key = self.full_key(&fallback_key);
                let fallback_path: ObjectPath = fallback_full_key.into();
                match self.store.head(&fallback_path).await {
                    Ok(_) => {
                        tracing::debug!(
                            key = %key,
                            fallback = %fallback_key,
                            "Found artifact at Artifactory fallback path"
                        );
                        return Ok(true);
                    }
                    Err(object_store::Error::NotFound { .. }) => {}
                    Err(e) => {
                        tracing::warn!(
                            key = %key,
                            fallback = %fallback_key,
                            error = %e,
                            "Fallback head_object failed with unexpected error"
                        );
                    }
                }
            }
        }

        Ok(false)
    }
```

- [ ] **Step 4: Rewrite delete()**

```rust
    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        self.store.delete(&path).await.map_err(|e| {
            AppError::Storage(format!("Failed to delete object '{}': {}", key, e))
        })?;

        tracing::debug!(key = %key, "S3 delete object successful");
        Ok(())
    }
```

- [ ] **Step 5: Keep supports_redirect() unchanged**

```rust
    fn supports_redirect(&self) -> bool {
        self.redirect_downloads
    }
```

- [ ] **Step 6: Rewrite get_presigned_url()**

```rust
    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.redirect_downloads {
            return Ok(None);
        }

        let full_key = self.full_key(key);

        // If CloudFront is configured, use CloudFront signed URLs
        if let Some(cf) = &self.cloudfront {
            let url = self.generate_cloudfront_signed_url(cf, &full_key, expires_in)?;
            tracing::debug!(
                key = %key,
                expires_in_secs = expires_in.as_secs(),
                source = "cloudfront",
                "Generated CloudFront signed URL"
            );
            return Ok(Some(PresignedUrl {
                url,
                expires_in,
                source: PresignedUrlSource::CloudFront,
            }));
        }

        // Generate S3 presigned URL
        use object_store::signer::Signer;

        let path: ObjectPath = full_key.into();
        let signer = self.signing_store.as_ref().unwrap_or(&self.store);

        // S3 enforces a maximum presigned URL expiry of 7 days
        let clamped_expiry = Duration::from_secs(expires_in.as_secs().min(604800));

        let presigned_url = signer
            .signed_url(http::Method::GET, &path, clamped_expiry)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to generate presigned URL for '{}': {}",
                    key, e
                ))
            })?;

        tracing::debug!(
            key = %key,
            expires_in_secs = expires_in.as_secs(),
            source = "s3",
            dedicated_creds = self.signing_store.is_some(),
            "Generated S3 presigned URL"
        );

        Ok(Some(PresignedUrl {
            url: presigned_url.to_string(),
            expires_in,
            source: PresignedUrlSource::S3,
        }))
    }
```

- [ ] **Step 7: Rewrite health_check()**

```rust
    async fn health_check(&self) -> Result<()> {
        let path: ObjectPath = ".health-probe".into();
        match self.store.head(&path).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()), // Bucket reachable
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("403") || msg.contains("Access Denied") {
                    Err(AppError::Storage(format!(
                        "S3 health check failed: access denied: {}",
                        e
                    )))
                } else {
                    Err(AppError::Storage(format!("S3 health check failed: {}", e)))
                }
            }
        }
    }
```

- [ ] **Step 8: Commit**

```bash
git add backend/src/storage/s3.rs
git commit -m "refactor: rewrite StorageBackend trait impl for object_store"
```

---

### Task 5: Rewrite Extended S3Backend Methods (list, copy, size)

**Files:**
- Modify: `backend/src/storage/s3.rs:810-958` (list, copy, size, CloudFront, accessors)

- [ ] **Step 1: Rewrite list()**

```rust
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_prefix = match (&self.prefix, prefix) {
            (Some(base), Some(p)) => format!("{}/{}", base.trim_end_matches('/'), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let list_path: ObjectPath = search_prefix.into();
        let objects: Vec<_> = self
            .store
            .list(Some(&list_path))
            .try_collect()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = objects
            .into_iter()
            .map(|meta| self.strip_prefix(meta.location.as_ref()))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }
```

- [ ] **Step 2: Rewrite copy()**

```rust
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        let from: ObjectPath = source_key.into();
        let to: ObjectPath = dest_key.into();

        self.store.copy(&from, &to).await.map_err(|e| {
            AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e))
        })?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }
```

- [ ] **Step 3: Rewrite size()**

```rust
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(meta) => {
                tracing::debug!(key = %key, size = meta.size, "S3 head object successful");
                Ok(meta.size as u64)
            }
            Err(object_store::Error::NotFound { .. }) => {
                Err(AppError::NotFound(format!("Storage key not found: {}", key)))
            }
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get size of '{}': {}",
                key, e
            ))),
        }
    }
```

- [ ] **Step 4: Keep CloudFront and accessor methods unchanged**

`generate_cloudfront_signed_url()`, `redirect_enabled()`, and `default_presign_expiry()` stay exactly as they are (lines 890-958). They use RSA/SHA1 directly, no rust-s3 dependency.

- [ ] **Step 5: Verify compilation**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo check --workspace 2>&1 | tail -10`

Expected: Compilation succeeds (or only test-related errors remain).

- [ ] **Step 6: Commit**

```bash
git add backend/src/storage/s3.rs
git commit -m "refactor: rewrite list/copy/size methods for object_store"
```

---

### Task 6: Rewrite Unit Tests

**Files:**
- Modify: `backend/src/storage/s3.rs:961-1828` (unit tests)

- [ ] **Step 1: Remove rust-s3-specific tests**

Delete all tests that depend on `S3Error`, `ResponseData`, or status code classifiers:
- `test_classify_put_status_*` (8 tests)
- `test_classify_get_response_*` (7 tests)
- `test_classify_get_error_*` (4 tests)
- `test_classify_head_status_*` (6 tests)
- `test_classify_delete_status_*` (5 tests)
- `test_classify_fallback_get_result_*` (7 tests)
- `test_is_not_found_error_*` (2 tests)
- `test_is_head_not_found_error_*` (2 tests)
- `test_status_code_boundary_*` (3 tests)
- `test_classify_*_includes_key_in_error` (4 tests)

These are no longer applicable because object_store uses typed error variants rather than HTTP status codes.

- [ ] **Step 2: Keep all tests that don't depend on rust-s3 types**

Keep unchanged:
- `test_full_key_with_prefix`
- `test_full_key_without_prefix`
- `test_strip_prefix`
- `test_strip_prefix_no_match`
- `test_strip_prefix_none`
- `test_s3_config_new`
- `test_s3_config_with_path_format`
- `test_s3_config_presign_credentials_default_none`
- `test_s3_config_supports_redirect_requires_key`
- `test_s3_config_with_presign_expiry`
- `test_s3_config_with_cloudfront`
- `test_s3_config_default_values`
- `test_s3_config_chained_builders`
- `test_artifactory_fallback_*` (4 tests)
- `test_full_key_trailing_slash_prefix`
- `test_native_format_has_no_fallback`
- `test_artifactory_format_has_no_fallback`
- `test_migration_format_has_fallback`

- [ ] **Step 3: Add new TLS config tests**

```rust
    #[test]
    fn test_s3_config_ca_cert_path_default_none() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_with_ca_cert_path() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_ca_cert_path("/etc/ssl/custom-ca.pem".to_string());
        assert_eq!(config.ca_cert_path, Some("/etc/ssl/custom-ca.pem".to_string()));
    }

    #[test]
    fn test_s3_config_with_insecure_tls() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_insecure_tls(true);
        assert!(config.insecure_tls);
    }

    #[test]
    fn test_s3_config_insecure_tls_default_false() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_chained_builders_with_tls() {
        let config = S3Config::new(
            "bucket".to_string(),
            "us-east-1".to_string(),
            Some("https://s3.internal:9000".to_string()),
            None,
        )
        .with_ca_cert_path("/etc/ssl/internal-ca.pem".to_string())
        .with_insecure_tls(false);

        assert_eq!(config.ca_cert_path, Some("/etc/ssl/internal-ca.pem".to_string()));
        assert!(!config.insecure_tls);
    }
```

- [ ] **Step 4: Update test_s3_config_default_values to include new fields**

Add to the existing `test_s3_config_default_values` test:
```rust
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
```

- [ ] **Step 5: Rewrite integration test**

Replace the `integration_tests` module (lines 1830-1932) with:

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::StorageBackend as StorageBackendTrait;

    /// Integration test for S3 presigned URLs
    /// Run with: S3_BUCKET=your-bucket cargo test s3_presigned --lib -- --ignored --nocapture
    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_presigned_url_generation() {
        let bucket = match std::env::var("S3_BUCKET") {
            Ok(b) => b,
            Err(_) => {
                println!("Skipping: S3_BUCKET not set");
                return;
            }
        };

        println!("Testing with bucket: {}", bucket);

        let config = S3Config::from_env()
            .expect("Failed to load S3 config")
            .with_redirect_downloads(true)
            .with_presign_expiry(Duration::from_secs(300));

        let backend = S3Backend::new(config)
            .await
            .expect("Failed to create S3 backend");

        let test_key = format!(
            "test/presign-test-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let test_content = Bytes::from("Test content for presigned URL");

        println!("Uploading test file: {}", test_key);
        StorageBackendTrait::put(&backend, &test_key, test_content.clone())
            .await
            .expect("Failed to upload test file");

        assert!(StorageBackendTrait::supports_redirect(&backend));

        println!("Generating presigned URL...");
        let presigned =
            StorageBackendTrait::get_presigned_url(&backend, &test_key, Duration::from_secs(300))
                .await
                .expect("Failed to generate presigned URL");

        assert!(presigned.is_some());
        let presigned = presigned.unwrap();
        assert!(presigned.url.contains("X-Amz-Signature"));

        // Verify URL works by downloading
        println!("Verifying presigned URL works...");
        let client = reqwest::Client::new();
        let response = client
            .get(presigned.url.as_str())
            .send()
            .await
            .expect("Failed to fetch presigned URL");
        assert!(response.status().is_success(), "Presigned URL should return 200");

        let body = response.bytes().await.expect("Failed to read body");
        assert_eq!(body.as_ref(), test_content.as_ref(), "Content should match");

        println!("Cleaning up...");
        StorageBackendTrait::delete(&backend, &test_key)
            .await
            .expect("Failed to delete test file");
        println!("Test complete");
    }
}
```

- [ ] **Step 6: Run all unit tests**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo test --workspace --lib 2>&1 | tail -10`

Expected: All tests pass with 0 failures.

- [ ] **Step 7: Commit**

```bash
git add backend/src/storage/s3.rs
git commit -m "test: rewrite S3 unit tests for object_store, add TLS config tests"
```

---

### Task 7: Update .env.example and Run Final Checks

**Files:**
- Modify: `.env.example:47-59`

- [ ] **Step 1: Add new env vars to .env.example**

After the existing S3 vars block (around line 59), add:

```
# S3 TLS Configuration
# S3_CA_CERT_PATH=/etc/ssl/custom-ca.pem  # PEM file with custom CA certificate(s)
# S3_INSECURE_TLS=false                    # Disable TLS verification (dev/test only)
```

- [ ] **Step 2: Run full test suite**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo test --workspace --lib 2>&1 | tail -5`

Expected: All tests pass.

- [ ] **Step 3: Run clippy**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo clippy --workspace 2>&1 | tail -5`

Expected: No warnings.

- [ ] **Step 4: Run fmt check**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo fmt --check`

Expected: No formatting issues.

- [ ] **Step 5: Commit**

```bash
git add .env.example
git commit -m "docs: add S3_CA_CERT_PATH and S3_INSECURE_TLS to .env.example"
```

---

### Task 8: Verify SQLx Offline Cache

**Files:**
- Check: `.sqlx/` directory

- [ ] **Step 1: Verify no SQLx query changes**

This migration only touches storage code, not database queries. Verify no `.sqlx/` files changed:

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && git diff --name-only .sqlx/`

Expected: No output (no SQLx files changed).

- [ ] **Step 2: Run full test suite one final time**

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && cargo test --workspace --lib 2>&1 | tail -5`

Expected: All tests pass with 0 failures.

- [ ] **Step 3: Verify the `http` crate is available for presigned URLs**

The `get_presigned_url` method uses `http::Method::GET`. Verify the `http` crate is in scope:

Run: `cd /Users/khan/ak/artifact-keeper/.worktrees/fix-567-s3-tls && grep -n "^http" Cargo.toml backend/Cargo.toml`

If `http` is not a direct dependency, it comes transitively through `object_store` and `axum`. If `http::Method` doesn't resolve, add `http.workspace = true` to `backend/Cargo.toml` (it's already in the workspace).
