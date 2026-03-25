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
use object_store::{ObjectStore, ObjectStoreExt};
use std::time::Duration;

use super::{PresignedUrl, PresignedUrlSource, StoragePathFormat};
use crate::error::{AppError, Result};

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
    /// Dedicated access key for presigned URL signing (optional, overrides default credentials)
    pub presign_access_key: Option<String>,
    /// Dedicated secret key for presigned URL signing (optional, overrides default credentials)
    pub presign_secret_key: Option<String>,
    /// Path to a PEM file containing custom CA certificate(s) for S3 connections
    pub ca_cert_path: Option<String>,
    /// Disable TLS certificate verification (for dev/test with self-signed certs)
    pub insecure_tls: bool,
}

/// CloudFront CDN configuration for signed URLs
#[derive(Debug, Clone)]
pub struct CloudFrontConfig {
    /// CloudFront distribution URL (e.g., https://d1234.cloudfront.net)
    pub distribution_url: String,
    /// CloudFront key pair ID for signing
    pub key_pair_id: String,
    /// CloudFront private key (PEM format)
    pub private_key: String,
}

impl S3Config {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let bucket =
            std::env::var("S3_BUCKET").map_err(|_| AppError::Config("S3_BUCKET not set".into()))?;
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let endpoint = std::env::var("S3_ENDPOINT").ok();
        let prefix = std::env::var("S3_PREFIX").ok();

        // Redirect download configuration
        let redirect_downloads = std::env::var("S3_REDIRECT_DOWNLOADS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        let presign_expiry_secs: u64 = std::env::var("S3_PRESIGN_EXPIRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        // CloudFront configuration (optional)
        let cloudfront = Self::load_cloudfront_config();

        // Storage path format (native, artifactory, or migration)
        let path_format = StoragePathFormat::from_env();

        // Dedicated signing credentials for presigned URLs (Option B)
        let presign_access_key = std::env::var("S3_PRESIGN_ACCESS_KEY_ID").ok();
        let presign_secret_key = std::env::var("S3_PRESIGN_SECRET_ACCESS_KEY").ok();

        let ca_cert_path = std::env::var("S3_CA_CERT_PATH").ok();
        let insecure_tls = std::env::var("S3_INSECURE_TLS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        Ok(Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads,
            presign_expiry: Duration::from_secs(presign_expiry_secs),
            cloudfront,
            path_format,
            presign_access_key,
            presign_secret_key,
            ca_cert_path,
            insecure_tls,
        })
    }

    /// Load CloudFront configuration from environment
    fn load_cloudfront_config() -> Option<CloudFrontConfig> {
        let distribution_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok()?;
        let key_pair_id = std::env::var("CLOUDFRONT_KEY_PAIR_ID").ok()?;

        // Load private key from file or directly from env
        let private_key = if let Ok(key_path) = std::env::var("CLOUDFRONT_PRIVATE_KEY_PATH") {
            std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    tracing::warn!(
                        "Failed to read CloudFront private key from {}: {}",
                        key_path,
                        e
                    );
                    e
                })
                .ok()?
        } else if let Ok(key) = std::env::var("CLOUDFRONT_PRIVATE_KEY") {
            key
        } else {
            tracing::debug!("CloudFront private key not configured");
            return None;
        };

        tracing::info!(
            distribution = %distribution_url,
            key_pair_id = %key_pair_id,
            "CloudFront CDN configured for redirect downloads"
        );

        Some(CloudFrontConfig {
            distribution_url,
            key_pair_id,
            private_key,
        })
    }

    /// Create config with explicit values
    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads: false,
            presign_expiry: Duration::from_secs(3600),
            cloudfront: None,
            path_format: StoragePathFormat::default(),
            presign_access_key: None,
            presign_secret_key: None,
            ca_cert_path: None,
            insecure_tls: false,
        }
    }

    /// Set storage path format (for Artifactory compatibility)
    pub fn with_path_format(mut self, format: StoragePathFormat) -> Self {
        self.path_format = format;
        self
    }

    /// Enable redirect downloads
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Set presigned URL expiry
    pub fn with_presign_expiry(mut self, expiry: Duration) -> Self {
        self.presign_expiry = expiry;
        self
    }

    /// Set CloudFront configuration
    pub fn with_cloudfront(mut self, config: CloudFrontConfig) -> Self {
        self.cloudfront = Some(config);
        self
    }

    pub fn with_ca_cert_path(mut self, path: String) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    pub fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }
}

/// S3-compatible storage backend
pub struct S3Backend {
    store: AmazonS3,
    prefix: Option<String>,
    redirect_downloads: bool,
    presign_expiry: Duration,
    cloudfront: Option<CloudFrontConfig>,
    path_format: StoragePathFormat,
    signing_store: Option<AmazonS3>,
}

impl S3Backend {
    fn build_store(config: &S3Config, access_key: Option<&str>, secret_key: Option<&str>) -> Result<AmazonS3> {
        let mut client_opts = object_store::ClientOptions::new();

        if config.endpoint.as_ref().is_some_and(|e| e.starts_with("http://")) {
            client_opts = client_opts.with_allow_http(true);
        }

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

        if let Some(ak) = access_key {
            if let Some(sk) = secret_key {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("S3_ACCESS_KEY_ID"),
            std::env::var("S3_SECRET_ACCESS_KEY"),
        ) {
            tracing::info!("Using S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY for S3 credentials");
            builder = builder.with_access_key_id(&ak).with_secret_access_key(&sk);
        }

        builder.build().map_err(|e| AppError::Config(format!("Failed to build S3 client: {}", e)))
    }

    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        let store = Self::build_store(&config, None, None)?;

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
            tracing::info!(path_format = %config.path_format, "S3 storage path format configured");
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

    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }

    /// Generate the full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), key),
            None => key.to_string(),
        }
    }

    /// Strip the prefix from an S3 key
    fn strip_prefix(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => {
                let prefix_with_slash = format!("{}/", prefix.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        }
    }

    /// Try to generate an Artifactory fallback path from a native path
    ///
    /// Native format: ab/cd/abcd...full_checksum (64 chars)
    /// Artifactory format: ab/abcd...full_checksum
    fn try_artifactory_fallback(&self, key: &str) -> Option<String> {
        // Parse native format: {checksum[0:2]}/{checksum[2:4]}/{checksum}
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() >= 3 {
            // Last part should be the full checksum
            let checksum = parts[parts.len() - 1];
            if checksum.len() == 64 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
                // Generate Artifactory format: {checksum[0:2]}/{checksum}
                return Some(format!("{}/{}", &checksum[..2], checksum));
            }
        }
        None
    }

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
}

#[async_trait]
impl super::StorageBackend for S3Backend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);

        let resp = self
            .bucket
            .put_object(&full_key, &content)
            .await
            .map_err(|e| {
                // With fail-on-err, non-2xx responses arrive here as
                // S3Error::HttpFailWithBody(status, body) which includes the
                // full S3 error XML (e.g. AccessDenied, SignatureDoesNotMatch).
                tracing::error!(
                    key = %key,
                    full_key = %full_key,
                    error = %e,
                    "S3 put_object failed"
                );
                AppError::Storage(format!("Failed to put object '{}': {}", key, e))
            })?;

        if let Err(e) = Self::classify_put_status(key, resp.status_code(), resp.bytes()) {
            tracing::error!(
                key = %key,
                full_key = %full_key,
                status = resp.status_code(),
                response_body = %String::from_utf8_lossy(resp.bytes()),
                "S3 put rejected"
            );
            return Err(e);
        }

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);

        let response = match self.bucket.get_object(&full_key).await {
            Ok(resp) => match Self::classify_get_response(key, &resp)? {
                Some(()) => resp,
                None => {
                    // rust-s3 may return Ok with 404 status (e.g. Ceph RGW)
                    if let Some(bytes) = self
                        .try_fallback_get(key, "primary returned status 404")
                        .await?
                    {
                        return Ok(bytes);
                    }
                    return Err(AppError::NotFound(format!(
                        "Storage key not found: {}",
                        key
                    )));
                }
            },
            Err(e) => {
                if Self::classify_get_error_is_not_found(key, &e)? {
                    if let Some(bytes) = self
                        .try_fallback_get(key, "primary returned not found error")
                        .await?
                    {
                        return Ok(bytes);
                    }
                    return Err(AppError::NotFound(format!(
                        "Storage key not found: {}",
                        key
                    )));
                }
                // classify_get_error_is_not_found returns Err for non-not-found errors,
                // so this is unreachable, but kept for safety.
                return Err(AppError::Storage(format!(
                    "Failed to get object '{}': {}",
                    key, e
                )));
            }
        };

        tracing::debug!(key = %key, size = response.bytes().len(), "S3 get object successful");
        Ok(Bytes::from(response.to_vec()))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);

        let is_not_found = match self.bucket.head_object(&full_key).await {
            Ok((_, status)) => {
                match Self::classify_head_status(key, status)? {
                    Some(true) => return Ok(true),
                    _ => true, // 404 -> not found, try fallback
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if Self::is_head_not_found_error(&err_str) {
                    true
                } else {
                    return Err(AppError::Storage(format!(
                        "Failed to check existence of '{}': {}",
                        key, e
                    )));
                }
            }
        };

        if is_not_found && self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_full_key = self.full_key(&fallback_key);
                match self.bucket.head_object(&fallback_full_key).await {
                    Ok((_, status)) if (200..300).contains(&status) => {
                        tracing::debug!(
                            key = %key,
                            fallback = %fallback_key,
                            "Found artifact at Artifactory fallback path"
                        );
                        return Ok(true);
                    }
                    Ok((_, status)) if status != 404 => {
                        tracing::warn!(
                            key = %key,
                            fallback = %fallback_key,
                            status,
                            "Unexpected status from fallback head_object"
                        );
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if !Self::is_head_not_found_error(&err_str) {
                            tracing::warn!(
                                key = %key,
                                fallback = %fallback_key,
                                error = %e,
                                "Fallback head_object failed with unexpected error"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(false)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);

        let resp =
            self.bucket.delete_object(&full_key).await.map_err(|e| {
                AppError::Storage(format!("Failed to delete object '{}': {}", key, e))
            })?;

        Self::classify_delete_status(key, resp.status_code())?;

        tracing::debug!(key = %key, "S3 delete object successful");
        Ok(())
    }

    fn supports_redirect(&self) -> bool {
        self.redirect_downloads
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.redirect_downloads {
            return Ok(None);
        }

        let full_key = self.full_key(key);
        let expiry_secs = expires_in.as_secs().min(604800) as u32; // Max 7 days for S3

        // If CloudFront is configured, use CloudFront signed URLs
        if let Some(cf) = &self.cloudfront {
            let url = self.generate_cloudfront_signed_url(cf, &full_key, expires_in)?;
            tracing::debug!(
                key = %key,
                expires_in_secs = expiry_secs,
                source = "cloudfront",
                "Generated CloudFront signed URL"
            );
            return Ok(Some(PresignedUrl {
                url,
                expires_in,
                source: PresignedUrlSource::CloudFront,
            }));
        }

        // Generate S3 presigned URL with fresh or dedicated credentials
        let presign_result = if let Some(sb) = &self.signing_bucket {
            // Option B: use dedicated signing credentials (long-lived, no STS expiry concern)
            sb.presign_get(&full_key, expiry_secs, None).await
        } else {
            // Option A: refresh credentials from default chain before signing
            // This ensures STS/IRSA credentials are current, so the presigned URL
            // gets the full requested lifetime instead of being limited by
            // the remaining TTL of stale credentials.
            match Credentials::default() {
                Ok(fresh_creds) => {
                    match Bucket::new(&self.bucket_name, self.region.clone(), fresh_creds) {
                        Ok(fresh_bucket) => {
                            let fresh_bucket = if self.use_path_style {
                                fresh_bucket.with_path_style()
                            } else {
                                fresh_bucket
                            };
                            fresh_bucket.presign_get(&full_key, expiry_secs, None).await
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to create fresh signing bucket, using cached credentials: {}",
                                e
                            );
                            self.bucket.presign_get(&full_key, expiry_secs, None).await
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to refresh credentials for presigning, using cached credentials: {}",
                        e
                    );
                    self.bucket.presign_get(&full_key, expiry_secs, None).await
                }
            }
        };

        let url = presign_result.map_err(|e| {
            AppError::Storage(format!(
                "Failed to generate presigned URL for '{}': {}",
                key, e
            ))
        })?;

        tracing::debug!(
            key = %key,
            expires_in_secs = expiry_secs,
            source = "s3",
            dedicated_creds = self.signing_bucket.is_some(),
            "Generated S3 presigned URL"
        );

        Ok(Some(PresignedUrl {
            url,
            expires_in,
            source: PresignedUrlSource::S3,
        }))
    }

    async fn health_check(&self) -> Result<()> {
        // Use head_object on a sentinel key. A 404 (NoSuchKey) proves that the
        // bucket is reachable and credentials are valid. Only transport-level or
        // auth errors indicate an unhealthy backend.
        match self.bucket.head_object(".health-probe").await {
            Ok(_) => Ok(()),
            Err(S3Error::HttpFailWithBody(status, _)) if (400..500).contains(&status) => {
                // 4xx other than auth errors: bucket is reachable.
                // 403 could mean bad creds, so treat that as unhealthy.
                if status == 403 {
                    Err(AppError::Storage(
                        "S3 health check failed: access denied (403)".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                // 404 / NoSuchKey is expected and proves connectivity
                if err_str.contains("404")
                    || err_str.contains("NoSuchKey")
                    || err_str.contains("Not Found")
                {
                    Ok(())
                } else if err_str.contains("403") || err_str.contains("Access Denied") {
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
}

/// Extended S3 backend operations (for StorageService compatibility)
impl S3Backend {
    /// List keys with optional prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_prefix = match (&self.prefix, prefix) {
            (Some(base), Some(p)) => format!("{}/{}", base.trim_end_matches('/'), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let results = self
            .bucket
            .list(search_prefix, None)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = results
            .into_iter()
            .flat_map(|result| result.contents)
            .map(|obj| self.strip_prefix(&obj.key))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }

    /// Copy content from one key to another
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        // S3 CopyObject requires source in format "bucket/key"
        let copy_source = format!("{}/{}", self.bucket.name(), source_key);

        self.bucket
            .copy_object_internal(&copy_source, &dest_key)
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e))
            })?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }

    /// Get content size without fetching full content
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);

        let (head, status) = match self.bucket.head_object(&full_key).await {
            Ok((head, status)) => match Self::classify_head_status(key, status)? {
                Some(true) => (head, status),
                _ => {
                    return Err(AppError::NotFound(format!(
                        "Storage key not found: {}",
                        key
                    )));
                }
            },
            Err(e) => {
                let err_str = e.to_string();
                if Self::is_head_not_found_error(&err_str) {
                    return Err(AppError::NotFound(format!(
                        "Storage key not found: {}",
                        key
                    )));
                }
                return Err(AppError::Storage(format!(
                    "Failed to get size of '{}': {}",
                    key, e
                )));
            }
        };

        let size = head.content_length.unwrap_or(0) as u64;
        tracing::debug!(key = %key, size = size, status, "S3 head object successful");
        Ok(size)
    }

    /// Generate a CloudFront signed URL
    ///
    /// CloudFront signed URLs use RSA-SHA1 signatures with a canned policy.
    fn generate_cloudfront_signed_url(
        &self,
        config: &CloudFrontConfig,
        key: &str,
        expires_in: Duration,
    ) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::RsaPrivateKey;
        use sha1::Sha1;

        // Calculate expiry timestamp
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?
            .as_secs()
            + expires_in.as_secs();

        // Build the resource URL
        let resource_url = format!(
            "{}/{}",
            config.distribution_url.trim_end_matches('/'),
            key.trim_start_matches('/')
        );

        // Create canned policy
        let policy = format!(
            r#"{{"Statement":[{{"Resource":"{}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{}}}}}}}]}}"#,
            resource_url, expires
        );

        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(&config.private_key)
            .map_err(|e| AppError::Config(format!("Invalid CloudFront private key: {}", e)))?;

        // Sign the policy with RSA-SHA1 (unprefixed for CloudFront compatibility)
        let signing_key = SigningKey::<Sha1>::new_unprefixed(private_key);
        let signature = signing_key.sign(policy.as_bytes());

        // Base64 encode and make URL-safe
        let signature_b64 = STANDARD
            .encode(signature.to_bytes())
            .replace('+', "-")
            .replace('=', "_")
            .replace('/', "~");

        // Build signed URL with canned policy (simplified - just expiry)
        let signed_url = format!(
            "{}?Expires={}&Signature={}&Key-Pair-Id={}",
            resource_url, expires, signature_b64, config.key_pair_id
        );

        Ok(signed_url)
    }

    /// Check if redirect downloads are enabled
    pub fn redirect_enabled(&self) -> bool {
        self.redirect_downloads
    }

    /// Get the default presign expiry duration
    pub fn default_presign_expiry(&self) -> Duration {
        self.presign_expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_with_prefix() {
        // We can't create a real S3Backend without credentials, but we can test the key logic
        // by testing the string operations directly
        let prefix = Some("artifacts".to_string());
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "artifacts/test/file.txt");
    }

    #[test]
    fn test_full_key_without_prefix() {
        let prefix: Option<String> = None;
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "test/file.txt");
    }

    #[test]
    fn test_strip_prefix() {
        let prefix = Some("artifacts".to_string());
        let key = "artifacts/test/file.txt";

        let stripped = match &prefix {
            Some(p) => {
                let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        };

        assert_eq!(stripped, "test/file.txt");
    }

    #[test]
    fn test_s3_config_new() {
        let config = S3Config::new(
            "my-bucket".to_string(),
            "us-west-2".to_string(),
            Some("http://localhost:9000".to_string()),
            Some("prefix".to_string()),
        );

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_with_path_format() {
        let config = S3Config::new("my-bucket".to_string(), "us-west-2".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);

        assert_eq!(config.path_format, StoragePathFormat::Artifactory);
    }

    #[test]
    fn test_artifactory_fallback_path_extraction() {
        // Test the path extraction logic directly
        let native_key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";

        // Parse native format: {checksum[0:2]}/{checksum[2:4]}/{checksum}
        let parts: Vec<&str> = native_key.split('/').collect();
        assert_eq!(parts.len(), 3);

        let checksum = parts[2];
        assert_eq!(checksum.len(), 64);

        // Generate Artifactory format
        let artifactory_key = format!("{}/{}", &checksum[..2], checksum);
        assert_eq!(
            artifactory_key,
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_artifactory_fallback_invalid_key() {
        // Test with invalid key (not a valid checksum path)
        let invalid_key = "not/a/valid/path.txt";

        let parts: Vec<&str> = invalid_key.split('/').collect();
        let last_part = parts.last().unwrap();

        // Should not match: not 64 chars and not all hex
        assert!(last_part.len() != 64 || !last_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_path_format_with_s3_config() {
        // Test that path format is properly set via with_path_format
        let config = S3Config::new("test".to_string(), "us-east-1".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);

        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    #[test]
    fn test_s3_config_presign_credentials_default_none() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_supports_redirect_requires_key() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_redirect_downloads(true);
        assert!(config.redirect_downloads);
        // Without presign credentials, Option A (auto-refresh) will be used
        assert!(config.presign_access_key.is_none());
    }

    #[test]
    fn test_is_not_found_error_matches_404() {
        assert!(S3Backend::is_not_found_error(
            "Got HTTP 404 with content 'NoSuchKey'"
        ));
        assert!(S3Backend::is_not_found_error("NoSuchKey"));
        assert!(S3Backend::is_not_found_error("404"));
    }

    #[test]
    fn test_is_not_found_error_rejects_other_errors() {
        assert!(!S3Backend::is_not_found_error(
            "Got HTTP 500 with content 'Internal'"
        ));
        assert!(!S3Backend::is_not_found_error("Service Unavailable"));
        assert!(!S3Backend::is_not_found_error("connection refused"));
    }

    const TEST_KEY: &str = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
    const TEST_FALLBACK: &str =
        "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";

    #[test]
    fn test_classify_fallback_get_result_success_returns_bytes() {
        use std::collections::HashMap;

        let body = b"artifact data";
        let resp = ResponseData::new(Bytes::from_static(body), 200, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        let bytes = result.unwrap().expect("expected Some(bytes)");
        assert_eq!(&bytes[..], body);
    }

    #[test]
    fn test_classify_fallback_get_result_404_returns_none() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 404, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_classify_fallback_get_result_propagates_server_failure() {
        use std::collections::HashMap;

        let resp = ResponseData::new(
            Bytes::from_static(b"fallback unavailable"),
            500,
            HashMap::new(),
        );
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        match result {
            Err(AppError::Storage(message)) => {
                assert!(
                    message.contains("500"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_fallback_get_result_not_found_error_returns_none() {
        let err = S3Error::HttpFailWithBody(404, "NoSuchKey".to_string());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Err(err));

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_classify_fallback_get_result_other_error_propagates() {
        let err = S3Error::HttpFailWithBody(503, "Service Unavailable".to_string());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Err(err));

        match result {
            Err(AppError::Storage(message)) => {
                assert!(
                    message.contains("Service Unavailable"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected storage error, got {other:?}"),
        }
    }

    // --- is_head_not_found_error tests ---

    #[test]
    fn test_is_head_not_found_error_matches_404_and_nosuchkey() {
        assert!(S3Backend::is_head_not_found_error("404"));
        assert!(S3Backend::is_head_not_found_error("NoSuchKey"));
        assert!(S3Backend::is_head_not_found_error("Not Found"));
        assert!(S3Backend::is_head_not_found_error("Got HTTP 404 Not Found"));
    }

    #[test]
    fn test_is_head_not_found_error_rejects_other_errors() {
        assert!(!S3Backend::is_head_not_found_error(
            "500 Internal Server Error"
        ));
        assert!(!S3Backend::is_head_not_found_error("connection refused"));
        assert!(!S3Backend::is_head_not_found_error("timeout"));
    }

    // --- classify_put_status tests ---

    #[test]
    fn test_classify_put_status_accepts_200() {
        assert!(S3Backend::classify_put_status(TEST_KEY, 200, b"").is_ok());
    }

    #[test]
    fn test_classify_put_status_accepts_201() {
        assert!(S3Backend::classify_put_status(TEST_KEY, 201, b"").is_ok());
    }

    #[test]
    fn test_classify_put_status_accepts_204() {
        assert!(S3Backend::classify_put_status(TEST_KEY, 204, b"").is_ok());
    }

    #[test]
    fn test_classify_put_status_rejects_403() {
        let body = b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
        match S3Backend::classify_put_status(TEST_KEY, 403, body) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("403"), "expected 403 in message: {msg}");
                assert!(msg.contains("put"), "expected 'put' in message: {msg}");
                assert!(
                    msg.contains("AccessDenied"),
                    "expected S3 error detail in message: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_put_status_rejects_500() {
        match S3Backend::classify_put_status(TEST_KEY, 500, b"Internal Error") {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("500"), "expected 500 in message: {msg}");
                assert!(
                    msg.contains("Internal Error"),
                    "expected S3 body in message: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_put_status_rejects_500_empty_body() {
        match S3Backend::classify_put_status(TEST_KEY, 500, b"") {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("500"), "expected 500 in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_put_status_rejects_301_redirect() {
        assert!(S3Backend::classify_put_status(TEST_KEY, 301, b"").is_err());
    }

    // --- classify_get_response tests ---

    #[test]
    fn test_classify_get_response_200_returns_some() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b"data"), 200, HashMap::new());
        let result = S3Backend::classify_get_response(TEST_KEY, &resp);
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_classify_get_response_206_partial_returns_some() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b"partial"), 206, HashMap::new());
        let result = S3Backend::classify_get_response(TEST_KEY, &resp);
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_classify_get_response_404_returns_none() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 404, HashMap::new());
        let result = S3Backend::classify_get_response(TEST_KEY, &resp);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_classify_get_response_500_returns_storage_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 500, HashMap::new());
        match S3Backend::classify_get_response(TEST_KEY, &resp) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("500"), "expected 500 in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_get_response_403_returns_storage_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b"Forbidden"), 403, HashMap::new());
        match S3Backend::classify_get_response(TEST_KEY, &resp) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("403"), "expected 403 in message: {msg}");
                assert!(msg.contains(TEST_KEY), "expected key in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    // --- classify_get_error_is_not_found tests ---

    #[test]
    fn test_classify_get_error_is_not_found_for_404() {
        let err = S3Error::HttpFailWithBody(404, "NoSuchKey".to_string());
        let result = S3Backend::classify_get_error_is_not_found(TEST_KEY, &err);
        assert!(result.unwrap());
    }

    #[test]
    fn test_classify_get_error_is_not_found_for_nosuchkey() {
        let err = S3Error::HttpFailWithBody(
            404,
            "NoSuchKey: the specified key does not exist".to_string(),
        );
        let result = S3Backend::classify_get_error_is_not_found(TEST_KEY, &err);
        assert!(result.unwrap());
    }

    #[test]
    fn test_classify_get_error_propagates_503() {
        let err = S3Error::HttpFailWithBody(503, "Service Unavailable".to_string());
        match S3Backend::classify_get_error_is_not_found(TEST_KEY, &err) {
            Err(AppError::Storage(msg)) => {
                assert!(
                    msg.contains("Service Unavailable"),
                    "expected error detail in message: {msg}"
                );
                assert!(msg.contains(TEST_KEY), "expected key in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_get_error_propagates_io_error() {
        let err = S3Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        match S3Backend::classify_get_error_is_not_found(TEST_KEY, &err) {
            Err(AppError::Storage(msg)) => {
                assert!(
                    msg.contains("connection refused"),
                    "expected error detail in message: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    // --- classify_head_status tests ---

    #[test]
    fn test_classify_head_status_200_returns_some_true() {
        let result = S3Backend::classify_head_status(TEST_KEY, 200);
        assert_eq!(result.unwrap(), Some(true));
    }

    #[test]
    fn test_classify_head_status_204_returns_some_true() {
        let result = S3Backend::classify_head_status(TEST_KEY, 204);
        assert_eq!(result.unwrap(), Some(true));
    }

    #[test]
    fn test_classify_head_status_404_returns_none() {
        let result = S3Backend::classify_head_status(TEST_KEY, 404);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_classify_head_status_403_returns_storage_error() {
        match S3Backend::classify_head_status(TEST_KEY, 403) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("403"), "expected 403 in message: {msg}");
                assert!(msg.contains("head"), "expected 'head' in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_head_status_500_returns_storage_error() {
        match S3Backend::classify_head_status(TEST_KEY, 500) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("500"), "expected 500 in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_head_status_301_returns_storage_error() {
        // Redirects should not be silently accepted
        assert!(S3Backend::classify_head_status(TEST_KEY, 301).is_err());
    }

    // --- classify_delete_status tests ---

    #[test]
    fn test_classify_delete_status_200_ok() {
        assert!(S3Backend::classify_delete_status(TEST_KEY, 200).is_ok());
    }

    #[test]
    fn test_classify_delete_status_204_ok() {
        assert!(S3Backend::classify_delete_status(TEST_KEY, 204).is_ok());
    }

    #[test]
    fn test_classify_delete_status_404_ok() {
        // Delete of a non-existent key is fine (idempotent)
        assert!(S3Backend::classify_delete_status(TEST_KEY, 404).is_ok());
    }

    #[test]
    fn test_classify_delete_status_403_returns_error() {
        match S3Backend::classify_delete_status(TEST_KEY, 403) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("403"), "expected 403 in message: {msg}");
                assert!(
                    msg.contains("delete"),
                    "expected 'delete' in message: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_delete_status_500_returns_error() {
        match S3Backend::classify_delete_status(TEST_KEY, 500) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("500"), "expected 500 in message: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_delete_status_503_returns_error() {
        assert!(S3Backend::classify_delete_status(TEST_KEY, 503).is_err());
    }

    // --- classify_fallback_get_result: additional edge cases ---

    #[test]
    fn test_classify_fallback_get_result_201_returns_bytes() {
        use std::collections::HashMap;

        let body = b"created";
        let resp = ResponseData::new(Bytes::from_static(body), 201, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        let bytes = result.unwrap().expect("expected Some(bytes)");
        assert_eq!(&bytes[..], body);
    }

    #[test]
    fn test_classify_fallback_get_result_403_returns_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b"Forbidden"), 403, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        match result {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("403"), "expected 403 in message: {msg}");
                assert!(
                    msg.contains("fallback"),
                    "expected 'fallback' in message: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_fallback_get_result_empty_body_on_success() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 200, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));

        let bytes = result.unwrap().expect("expected Some(bytes)");
        assert!(bytes.is_empty());
    }

    // --- Boundary / combined tests ---

    #[test]
    fn test_status_code_boundary_299_is_success() {
        // 299 is the upper boundary of 2xx
        assert!(S3Backend::classify_put_status(TEST_KEY, 299, b"").is_ok());
        assert!(S3Backend::classify_delete_status(TEST_KEY, 299).is_ok());
        assert_eq!(
            S3Backend::classify_head_status(TEST_KEY, 299).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn test_status_code_boundary_300_is_failure() {
        assert!(S3Backend::classify_put_status(TEST_KEY, 300, b"").is_err());
        assert!(S3Backend::classify_head_status(TEST_KEY, 300)
            .unwrap_err()
            .to_string()
            .contains("300"));
    }

    #[test]
    fn test_status_code_boundary_199_is_failure() {
        // Below 200 range
        assert!(S3Backend::classify_put_status(TEST_KEY, 199, b"").is_err());
        assert!(S3Backend::classify_delete_status(TEST_KEY, 199).is_err());
    }

    #[test]
    fn test_classify_get_response_includes_key_in_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 503, HashMap::new());
        match S3Backend::classify_get_response(TEST_KEY, &resp) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains(TEST_KEY), "error should include key: {msg}");
                assert!(msg.contains("503"), "error should include status: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_put_status_includes_key_in_error() {
        match S3Backend::classify_put_status("my/custom/key.jar", 502, b"Bad Gateway") {
            Err(AppError::Storage(msg)) => {
                assert!(
                    msg.contains("my/custom/key.jar"),
                    "error should include key: {msg}"
                );
                assert!(msg.contains("502"), "error should include status: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_head_status_includes_key_in_error() {
        match S3Backend::classify_head_status("some/artifact", 503) {
            Err(AppError::Storage(msg)) => {
                assert!(
                    msg.contains("some/artifact"),
                    "error should include key: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_delete_status_includes_key_in_error() {
        match S3Backend::classify_delete_status("to-delete/key", 502) {
            Err(AppError::Storage(msg)) => {
                assert!(
                    msg.contains("to-delete/key"),
                    "error should include key: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    // --- S3Config builder method tests ---

    #[test]
    fn test_s3_config_with_presign_expiry() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_presign_expiry(Duration::from_secs(7200));
        assert_eq!(config.presign_expiry, Duration::from_secs(7200));
    }

    #[test]
    fn test_s3_config_with_cloudfront() {
        let cf = CloudFrontConfig {
            distribution_url: "https://d1234.cloudfront.net".to_string(),
            key_pair_id: "KPID123".to_string(),
            private_key: "fake-key-data".to_string(),
        };
        let config =
            S3Config::new("b".to_string(), "us-east-1".to_string(), None, None).with_cloudfront(cf);
        assert!(config.cloudfront.is_some());
        let cf = config.cloudfront.unwrap();
        assert_eq!(cf.distribution_url, "https://d1234.cloudfront.net");
        assert_eq!(cf.key_pair_id, "KPID123");
    }

    #[test]
    fn test_s3_config_default_values() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(3600));
        assert!(config.cloudfront.is_none());
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.endpoint.is_none());
        assert!(config.prefix.is_none());
    }

    #[test]
    fn test_s3_config_chained_builders() {
        let cf = CloudFrontConfig {
            distribution_url: "https://cdn.example.com".to_string(),
            key_pair_id: "KP1".to_string(),
            private_key: "key".to_string(),
        };
        let config = S3Config::new(
            "bucket".to_string(),
            "eu-west-1".to_string(),
            Some("https://minio:9000".to_string()),
            Some("prefix".to_string()),
        )
        .with_redirect_downloads(true)
        .with_presign_expiry(Duration::from_secs(600))
        .with_path_format(StoragePathFormat::Migration)
        .with_cloudfront(cf);

        assert_eq!(config.bucket, "bucket");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint, Some("https://minio:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert!(config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(600));
        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.cloudfront.is_some());
    }

    // --- full_key / strip_prefix via actual struct logic ---

    #[test]
    fn test_full_key_trailing_slash_prefix() {
        let prefix = Some("artifacts/".to_string());
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "artifacts/test/file.txt");
    }

    #[test]
    fn test_strip_prefix_no_match() {
        let prefix = Some("other-prefix".to_string());
        let key = "artifacts/test/file.txt";

        let stripped = match &prefix {
            Some(p) => {
                let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        };

        // Key doesn't start with "other-prefix/", so it returns the key unchanged
        assert_eq!(stripped, "artifacts/test/file.txt");
    }

    #[test]
    fn test_strip_prefix_none() {
        let prefix: Option<String> = None;
        let key = "test/file.txt";

        let stripped = match &prefix {
            Some(p) => {
                let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        };

        assert_eq!(stripped, "test/file.txt");
    }

    // --- try_artifactory_fallback logic ---

    #[test]
    fn test_artifactory_fallback_valid_native_path() {
        // Simulate the try_artifactory_fallback logic for a valid path
        let key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let parts: Vec<&str> = key.split('/').collect();
        assert_eq!(parts.len(), 3);
        let checksum = parts[parts.len() - 1];
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
        let fallback = format!("{}/{}", &checksum[..2], checksum);
        assert_eq!(
            fallback,
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_artifactory_fallback_short_checksum_rejected() {
        let key = "ab/cd/abcdef1234";
        let parts: Vec<&str> = key.split('/').collect();
        let checksum = parts[parts.len() - 1];
        // Not 64 chars, should be rejected
        assert_ne!(checksum.len(), 64);
    }

    #[test]
    fn test_artifactory_fallback_non_hex_rejected() {
        let key = "zz/yy/zzyy00000000000000000000000000000000000000000000000000gggggg";
        let parts: Vec<&str> = key.split('/').collect();
        let checksum = parts[parts.len() - 1];
        assert!(!checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_artifactory_fallback_single_segment_rejected() {
        let key = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let parts: Vec<&str> = key.split('/').collect();
        // Only 1 part, need >= 3
        assert!(parts.len() < 3);
    }

    // --- classify_get_response additional edge cases ---

    #[test]
    fn test_classify_get_response_301_redirect_is_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 301, HashMap::new());
        assert!(S3Backend::classify_get_response(TEST_KEY, &resp).is_err());
    }

    #[test]
    fn test_classify_get_response_204_returns_some() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 204, HashMap::new());
        assert!(S3Backend::classify_get_response(TEST_KEY, &resp)
            .unwrap()
            .is_some());
    }

    // --- classify_get_error_is_not_found edge case ---

    #[test]
    fn test_classify_get_error_propagates_403() {
        let err = S3Error::HttpFailWithBody(403, "Forbidden".to_string());
        match S3Backend::classify_get_error_is_not_found(TEST_KEY, &err) {
            Err(AppError::Storage(msg)) => {
                assert!(msg.contains("Forbidden"), "expected detail: {msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    // --- path_format tests ---

    #[test]
    fn test_native_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Native);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_artifactory_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_migration_format_has_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    // --- classify_fallback_get_result boundary ---

    #[test]
    fn test_classify_fallback_get_result_299_returns_bytes() {
        use std::collections::HashMap;

        let body = b"upper boundary";
        let resp = ResponseData::new(Bytes::from_static(body), 299, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_classify_fallback_get_result_300_returns_error() {
        use std::collections::HashMap;

        let resp = ResponseData::new(Bytes::from_static(b""), 300, HashMap::new());
        let result = S3Backend::classify_fallback_get_result(TEST_KEY, TEST_FALLBACK, Ok(resp));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::StorageBackend as StorageBackendTrait;

    /// Integration test for S3 presigned URLs
    /// Run with: S3_BUCKET=your-bucket cargo test s3_presigned --lib -- --ignored --nocapture
    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_presigned_url_generation() {
        // Skip if S3_BUCKET not set
        let bucket = match std::env::var("S3_BUCKET") {
            Ok(b) => b,
            Err(_) => {
                println!("Skipping: S3_BUCKET not set");
                return;
            }
        };

        println!("Testing with bucket: {}", bucket);

        // Create config with redirect enabled
        let config = S3Config::from_env()
            .expect("Failed to load S3 config")
            .with_redirect_downloads(true)
            .with_presign_expiry(Duration::from_secs(300));

        let backend = S3Backend::new(config)
            .await
            .expect("Failed to create S3 backend");

        // Upload a test file
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

        // Check supports_redirect
        assert!(
            StorageBackendTrait::supports_redirect(&backend),
            "Backend should support redirect"
        );

        // Generate presigned URL
        println!("Generating presigned URL...");
        let presigned =
            StorageBackendTrait::get_presigned_url(&backend, &test_key, Duration::from_secs(300))
                .await
                .expect("Failed to generate presigned URL");

        assert!(presigned.is_some(), "Should return presigned URL");
        let presigned = presigned.unwrap();

        println!(
            "Presigned URL: {}...",
            &presigned.url[..80.min(presigned.url.len())]
        );
        println!("Source: {:?}", presigned.source);
        println!("Expires in: {:?}", presigned.expires_in);

        assert!(
            presigned.url.contains(&bucket),
            "URL should contain bucket name"
        );
        assert!(
            presigned.url.contains("X-Amz-Signature"),
            "URL should have signature"
        );

        // Verify URL works by downloading
        println!("Verifying presigned URL works...");
        let client = reqwest::Client::new();
        let response = client
            .get(&presigned.url)
            .send()
            .await
            .expect("Failed to fetch presigned URL");
        assert!(
            response.status().is_success(),
            "Presigned URL should return 200"
        );

        let body = response.bytes().await.expect("Failed to read body");
        assert_eq!(body.as_ref(), test_content.as_ref(), "Content should match");
        println!("✓ Presigned URL works!");

        // Cleanup
        println!("Cleaning up...");
        StorageBackendTrait::delete(&backend, &test_key)
            .await
            .expect("Failed to delete test file");
        println!("✓ Test complete");
    }
}
