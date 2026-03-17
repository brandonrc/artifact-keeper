# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0-rc.8] - 2026-03-17

### Thank You
- @inspired-geek (Alexey Ivanov) for three quality contributions: paginated Dependency-Track list endpoints preventing truncated security data (#434), paginated Meilisearch reindex preventing OOM on large registries (#435/#440), advisory cache eviction with error visibility (#433/#439), S3 status code handling (#410), and Cargo sparse index field name fix (#419)
- @pipelineRat for reporting Maven pull-through cache failures (#427)
- @dispalt for continued feedback on storage backend behavior (#428)

### Added
- **Per-repository storage backend selection** (#431) - repositories can now be configured to use different storage backends (filesystem, S3, Azure, GCS) independently of the global default.
- **Correlation ID middleware** (#432) - every HTTP response now includes an `X-Correlation-ID` header for distributed tracing. The middleware was previously defined with 13 unit tests but never wired into the router.
- **Configurable rate limits** (#436) - auth and API rate limits are now configurable via `RATE_LIMIT_AUTH_PER_MIN` (default 120), `RATE_LIMIT_API_PER_MIN` (default 5000), and `RATE_LIMIT_WINDOW_SECS` (default 60) environment variables.

### Fixed
- **bcrypt blocking the async runtime** (#436) - moved all `bcrypt::verify` and `bcrypt::hash` calls to `tokio::task::spawn_blocking()`. Previously, bcrypt at cost-12 (~250ms per call) ran synchronously on the tokio event loop, serializing all concurrent requests. At 5 concurrent logins, max latency was 2.7s. Now runs on the blocking thread pool.
- **Rate limiter shared bucket in Kubernetes** (#436) - without `ConnectInfo`, all clients shared a single `ip:unknown` rate limit bucket. Now falls back to `X-Forwarded-For` from trusted ingress controllers. Auth rate limit raised from 30 to 120 req/min (bcrypt cost-12 already provides brute-force protection).
- **Sync policy create doesn't auto-evaluate** (#438) - creating, updating, deleting, or toggling a sync policy now automatically calls `evaluate_policies()` to populate `peer_repo_subscriptions`. Previously, uploads after policy creation wouldn't trigger sync tasks until a manual `/evaluate` call.
- **Maven SNAPSHOT timestamp treated as classifier** (#432) - `strip_snapshot_timestamp()` now correctly strips timestamp-build suffixes (e.g., `-20260314.155654-1`) from SNAPSHOT filenames so they aren't misidentified as classifiers.
- **Maven SNAPSHOT re-upload not updating primary** (#432) - when a new SNAPSHOT build replaces an existing primary artifact, the artifact record now correctly updates path, checksum, and storage key.
- **Dependency-Track truncated results** (#434) - list endpoints now paginate through all results instead of returning only the first page. Contributed by @inspired-geek.
- **Meilisearch OOM on large reindex** (#440) - full reindex now uses cursor-based pagination (1000 rows per batch) instead of loading all artifacts into memory. Download count subquery scoped to batch. `MeiliService::new` returns `Result` instead of panicking. Based on contribution by @inspired-geek.
- **Advisory cache silent error swallowing** (#439) - replaced `if let Ok` patterns with `match` + `warn!` logging for OSV and GitHub advisory API deserialization failures. Added bounded cache eviction. Based on contribution by @inspired-geek.
- **S3 backend error propagation** (#410) - improved status code handling and fallback error messages. Contributed by @inspired-geek.
- **Cargo sparse index field name** (#419) - renamed `version_req` to `req` in dependency entries to match the sparse registry protocol spec. Contributed by @inspired-geek.
- **Maven secondary GAV file serving** (#430) - resolve SNAPSHOT downloads and serve secondary files (POM, javadoc, sources) from the correct GAV path.
- **Maven SNAPSHOT checksum resolution** (#417) - resolve checksum requests for timestamped SNAPSHOT versions.
- **Maven GAV coordinate grouping** (#418) - group deploy artifacts by GAV coordinates to prevent incorrect artifact association.

### Changed
- Auth rate limit default raised from 30 to 120 req/min
- API rate limit default raised from 1,000 to 5,000 req/min
- Dependency bumps: docker/metadata-action 5 to 6, docker/build-push-action 6 to 7, docker/login-action 3 to 4, actions/github-script 7 to 8, anchore/grype v0.109.0 to v0.109.1, aquasecurity/trivy-action 0.34.2 to 0.35.0, rust 1.93-bookworm to 1.94-bookworm, quinn-proto security patch

## [1.1.0-rc.7] - 2026-03-08

### Thank You
- @todpunk for the security advisory heads-up and a Cargo token performance fix (#378, #377)
- @arp-mbender for reporting the broken quickstart commands (#368)
- @dispalt for catching the staging repo filter issue and SNAPSHOT soft-delete collision (#363, #321)
- @Lerentis for reporting the Maven path upload bug and the S3 IRSA panic (#361, #343)
- @lpreiner for flagging private repository visibility leaking to unauthenticated users (#333)
- @CJLove for continued follow-up on Docker login behind reverse proxies (#322)

### Added
- **Package curation engine** (#405) - intercept packages from upstream mirrors through staging repos, evaluate against configurable rules (glob patterns, version constraints, architecture filters), and approve or block before exposing to consumers. Includes rules CRUD, bulk operations, re-evaluation, and stats API endpoints.
- **Curation upstream sync** (#405) - background scheduler fetches and parses RPM primary.xml and DEB Packages indexes from remote repos, populating the curation catalog automatically.
- **Artifact content viewing endpoint** (#407) - `GET /api/v1/tree/content` returns inline file content for browsing artifacts in the web UI.
- **Automatic stale peer detection** (#402) - scheduler marks peers as stale when heartbeats stop, preventing sync attempts to unreachable nodes.
- **Failed sync retry on peer recovery** (#401) - automatically retries previously failed sync tasks when a peer comes back online.
- **Shared virtual metadata resolution** (#399) - extracted reusable helpers for resolving metadata across virtual repository members, reducing duplication in format handlers.
- **Build traceability** (#367) - `/health` endpoint now includes the git commit SHA for identifying deployed versions.

### Fixed
- **Path traversal in FilesystemStorage** (#387, #380) - sanitize storage keys to prevent directory traversal attacks via crafted artifact paths.
- **Peer identity endpoint exposed to non-admins** (#388, #381, #382) - restrict peer announce, heartbeat, and identity endpoints to admin users only.
- **gRPC missing admin authorization** (#390, #383) - add admin privilege checks to the gRPC auth interceptor.
- **Admin password file permissions** (#391, #384) - create password file with mode 0600 instead of world-readable.
- **Timing side-channel in token validation** (#392, #385) - use constant-time comparison for API token prefix lookup.
- **Authentication audit logging** (#393, #386) - wire up audit log entries for login, logout, and token operations.
- **Quickstart commands in README** (#394, #368) - fix incorrect docker compose commands in the getting started guide.
- **Air-gapped deployment issues** (#379) - fix offline installation and configuration for disconnected environments.
- **Cargo sparse index proxy path** (#342, #341) - strip `index/` prefix when proxying to upstream Cargo registries.
- **Soft-deleted artifact collision on re-upload** (#339, #321) - clean up soft-deleted records before INSERT to prevent unique constraint violations.
- **Maven version-level metadata** (#362, #361) - serve maven-metadata.xml from storage at the version path level.
- **Staging repo filter** (#364, #363) - accept `repo_type` query alias for filtering staging repositories.
- **Repository format enum casting** (#376) - cast `repository_format` enum to text in quality check queries to prevent type mismatch errors.
- **S3 IRSA TLS panic** (#348, #343) - install rustls CryptoProvider before S3 client initialization to prevent panics with IAM Roles for Service Accounts.
- **Fork PR SonarCloud gate** (#396) - detect fork PRs correctly in the quality gate workflow.
- **E2E PKI container cleanup** (#400) - kill lingering gpg-agent processes before cleanup to prevent non-zero exit codes.
- **Cargo token auth performance** (#377) - contributed by @todpunk.

### Tests
- Curation E2E test suite (#406) - 33 assertions across 13 phases covering sync, rules, manual/bulk status, stats, CRUD, global rules, and DEB format. Uses mock upstream repos (nginx serving RPM/DEB fixture files).

### Changed
- Trivy CI scanner bumped from 0.69.1 to 0.69.3 (#404)
- ALLOW_HTTP_INTEGRATIONS added to compose backend environment (#397)
- CI mirror namespace switched to GHCR for fork PR E2E parity (#366)
- Dependency bumps: actions/checkout 4 to 6, actions/upload-artifact 6 to 7, actions/download-artifact 4 to 8, github/codeql-action 3 to 4, alpine 3.21 to 3.23, trivy-action 0.34.1 to 0.34.2

## [1.1.0-rc.6] - 2026-02-28

### Thank You
- @CJLove for reporting the OCI v2 auth challenge issue behind reverse proxies (#315)
- @dispalt for identifying the Maven SNAPSHOT re-upload bug and scanner storage backend resolution (#297, #296)
- @msegura501 for reporting private repository visibility enforcement (#280)

### Added
- **Azure RBAC authentication for Blob Storage** (#312) - support managed identity and service principal authentication for Azure Blob Storage, removing the need for connection strings
- **Alpine-based Docker image variant** (#306) - lighter alternative image based on Alpine Linux alongside the existing UBI image
- **Release gate integration** (#317) - backend releases now run the full artifact-keeper-test suite (38 formats, stress, resilience, mesh) before proceeding
- **Quality of life improvements** (#298) - 9 features: configurable GC/lifecycle cron scheduling, stale proxy cache fallback, deletion replication to peers, webhook delivery retry with exponential backoff, soft token revocation with `last_used_at` tracking, per-repo cache TTL endpoint, search reindex API, quota warning events, and replication filters with regex include/exclude patterns

### Fixed
- **OCI v2 auth challenge uses wrong scheme/host behind reverse proxy** (#315, #316) - `Www-Authenticate` header now respects `X-Forwarded-Proto` and `X-Forwarded-Host`, fixing `docker login` failures when running behind Caddy, Nginx, or other reverse proxies
- **Maven SNAPSHOT re-upload and hard-delete** (#297, #301) - SNAPSHOT artifacts can now be re-uploaded (overwritten) as expected, and hard-delete properly removes files from storage
- **Scanner storage backend resolution** (#296, #301) - security scanners now use the configured storage backend (S3, Azure, GCS) instead of defaulting to filesystem
- **Format route key extraction** (#302) - fix repo key parsing for format handler routes when the key contains path separators
- **Private repository visibility enforcement** (#300) - anonymous users can no longer access private repository metadata
- **Storage probe path traversal** (#293, #308) - validate that health check storage probe paths stay within the base directory
- **Code scanning alerts** (#307) - address CodeQL alerts #16 and #39 for taint flow and input validation
- **Wasmtime CVE bump** (#292) - upgrade to wasmtime 24.0.6 for CVE-2026-27572 and CVE-2026-27204

### Tests
- Unit tests for ArtifactFilter matching logic (#309)
- E2E tests for Maven SNAPSHOT re-upload and S3 scanner (#304)
- Flaky cron policy test fix and Postgres added to coverage job (#311)
- Custom CodeQL workflow replacing default setup (#305)

### Changed
- Docker Hub documented as alternative registry (#289)
- Dependency bumps: actions/attest-build-provenance 3 to 4, SonarSource/sonarqube-scan-action 6 to 7

## [1.1.0-rc.4] - 2026-02-25

### Added
- **Service accounts and token scoping** (#205, #208, #209) - service account entities with API tokens, scope enforcement across all repository handlers, and RepoSelector-based token restrictions
- **Incus/LXC container image support** (#206) - new `incus` repository format implementing the SimpleStreams protocol for container and VM images
- **SSE event stream for live data refresh** (#269) - server-sent events endpoint allowing the web UI to receive real-time cache invalidation signals
- **Physical storage garbage collection** (#233) - background task to reclaim disk space from soft-deleted artifacts
- **Tag-filtered peer replication** (#243) - filter replication to only sync artifacts matching specified tag patterns
- **WASM plugin v2: handle-request** (#256) - plugins can now serve native package format wire protocols directly
- **`SKIP_ADMIN_PROVISIONING` env var** (#224) - skip admin user creation on first boot for SSO-only deployments
- **Artifact filter enforcement with retroactive sync** (#204) - evaluate filters against existing artifacts when policies change

### Fixed
- **Storage backend hardcoded to filesystem** (#237, #244, #245, #246) - use the configured storage backend (S3, Azure, GCS) instead of always defaulting to local filesystem
- **OIDC env var config ignored** (#249) - environment variable configuration for OIDC providers was not being read
- **Local login not blocked with SSO** (#223) - block local password login when SSO providers are configured
- **LRU eviction for size quotas** (#226) - change storage quota eviction from FIFO to least-recently-used ordering
- **Lifecycle policy execution** (#225) - implement `tag_pattern_keep` lifecycle policy type
- **Streaming uploads for Incus** (#217, #242) - fix chunked upload handling for large container images
- **96 code scanning alerts resolved** (#267, #268) - taint-flow fixes, safe string handling, and input validation improvements
- **DNS rebinding protection** - bound allocations, upgrade KDF from static HMAC to HKDF with domain separation
- **HTTPS enforced in Dockerfile healthchecks** (#251)

### Security
- **Privilege escalation fix** (#273) - enforce admin checks on user creation and all admin routes
- **Archive extraction hardening** (#274) - path traversal protection, safe file handling, parameterized SQL
- **Encryption and rate limiter hardening** (#275) - improved encryption key derivation, LDAP injection prevention, CSP headers, XSS/SSRF mitigations
- **SSRF and path traversal fixes** (#277) - close server-side request forgery vectors and path traversal in file operations
- **KDF upgrade** - migrate from static HMAC key to HKDF with domain separation, fix CodeQL hard-coded crypto alerts

### Changed
- SonarCloud scanner added to CI (#247)
- Code coverage reporting with cargo-llvm-cov (#229)
- All environment variables documented in .env.example (#227)
- Mergify auto-merge configuration (#215)
- Dependency bumps: actions/upload-artifact 4 to 6, actions/checkout 4 to 6, actions/attest-build-provenance 2 to 3

### Tests
- Unit test coverage increased toward 80% quality gate (#253, #254)

## [1.1.0-rc.3] - 2026-02-17

### Fixed
- **Token creation broken** (#195, #197) — `POST /api/v1/auth/tokens` and `DELETE /api/v1/auth/tokens/{token_id}` were documented in the OpenAPI spec but never registered in the router, causing silent 404s from the frontend
- **Non-admin users could request admin scope** (#197) — backend now returns 403 when a non-admin user attempts to create a token with the `admin` scope
- **Podman / standalone Docker Compose compatibility** (#194, #196) — SELinux `:z` bind-mount labels, replaced `service_completed_successfully` dependency with polling entrypoint, changed healthcheck from `/readyz` to `/livez`, downgraded web/caddy depends_on to `service_started`
- **Caddyfile missing `/livez` and `/readyz` routes** (#196) — reverse proxy now forwards liveness and readiness probes to the backend

### Added
- **OpenAPI route audit test** (#197) — `test_all_openapi_paths_have_handlers` cross-checks every documented endpoint against handler source files, catching annotated-but-unregistered routes at compile time

### Changed
- Renamed `UserResponse` to `AdminUserResponse` in users handler to avoid DTO collision (#187)
- CI skips Docker publish for docs-only changes (#185)

## [1.1.0-rc.2] - 2026-02-15

### Added
- **Promotion Workflow** (#151) — approval chains, age gates, signature verification, and rejection with audit trail
- **Auto-Promotion Rules Engine** (#152) — configurable rules for automatic artifact promotion based on quality gates, age, and scan results
- **K8s Health Probes & OpenTelemetry Tracing** (#147) — structured health endpoints for liveness/readiness and distributed tracing with span propagation
- **SECURITY.md** — vulnerability reporting policy

### Changed
- **UBI 9 Micro Runtime** (#160) — all containers migrated from Alpine to Red Hat UBI 9 Micro for STIG compliance
- **Container Hardening** (#163, #164) — Cosign image signing, Trivy vulnerability scanning in CI, and STIG hardening
- **UBI 9.5 → 9.7** (#170, #172, #173) and **Alpine 3.19 → 3.23** (#171)
- **SonarCloud Integration** (#158, #159, #162) — static analysis and Dockerfile scanning in CI
- **Dockerfiles Consolidated** (#157) — all Dockerfiles and Caddyfile moved to `docker/` directory
- **Deploy Folder Relocated** (#154, #155) — moved to `artifact-keeper-iac` repository
- **Self-Hosted ARC Runner** (#148) — smoke E2E tests run on self-hosted Actions Runner Controller
- **Dependabot Bumps** — codeql-action 3→4, upload-artifact 4→6, download-artifact 4→7, aws-actions/configure-aws-credentials 4→6, stale 9→10

### Fixed
- **Duplicate OpenAPI operationIds** (#182) — explicit operation IDs for sync_policies and repository_labels handlers to fix SDK generation
- **Release Build Pipeline** (#181) — add protoc installation and vendored OpenSSL for cross-platform binary builds
- **CI Pipeline Repairs** (#174, #175, #178) — Docker publish, security scan, and Trivy scan fixes
- **Native Test Scripts** (#177) — PyPI sed portability, NPM auth config, Cargo registry config fixes
- **E2E Test Failures** (#146, #180) — Go, Docker, Helm, Protobuf test fixes; switched release gate to smoke profile
- **arm64 Docker Builds** — use arch-appropriate protoc binary
- **Artifact Download Filter** — release workflow only downloads binary archives, not E2E artifacts

### Tests
- Backend unit test coverage pushed toward 80% (#153)

## [1.1.0-rc.1] - 2026-02-13

### Added
- **Artifact Health Scoring & Quality Gates** (#129)
  - Pluggable quality check system with composite health scores (A-F grade) and configurable quality gates for promotion gating
  - MetadataCompletenessChecker (all formats) and HelmLintChecker (in-process chart.tgz validation)
  - QualityCheckService orchestrator with weighted scoring (security=40, quality=25, license=20, metadata=15)
  - 15 new API endpoints under `/api/v1/quality`; async checks triggered on artifact upload
- **Sync Policy Engine & Background Sync Worker** (#109, #122)
  - Declarative label-based replication policies with JSONB selectors for repos and peers
  - 8 new API endpoints (`/api/v1/sync-policies`) for CRUD, evaluation, and preview
  - Peer instance labels API (`GET/PUT/POST/DELETE /api/v1/peers/:id/labels`) for `match_labels` resolution (#122)
  - Auto-evaluate triggers on repo label, peer label, and new peer registration changes (#122)
  - 5-minute periodic re-evaluation scheduler to catch drift (#122)
  - Background sync worker with per-peer sync windows, exponential backoff, and concurrent transfer limits
- **Remote Proxy Repositories** (#112)
  - Remote repos now proxy artifacts from upstream registries (npmjs.org, PyPI, Maven Central, etc.) on cache miss
  - Automatic local caching with 24-hour TTL and ETag-based revalidation
  - ProxyService wired into all 28 format handlers for download endpoints
  - Write guards return 405 Method Not Allowed on remote repos
- **Virtual Repository Resolution** (#112)
  - Virtual repos aggregate multiple member repos (local + remote) with priority-based resolution
  - Metadata merging for npm (`get_package_metadata`) and PyPI (`simple_project`) so native clients (`npm install`, `pip install`) work through virtual repos
  - Write guards return 400 Bad Request on virtual repos
  - Tarball URL rewriting to route downloads through the virtual repo key
- **Protobuf/BSR Format Support** (#119)
  - New `protobuf` repository format implementing BSR-compatible Connect RPC endpoints
  - 10 endpoints: GetModules, CreateModules, GetCommits, ListCommits, Upload, Download, GetLabels, CreateOrUpdateLabels, GetGraph, GetResources
  - Full proxy/virtual repository resolution support
- **Repository Key Renames** (#120) — `PATCH /api/v1/repositories/{key}` now accepts a `key` field to rename the URL slug
- **Repository Labels API** (#108)
- **Artifact Upload Sync Trigger** (#108)
- **Full-stack Kubernetes Manifest** (#104)
- **Proxy/Virtual E2E Test Suite** (#112)
  - 21-test script covering proxy downloads, write rejection, virtual resolution, and native client integration
  - Docker Compose `proxy` profile for CI
  - Bootstrap script creates remote, local, and virtual repos with member wiring
- **Mesh Replication E2E Workflow** (#127) — GitHub Actions workflow for automated mesh replication testing via ArgoCD
- **Stale Bot** (#121) — auto-labels inactive issues

### Fixed
- **Proxy cache key collision**: Metadata cached as file blocked tarball paths that needed same prefix as directory; fixed with `__content__` leaf file scheme (#112)
- Fix `replication_mode` enum type cast in sync policy evaluate (#126)
- Fix `format` column type mismatch in sync policy evaluate (#125)
- Fix peer instance labels auth middleware mismatch (#124)
- Use AWS default credential chain instead of env vars only (#106)
- Ensure admin login works on fresh installs and fix Dependency-Track startup race (#102)
- Add setup instructions to `admin.password` file so users know to login first (#100)
- Auto-enable NVD API 2.0 and add proxy passthrough for Dependency-Track (#98)
- Set global 512 MB body limit to prevent silent upload truncation (#97)

### Changed
- Moved `site/` to separate `artifact-keeper-site` repository (#101)

## [1.0.0-rc.3] - 2026-02-08

Bug fix release resolving 9 issues found by automated stress testing, plus build hygiene improvements.

### Fixed
- **Promotion handler**: Fix storage_key bind using `artifact.path` instead of `artifact.storage_key`, causing promoted artifacts to be undownloadable (#65, #72)
- **Promotion handler**: Replace direct `tokio::fs::copy` with `FilesystemStorage` abstraction to respect content-addressable sharding (#65, #72)
- **Repository key validation**: Add strict allowlist rejecting path traversal, XSS, SQL injection chars, null bytes, and keys over 128 characters (#69, #70)
- **Upload size limit**: Add `DefaultBodyLimit::max(512MB)` to repository router; Axum default 2MB was blocking legitimate uploads (#67)
- **Rate limiting**: Increase API rate limit from 100 to 1000 req/min, auth from 10 to 30 req/min (#66, #68, #71, #73)
- **Download panic**: Lowercase `X_ARTIFACT_STORAGE` header constant for `HeaderName::from_static()` compatibility
- Correct `AuthExtension` type in promotion handlers (#62)
- Remove extra blank lines in promotion handlers (#63)
- Fix pre-release banner overlapping content on mobile (#64)
- Use dev tag for main builds, latest only on release tags (#60)

### Added
- DevOps stress test agent script (12-phase, 71-test suite)

### Changed
- Documentation gaps filled for v1.0.0-a2 features (#61)

## [1.0.0-a2] - 2026-02-08

Second alpha release with staging promotion workflow, Dependency-Track monitoring, red team security hardening, and landing page refresh.

### Added
- **Staging Promotion Workflow**
  - New staging repository type for promotion-based artifact lifecycle
  - Promotion API endpoints for staging → release workflow
  - Policy gate integration for automated promotion decisions
  - Simplified promotion policy and handler code (#49)
- **Dependency-Track Monitoring** (#57)
  - Backend API for Dependency-Track integration
  - OpenSCAP and Dependency-Track added to health monitoring dashboard
- **Red Team Security Testing Suite** (#52)
- **STS Credential Rotation E2E Tests** (#56)
- **Pre-release banner** on landing page and README

### Changed
- Updated landing page to LCARS color scheme with new brand colors
- Pre-release banner changed from warning to release announcement

### Fixed
- Refresh credentials before presigned URL generation (#55)
- Calculate storage_used_bytes for repository list view (#58)
- Position banner above navbar without overlap
- CI fixes: fmt, clippy, and broken migration (#48)
- CI fixes: PKI file handling in E2E tests (tar archive, explicit patterns)

### Security
- Hardened 7 vulnerabilities identified by red team scan (#53)

## [1.0.0-a1] - 2026-02-06

First public alpha release, announced on Hacker News.

### Added
- **OWASP Dependency-Track Integration** (#46)
  - Docker service configuration for Dependency-Track API server
  - Rust API client for SBOM upload, vulnerability findings, policy violations
  - Comprehensive SBOM & Dependency-Track documentation
  - E2E test script for Dependency-Track integration
- **Multi-cloud Storage Backends** (#45)
  - Azure Blob Storage backend
  - Google Cloud Storage backend
  - Artifactory migration mode with fallback path support
- **S3 Direct Downloads** (#38)
  - 302 redirect to presigned S3 URLs
  - CloudFront signed URL generation
  - Configurable via `STORAGE_S3_REDIRECT_DOWNLOADS`
- **SBOM Generation & gRPC API** (#31)
  - CycloneDX and SPDX format support
  - CVE history tracking
  - gRPC service for SBOM operations
- **WASM Plugin E2E Tests** (#37)
- **SSO E2E Test Suite** - LDAP/OIDC/SAML authentication tests
- **TOTP Two-Factor Authentication**
- **Privacy Policy Page** for app store submissions
- **Migration Pipeline** - Artifactory and Nexus OSS support
- **OpenSCAP Multi-arch Image** with scanning enabled by default

### Changed
- Simplified and deduplicated code across backend and scripts (#27)
- Updated docs to use peer replication model instead of edge nodes
- Docker build cache optimization with cargo-chef and native arm64 runners
- Streamlined CI pipeline with CI/CD diagram in README

### Fixed
- E2E test infrastructure improvements (bootstrap, setup containers)
- CI workflow fixes (clippy warnings, YAML indentation)
- SSO e2e test infrastructure fixes
- Logo resized to exact 512x512 for app stores
- Metrics endpoint proxied through Caddy
- Various Caddy and port configuration fixes

### Security
- Secure first-boot admin password with API lock
- GitGuardian integration for secret scanning

## [1.0.0-rc.1] - 2026-02-03

### Added
- First-boot admin provisioning and Caddy reverse proxy
- OpenSCAP compliance scanner service
- Package auto-population and build tracking API
- httpOnly cookies, download tickets, and remote instance proxy
- SSO single-use exchange codes for secure token passing
- Complete SSO auth flows with real LDAP bind, SAML endpoints, and encryption key handling
- Admin-configurable SSO providers (OIDC, LDAP, SAML)
- Web frontend service in all docker-compose files
- Native apps section on landing page with macOS, iOS, Android demos

### Changed
- Use pre-built images from ghcr.io instead of local builds
- Rename frontend to web in Docker deployment docs
- Use standard port 3000 and correct BACKEND_URL env var for web service
- Clean up operations services and handlers
- Simplify SSO backend code for clarity and consistency

### Fixed
- NPM tarball URL and integrity hash in package metadata
- Hardcoded localhost:9080 fallback URLs removed from frontend
- Logo transparency using flood-fill to preserve silver highlights
- Duplicate heading on docs welcome page
- GitHub links updated to point to org instead of repo
- CORS credentials support for dev mode
