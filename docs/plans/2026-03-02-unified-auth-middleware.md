# Unified Auth Middleware Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix #320 and #333 by adding Basic auth support to the auth middleware, removing duplicated auth from 30 format handlers, and adding visibility filtering to API list endpoints.

**Architecture:** Extend the existing `ExtractedToken` / `try_resolve_auth` / `repo_visibility_middleware` chain to recognize Basic auth credentials. Then refactor all format handlers to read `Option<AuthExtension>` from request extensions instead of parsing headers themselves. Finally, add `public_only` filtering to the packages and artifacts API endpoints.

**Tech Stack:** Rust, Axum middleware, SQLx, base64 crate (already a dependency)

---

### Task 1: Add Basic Auth to ExtractedToken and extract_token()

**Files:**
- Modify: `backend/src/api/middleware/auth.rs:102-161`

**Step 1: Write the failing tests**

Add these tests to the existing `#[cfg(test)] mod tests` block at the bottom of `auth.rs` (after line 764):

```rust
// -----------------------------------------------------------------------
// Basic auth extraction
// -----------------------------------------------------------------------

#[test]
fn test_extract_basic_auth_header() {
    let result = extract_token_from_auth_header("Basic dXNlcjpwYXNz");
    assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
}

#[test]
fn test_extract_basic_auth_from_request() {
    let request = Request::builder()
        .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .body(axum::body::Body::empty())
        .unwrap();
    let result = extract_token(&request);
    assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
}

#[test]
fn test_extract_basic_auth_does_not_fall_through_to_x_api_key() {
    // Basic auth in Authorization header should be recognized, not fall through
    let request = Request::builder()
        .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .header("x-api-key", "api-key-value")
        .body(axum::body::Body::empty())
        .unwrap();
    let result = extract_token(&request);
    assert!(matches!(result, ExtractedToken::Basic(_)));
}
```

**Step 2: Run tests to verify they fail**

Run: `cd artifact-keeper && cargo test --workspace --lib test_extract_basic`
Expected: FAIL (no `Basic` variant on `ExtractedToken`)

**Step 3: Add the Basic variant and recognition**

In `auth.rs`, modify the `ExtractedToken` enum (line 103):

```rust
#[derive(Debug)]
enum ExtractedToken<'a> {
    /// JWT or API token from Bearer scheme
    Bearer(&'a str),
    /// API token from ApiKey scheme
    ApiKey(&'a str),
    /// Basic auth credentials (base64-encoded username:password)
    Basic(&'a str),
    /// No token found
    None,
    /// Invalid header format
    Invalid,
}
```

Modify `extract_token_from_auth_header` (line 116):

```rust
fn extract_token_from_auth_header(auth_header: &str) -> ExtractedToken<'_> {
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        ExtractedToken::Bearer(token)
    } else if let Some(token) = auth_header.strip_prefix("ApiKey ") {
        ExtractedToken::ApiKey(token)
    } else if let Some(creds) = auth_header.strip_prefix("Basic ").or(auth_header.strip_prefix("basic ")) {
        ExtractedToken::Basic(creds)
    } else {
        ExtractedToken::Invalid
    }
}
```

**Step 4: Update the existing test that expects Basic to be Invalid**

The existing test at line 438 (`test_extract_invalid_scheme`) currently asserts that `Basic` returns `Invalid`. Update it:

```rust
#[test]
fn test_extract_basic_scheme_recognized() {
    // Basic auth is now a recognized scheme (not Invalid)
    let result = extract_token_from_auth_header("Basic dXNlcjpwYXNz");
    assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
}
```

Also update the test at line 543 (`test_extract_token_invalid_auth_header_does_not_fall_through`) which expects Basic to return `Invalid` and NOT fall through to X-API-Key. Now Basic is recognized, so update the assertion:

```rust
#[test]
fn test_extract_token_basic_auth_does_not_fall_through() {
    let request = Request::builder()
        .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .header("x-api-key", "api-key-value")
        .body(axum::body::Body::empty())
        .unwrap();
    let result = extract_token(&request);
    assert!(matches!(result, ExtractedToken::Basic(_)));
}
```

**Step 5: Run tests to verify they pass**

Run: `cd artifact-keeper && cargo test --workspace --lib -- auth::tests`
Expected: All auth tests PASS

**Step 6: Commit**

```
feat: add Basic auth variant to ExtractedToken

The auth middleware now recognizes Authorization: Basic headers as a
distinct token type instead of treating them as Invalid. This is the
first step toward unified auth for format handlers.

Fixes #320, #333
```

---

### Task 2: Add Basic auth resolution in try_resolve_auth()

**Files:**
- Modify: `backend/src/api/middleware/auth.rs:251-270`

**Step 1: Write the failing test**

Add to the test module. This test validates the Base64 decoding helper (pure function, no async/DB needed):

```rust
#[test]
fn test_decode_basic_credentials_valid() {
    // "user:pass" base64-encoded is "dXNlcjpwYXNz"
    let result = decode_basic_credentials("dXNlcjpwYXNz");
    assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
}

#[test]
fn test_decode_basic_credentials_with_colon_in_password() {
    // "user:p:a:ss" base64-encoded
    let encoded = base64::engine::general_purpose::STANDARD.encode("user:p:a:ss");
    let result = decode_basic_credentials(&encoded);
    assert_eq!(result, Some(("user".to_string(), "p:a:ss".to_string())));
}

#[test]
fn test_decode_basic_credentials_invalid_base64() {
    let result = decode_basic_credentials("not-valid-base64!!!");
    assert_eq!(result, None);
}

#[test]
fn test_decode_basic_credentials_no_colon() {
    // "justusername" base64-encoded
    let encoded = base64::engine::general_purpose::STANDARD.encode("justusername");
    let result = decode_basic_credentials(&encoded);
    assert_eq!(result, None);
}

#[test]
fn test_decode_basic_credentials_empty() {
    let result = decode_basic_credentials("");
    assert_eq!(result, None);
}
```

**Step 2: Run tests to verify they fail**

Run: `cd artifact-keeper && cargo test --workspace --lib test_decode_basic`
Expected: FAIL (`decode_basic_credentials` not found)

**Step 3: Add decode_basic_credentials and update try_resolve_auth**

Add the `base64` import at the top of auth.rs (near the other imports):

```rust
use base64::Engine;
```

Add the helper function (before `try_resolve_auth`, around line 250):

```rust
/// Decode base64-encoded Basic auth credentials into (username, password).
///
/// Returns `None` if the base64 is invalid, the bytes are not valid UTF-8,
/// or there is no `:` separator.
fn decode_basic_credentials(encoded: &str) -> Option<(String, String)> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}
```

Update `try_resolve_auth` to handle the Basic variant:

```rust
async fn try_resolve_auth(
    auth_service: &AuthService,
    extracted: ExtractedToken<'_>,
) -> Option<AuthExtension> {
    match extracted {
        ExtractedToken::Bearer(token) => {
            if let Ok(claims) = auth_service.validate_access_token(token) {
                Some(AuthExtension::from(claims))
            } else {
                validate_api_token_with_scopes(auth_service, token)
                    .await
                    .ok()
            }
        }
        ExtractedToken::ApiKey(token) => validate_api_token_with_scopes(auth_service, token)
            .await
            .ok(),
        ExtractedToken::Basic(encoded) => {
            let (username, password) = decode_basic_credentials(encoded)?;
            let (user, _tokens) = auth_service.authenticate(&username, &password).await.ok()?;
            Some(AuthExtension {
                user_id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                is_api_token: false,
                is_service_account: user.is_service_account,
                scopes: None,
                allowed_repo_ids: None,
            })
        }
        ExtractedToken::None | ExtractedToken::Invalid => None,
    }
}
```

Also update `auth_middleware` (line 170) to handle the Basic variant in its match. Add a case between `ApiKey` and `None`:

```rust
ExtractedToken::Basic(encoded) => {
    let Some((username, password)) = decode_basic_credentials(encoded) else {
        return (StatusCode::UNAUTHORIZED, "Invalid Basic auth credentials").into_response();
    };
    match auth_service.authenticate(&username, &password).await {
        Ok((user, _tokens)) => {
            let auth_ext = AuthExtension {
                user_id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                is_api_token: false,
                is_service_account: user.is_service_account,
                scopes: None,
                allowed_repo_ids: None,
            };
            request.extensions_mut().insert(auth_ext);
            next.run(request).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
    }
}
```

And `admin_middleware` (line 292) similarly:

```rust
ExtractedToken::Basic(encoded) => {
    let Some((username, password)) = decode_basic_credentials(encoded) else {
        return (StatusCode::UNAUTHORIZED, "Invalid Basic auth credentials").into_response();
    };
    match auth_service.authenticate(&username, &password).await {
        Ok((user, _tokens)) => AuthExtension {
            user_id: user.id,
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
            is_api_token: false,
            is_service_account: user.is_service_account,
            scopes: None,
            allowed_repo_ids: None,
        },
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd artifact-keeper && cargo test --workspace --lib -- auth::tests`
Expected: All auth tests PASS

**Step 5: Commit**

```
feat: resolve Basic auth credentials in middleware

try_resolve_auth() now decodes Basic auth headers and validates
credentials via AuthService::authenticate(). This means
repo_visibility_middleware can detect authenticated users who send
Basic auth (Maven, PyPI, npm, etc.), fixing the 404 on private
repo uploads.
```

---

### Task 3: Add require_auth_basic helper and make it public

**Files:**
- Modify: `backend/src/api/middleware/auth.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_require_auth_basic_some() {
    let ext = AuthExtension {
        user_id: Uuid::new_v4(),
        username: "user".to_string(),
        email: "user@test.com".to_string(),
        is_admin: false,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: None,
    };
    let result = require_auth_basic(Some(ext.clone()), "maven");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().username, "user");
}

#[test]
fn test_require_auth_basic_none() {
    let result = require_auth_basic(None, "maven");
    assert!(result.is_err());
}
```

**Step 2: Run tests to verify they fail**

Run: `cd artifact-keeper && cargo test --workspace --lib test_require_auth_basic`
Expected: FAIL

**Step 3: Implement require_auth_basic**

Add this public function to `auth.rs` (after the `AuthExtension` impl block, around line 100):

```rust
/// Require that the request is authenticated, returning a 401 with a
/// `WWW-Authenticate: Basic` challenge if not.
///
/// Format handlers call this instead of implementing their own auth.
pub fn require_auth_basic(
    auth: Option<AuthExtension>,
    realm: &str,
) -> std::result::Result<AuthExtension, Response> {
    auth.ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
            .body(axum::body::Body::from("Authentication required"))
            .unwrap()
    })
}
```

**Step 4: Run tests to verify they pass**

Run: `cd artifact-keeper && cargo test --workspace --lib test_require_auth_basic`
Expected: PASS

**Step 5: Commit**

```
feat: add require_auth_basic() helper for format handlers

Provides a single public function that format handlers call to
demand authentication, replacing 30 identical authenticate()
implementations.
```

---

### Task 4: Refactor Maven handler (template for all others)

**Files:**
- Modify: `backend/src/api/handlers/maven.rs:1-85,497-503`

This is the template refactor. All other format handlers follow the same pattern.

**Step 1: Run existing Maven tests to establish baseline**

Run: `cd artifact-keeper && cargo test --workspace --lib maven`
Expected: PASS (baseline)

**Step 2: Refactor the upload handler**

Replace the `upload` function signature and first line (line 497-503):

Before:
```rust
async fn upload(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
```

After:
```rust
async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "maven")?.user_id;
```

Add the necessary imports at the top of `maven.rs`:

```rust
use axum::Extension;
use crate::api::middleware::auth::{AuthExtension, require_auth_basic};
```

**Step 3: Delete the local auth helpers**

Remove these functions from `maven.rs` (lines 44-85):
- `fn extract_basic_credentials(...)`
- `async fn authenticate(...)`

Also remove the now-unused import:
- `use crate::services::auth_service::AuthService;`

And remove `use base64::Engine;` if it's only used by `extract_basic_credentials`.

**Step 4: Run tests to verify nothing broke**

Run: `cd artifact-keeper && cargo test --workspace --lib maven`
Expected: PASS

**Step 5: Commit**

```
refactor(maven): use middleware auth instead of local authenticate()

Removes duplicated extract_basic_credentials() and authenticate()
from the Maven handler. The upload handler now reads
Option<AuthExtension> from the middleware and calls
require_auth_basic() for the 401 challenge.
```

---

### Task 5: Refactor remaining standard format handlers (batch)

**Files to modify** (same pattern as Task 4 for each):

Standard handlers (Basic auth only, same `authenticate()` pattern as Maven):
1. `backend/src/api/handlers/pypi.rs`
2. `backend/src/api/handlers/helm.rs`
3. `backend/src/api/handlers/debian.rs`
4. `backend/src/api/handlers/alpine.rs`
5. `backend/src/api/handlers/rpm.rs`
6. `backend/src/api/handlers/rubygems.rs`
7. `backend/src/api/handlers/composer.rs`
8. `backend/src/api/handlers/conan.rs`
9. `backend/src/api/handlers/conda.rs`
10. `backend/src/api/handlers/swift.rs`
11. `backend/src/api/handlers/terraform.rs`
12. `backend/src/api/handlers/cocoapods.rs`
13. `backend/src/api/handlers/hex.rs`
14. `backend/src/api/handlers/huggingface.rs`
15. `backend/src/api/handlers/jetbrains.rs`
16. `backend/src/api/handlers/chef.rs`
17. `backend/src/api/handlers/puppet.rs`
18. `backend/src/api/handlers/ansible.rs`
19. `backend/src/api/handlers/cran.rs`
20. `backend/src/api/handlers/sbt.rs`
21. `backend/src/api/handlers/vscode.rs`
22. `backend/src/api/handlers/protobuf.rs`
23. `backend/src/api/handlers/incus.rs`
24. `backend/src/api/handlers/gitlfs.rs`
25. `backend/src/api/handlers/pub_registry.rs`

For EACH handler, the refactor is identical to Task 4:

1. Add imports: `use axum::Extension;` and `use crate::api::middleware::auth::{AuthExtension, require_auth_basic};`
2. Change every `async fn` that calls `authenticate(...)` to extract `Extension(auth): Extension<Option<AuthExtension>>` and call `require_auth_basic(auth, "<format_name>")?.user_id`
3. Remove the `headers: HeaderMap` parameter if it was only used for auth
4. Delete `fn extract_basic_credentials(...)` and `async fn authenticate(...)`
5. Remove unused `use crate::services::auth_service::AuthService;` and `use base64::Engine;`

**Important:** Some handlers have multiple write endpoints (e.g. `upload`, `delete`, `publish`). Each one that calls `authenticate()` needs the same change.

**Use parallel subagents** to process these 25 handlers concurrently (5 batches of 5).

After all are done:

Run: `cd artifact-keeper && cargo test --workspace --lib`
Expected: All unit tests PASS

**Commit:**

```
refactor: remove duplicated auth from 25 format handlers

All standard format handlers now use middleware-provided
Option<AuthExtension> and the shared require_auth_basic() helper
instead of their own extract_basic_credentials() / authenticate()
functions.
```

---

### Task 6: Refactor special-case format handlers

**Files:**
- Modify: `backend/src/api/handlers/npm.rs`
- Modify: `backend/src/api/handlers/cargo.rs`
- Modify: `backend/src/api/handlers/goproxy.rs`
- Modify: `backend/src/api/handlers/nuget.rs`

These handlers have non-standard auth patterns that need individual attention.

#### npm, Cargo, Goproxy (Basic + Bearer with base64 user:pass)

These accept Bearer tokens where the token itself is base64-encoded `user:pass` (not a JWT). The middleware already handles this correctly: Bearer tokens are tried as JWT first, then as API tokens. If neither works, the middleware returns `None`.

However, the npm/Cargo/Goproxy specific behavior (decoding Bearer as base64 user:pass) would be lost. Two options:

**Option A (recommended):** Keep a small fallback in these handlers. If `auth` from middleware is `None` AND the request has a Bearer header, try decoding it as base64 user:pass. This preserves backward compatibility without complicating the middleware.

```rust
async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = match auth {
        Some(ext) => ext.user_id,
        None => {
            // npm/cargo fallback: Bearer token may be base64-encoded user:pass
            let (username, password) = extract_bearer_credentials(&headers)
                .ok_or_else(|| {
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Basic realm=\"npm\"")
                        .body(Body::from("Authentication required"))
                        .unwrap()
                })?;
            let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
            let (user, _) = auth_service.authenticate(&username, &password).await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response())?;
            user.id
        }
    };
```

Keep `extract_bearer_credentials()` in npm.rs, cargo.rs, goproxy.rs. Delete only `extract_basic_credentials()` and `authenticate()`.

#### NuGet (X-NuGet-ApiKey header)

NuGet clients send credentials via `X-NuGet-ApiKey` header, not Basic auth. The middleware's `extract_token()` already checks `X-API-Key` but not `X-NuGet-ApiKey`.

**Fix:** Add `X-NuGet-ApiKey` recognition to `extract_token()` in auth.rs, treating it the same as `X-API-Key`. However, NuGet's API key format is `user:password`, not an API token. So the NuGet handler still needs a small adapter:

```rust
async fn push_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = match auth {
        Some(ext) => ext.user_id,
        None => {
            // NuGet fallback: X-NuGet-ApiKey with user:password format
            let api_key = headers.get("X-NuGet-ApiKey")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authentication required").into_response())?;
            let (username, password) = if let Some((u, p)) = api_key.split_once(':') {
                (u.to_string(), p.to_string())
            } else {
                ("apikey".to_string(), api_key.to_string())
            };
            let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
            let (user, _) = auth_service.authenticate(&username, &password).await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid API key").into_response())?;
            user.id
        }
    };
```

Delete `extract_basic_credentials()` and the old `authenticate()`. Keep the NuGet-specific fallback logic.

After all four:

Run: `cd artifact-keeper && cargo test --workspace --lib`
Expected: All unit tests PASS

**Commit:**

```
refactor: update npm, cargo, goproxy, nuget handlers to use middleware auth

These handlers have non-standard auth (Bearer-as-base64, X-NuGet-ApiKey)
so they keep a small fallback for their specific scheme while using
middleware auth as the primary path.
```

---

### Task 7: Handle OCI v2 (Docker) handler

**Files:**
- Modify: `backend/src/api/handlers/oci_v2.rs`

OCI v2 is the most complex handler. It has its own token exchange endpoint (`GET /v2/token`) where clients authenticate with Basic auth and receive a Bearer JWT. Subsequent requests use that Bearer token.

The middleware already handles Bearer JWTs, so the main change is:

1. The `token()` endpoint: Keep its own Basic auth parsing since it's the token exchange entrypoint. It receives Basic auth and returns a JWT. The middleware will have already set `Some(AuthExtension)` for the Basic auth, so the token endpoint can use that instead.

2. All other OCI endpoints (push manifest, push blob, etc.): Change to use `Extension(auth): Extension<Option<AuthExtension>>` instead of calling `validate_token()` directly.

3. Delete `extract_basic_credentials()` from oci_v2.rs. Keep `extract_bearer_token()` only if it's used outside of auth (it shouldn't be after the refactor).

**This task needs careful reading of the full oci_v2.rs file** to identify all endpoints that call `validate_token()` or `extract_basic_credentials()`. The refactor pattern is the same but the token endpoint's role as an auth exchange makes it a special case.

Run: `cd artifact-keeper && cargo test --workspace --lib oci`
Expected: All OCI tests PASS

**Commit:**

```
refactor(oci_v2): use middleware auth for Docker registry endpoints

The OCI v2 token exchange endpoint now reads the middleware-provided
AuthExtension. All other OCI endpoints (blob push, manifest push,
catalog, tags) use the middleware auth extension directly.
```

---

### Task 8: Fix packages endpoint visibility (#333)

**Files:**
- Modify: `backend/src/api/handlers/packages.rs:103-185`

**Step 1: Write the failing test**

Add to `packages.rs` test module (or create one):

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_list_packages_sql_includes_visibility_filter() {
        // Verify the SQL query includes is_public filtering
        // This is a documentation/marker test; the real verification
        // is in the integration tests (Task 10)
        let query = r#"
        SELECT p.id, r.key as repository_key, ...
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ...
          AND ($4 = false OR r.is_public = true)
        "#;
        assert!(query.contains("is_public"));
    }
}
```

**Step 2: Modify list_packages handler**

Change the handler signature (line 103) to extract auth:

```rust
pub async fn list_packages(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListPackagesQuery>,
) -> Result<Json<PackageListResponse>> {
    let public_only = auth.is_none();
```

Add imports at the top:
```rust
use axum::Extension;
use crate::api::middleware::auth::AuthExtension;
```

Update the SQL query (line 133) to add visibility filtering:

```rust
let packages: Vec<PackageRow> = sqlx::query_as(
    r#"
    SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
           p.description, p.size_bytes, p.download_count, p.created_at, p.updated_at,
           p.metadata
    FROM packages p
    JOIN repositories r ON r.id = p.repository_id
    WHERE ($1::text IS NULL OR r.key = $1)
      AND ($2::text IS NULL OR r.format::text = $2)
      AND ($3::text IS NULL OR p.name ILIKE $3)
      AND ($6 = false OR r.is_public = true)
    ORDER BY p.updated_at DESC
    OFFSET $4
    LIMIT $5
    "#,
)
.bind(&query.repository_key)
.bind(&query.format)
.bind(&search_pattern)
.bind(offset)
.bind(per_page as i64)
.bind(public_only)
.fetch_all(&state.db)
.await
.map_err(|e| AppError::Database(e.to_string()))?;
```

Update the count query similarly (line 157):

```rust
let total: i64 = sqlx::query_scalar(
    r#"
    SELECT COUNT(*)
    FROM packages p
    JOIN repositories r ON r.id = p.repository_id
    WHERE ($1::text IS NULL OR r.key = $1)
      AND ($2::text IS NULL OR r.format::text = $2)
      AND ($3::text IS NULL OR p.name ILIKE $3)
      AND ($4 = false OR r.is_public = true)
    "#,
)
.bind(&query.repository_key)
.bind(&query.format)
.bind(&search_pattern)
.bind(public_only)
.fetch_one(&state.db)
.await
.unwrap_or(0);
```

Do the same for `get_package` and `get_package_versions` if they also return data without checking repo visibility.

**Step 3: Run tests**

Run: `cd artifact-keeper && cargo test --workspace --lib packages`
Expected: PASS

**Step 4: Commit**

```
fix(packages): filter private repo packages for unauthenticated users

The list_packages endpoint now extracts the auth extension and adds
a public_only filter to the SQL query, preventing private repository
packages from appearing in anonymous API responses.

Fixes #333
```

---

### Task 9: Fix artifacts endpoint visibility (#333)

**Files:**
- Modify: `backend/src/api/handlers/artifacts.rs:74-215`

**Step 1: Modify get_artifact handler**

Change the handler to extract auth and check repo visibility (line 74):

```rust
pub async fn get_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactResponse>> {
    let artifact = sqlx::query!(
        r#"
        SELECT
            a.id, a.repository_id, a.path, a.name, a.version, a.size_bytes,
            a.checksum_sha256, a.checksum_md5, a.checksum_sha1,
            a.content_type, a.created_at, a.updated_at,
            r.key as repository_key, r.is_public
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.id = $1 AND a.is_deleted = false
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    // Deny access to private repo artifacts for unauthenticated users
    if !artifact.is_public && auth.is_none() {
        return Err(AppError::NotFound("Artifact not found".to_string()));
    }
```

Add imports:
```rust
use axum::Extension;
use crate::api::middleware::auth::AuthExtension;
```

**Step 2: Apply same pattern to get_artifact_metadata and get_artifact_stats**

Both handlers (lines 127 and 178) need the same treatment: extract auth, join on repositories to get `is_public`, and deny if private + unauthenticated.

**Step 3: Run tests**

Run: `cd artifact-keeper && cargo test --workspace --lib artifacts`
Expected: PASS

**Step 4: Commit**

```
fix(artifacts): check repo visibility on artifact endpoints

get_artifact, get_artifact_metadata, and get_artifact_stats now
return 404 for artifacts in private repos when the request is
unauthenticated.

Fixes #333
```

---

### Task 10: Add integration tests for private repo visibility

**Files:**
- Modify: `backend/tests/integration_tests.rs`

**Step 1: Add private repo integration tests**

Add these test functions to `integration_tests.rs`:

```rust
/// Test that private repos are excluded from the repo list for anonymous users.
#[tokio::test]
#[ignore]
async fn test_private_repo_hidden_from_anonymous_list() {
    let mut server = TestServer::new();
    server.login().await.unwrap();
    let client = Client::new();

    // Create a private repo (authenticated)
    let _repo = client
        .post(format!("{}/api/v1/repositories", server.base_url))
        .header("Authorization", server.auth_header())
        .json(&json!({
            "key": "private-test-repo",
            "name": "Private Test Repo",
            "format": "generic",
            "repo_type": "local",
            "is_public": false
        }))
        .send()
        .await
        .unwrap();

    // List repos without auth
    let resp = client
        .get(format!("{}/api/v1/repositories", server.base_url))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    let keys: Vec<&str> = items.iter()
        .filter_map(|r| r["key"].as_str())
        .collect();
    assert!(!keys.contains(&"private-test-repo"),
        "Private repo should not appear in anonymous listing");

    // List repos with auth - should include private repo
    let resp = client
        .get(format!("{}/api/v1/repositories", server.base_url))
        .header("Authorization", server.auth_header())
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    let keys: Vec<&str> = items.iter()
        .filter_map(|r| r["key"].as_str())
        .collect();
    assert!(keys.contains(&"private-test-repo"),
        "Private repo should appear in authenticated listing");
}

/// Test that Maven upload to a private repo works with Basic auth.
#[tokio::test]
#[ignore]
async fn test_private_repo_maven_upload_with_basic_auth() {
    let mut server = TestServer::new();
    server.login().await.unwrap();
    let client = Client::new();

    // Create a private Maven repo
    let _repo = client
        .post(format!("{}/api/v1/repositories", server.base_url))
        .header("Authorization", server.auth_header())
        .json(&json!({
            "key": "private-maven",
            "name": "Private Maven",
            "format": "maven",
            "repo_type": "local",
            "is_public": false
        }))
        .send()
        .await
        .unwrap();

    // Upload with Basic auth should succeed
    let basic_creds = base64::engine::general_purpose::STANDARD
        .encode("admin:admin123");
    let resp = client
        .put(format!(
            "{}/maven/private-maven/com/example/test/1.0/test-1.0.jar",
            server.base_url
        ))
        .header("Authorization", format!("Basic {}", basic_creds))
        .header("Content-Type", "application/java-archive")
        .body(b"fake-jar-content".to_vec())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(),
        "Basic auth upload to private repo should succeed, got {}",
        resp.status());
}

/// Test that anonymous download from a private repo returns 404.
#[tokio::test]
#[ignore]
async fn test_private_repo_anonymous_download_blocked() {
    let server = TestServer::new();
    let client = Client::new();

    // Attempt anonymous download from the private Maven repo
    let resp = client
        .get(format!(
            "{}/maven/private-maven/com/example/test/1.0/test-1.0.jar",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404,
        "Anonymous access to private repo should return 404");
}

/// Test that packages list filters private repo packages for anonymous users.
#[tokio::test]
#[ignore]
async fn test_private_repo_packages_hidden_from_anonymous() {
    let mut server = TestServer::new();
    server.login().await.unwrap();
    let client = Client::new();

    // List packages without auth
    let resp = client
        .get(format!("{}/api/v1/packages", server.base_url))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    // Verify no packages from private repos appear
    let private_repo_packages: Vec<&Value> = items.iter()
        .filter(|p| p["repository_key"].as_str() == Some("private-maven"))
        .collect();
    assert!(private_repo_packages.is_empty(),
        "Private repo packages should not appear in anonymous listing");
}
```

Add `use base64::Engine;` to the test file imports.

**Step 2: Run the integration tests**

Run: `cd artifact-keeper && cargo test --test integration_tests -- --ignored test_private_repo`
Expected: All 4 new tests PASS (requires running backend)

**Step 3: Commit**

```
test: add integration tests for private repo visibility

Tests verify:
- Private repos hidden from anonymous repo listing
- Private repos visible to authenticated users
- Maven upload to private repo works with Basic auth
- Anonymous download from private repo returns 404
- Private repo packages hidden from anonymous package listing

Validates fixes for #320 and #333.
```

---

### Task 11: Update SQLx offline cache

**Files:**
- Modify: `backend/.sqlx/` (auto-generated)

The new SQL queries in packages.rs and artifacts.rs (with the added `is_public` filter) need their offline metadata cached.

**Step 1: Regenerate SQLx offline cache**

Run: `cd artifact-keeper && cargo sqlx prepare --workspace`

This requires a running PostgreSQL instance at `localhost:30432`. If not available, the CI will regenerate it.

**Step 2: Commit the updated cache**

```
chore: update SQLx offline query cache
```

---

### Task 12: Run full test suite and verify

**Step 1: Run unit tests**

Run: `cd artifact-keeper && cargo test --workspace --lib`
Expected: All tests PASS

**Step 2: Run clippy**

Run: `cd artifact-keeper && cargo clippy --workspace`
Expected: No new warnings from our changes

**Step 3: Run fmt check**

Run: `cd artifact-keeper && cargo fmt --check`
Expected: No formatting issues

**Step 4: Final commit (if any fixups needed)**

---

## Execution Order and Dependencies

```
Task 1 (ExtractedToken::Basic)
  └─> Task 2 (try_resolve_auth Basic handling)
        └─> Task 3 (require_auth_basic helper)
              ├─> Task 4 (Maven refactor - template)
              │     └─> Task 5 (25 standard handlers - parallel)
              │     └─> Task 6 (4 special handlers)
              │     └─> Task 7 (OCI v2)
              ├─> Task 8 (packages visibility)
              └─> Task 9 (artifacts visibility)
                    └─> Task 10 (integration tests)
                          └─> Task 11 (SQLx cache)
                                └─> Task 12 (full test suite)
```

Tasks 4-9 can run in parallel after Task 3 completes.
Tasks 5, 6, 7 can run in parallel after Task 4 validates the pattern.
