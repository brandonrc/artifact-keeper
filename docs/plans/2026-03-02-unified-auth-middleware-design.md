# Unified Auth Middleware for Format Handlers

Fixes: [#333](https://github.com/artifact-keeper/artifact-keeper/issues/333), [#320](https://github.com/artifact-keeper/artifact-keeper/issues/320)

## Problem

Two related bugs share a root cause in the auth middleware:

**Issue #320**: Authenticated users get 404 when uploading to private repos via format handlers (Maven, PyPI, etc.). The `repo_visibility_middleware` runs before the handler, calls `extract_token()` to detect auth, but `extract_token()` only recognizes Bearer/ApiKey/Cookie schemes. It does not recognize `Authorization: Basic ...` headers. So it treats Basic-auth users as anonymous and returns 404 for private repos before the handler ever runs.

**Issue #333**: Unauthenticated users see private repos in API listing responses. The `/api/v1/packages` and `/api/v1/artifacts` handlers don't extract the auth extension or apply visibility filtering.

Additionally, 31 format handlers each contain their own copy of `extract_basic_credentials()` and `authenticate()`, creating ~1,500 lines of duplicated auth code that bypasses the middleware entirely.

## Design

### 1. Extend `extract_token()` with Basic Auth

Add `ExtractedToken::Basic(&str)` variant to handle the `Basic ` prefix in Authorization headers.

In `try_resolve_auth()`, add a handler for the Basic variant that:
- Decodes the base64 payload
- Splits on `:` to get username and password
- Calls `auth_service.authenticate(username, password)`
- Returns `AuthExtension` on success, `None` on failure

After this change, `repo_visibility_middleware` correctly detects Basic auth users, inserts `Some(AuthExtension)` into request extensions, and allows access to private repos.

### 2. Shared `require_auth()` Helper

Add a helper function that format handlers call instead of implementing their own auth:

```rust
pub fn require_auth_basic(
    auth: Option<AuthExtension>,
    realm: &str,
) -> Result<AuthExtension, Response> {
    auth.ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", format!("Basic realm=\"{realm}\""))
            .body(Body::from("Authentication required"))
            .unwrap()
    })
}
```

### 3. Refactor Format Handlers

For each of the 31 format handlers:

- Change write-path handler signatures to extract `Extension(auth): Extension<Option<AuthExtension>>`
- Replace `authenticate(&state.db, &state.config, &headers).await?` with `require_auth_basic(auth, "format_name")?.user_id`
- Delete the per-handler `authenticate()` and `extract_basic_credentials()` functions
- Read-path handlers (downloads) remain unchanged; they don't require auth

Special cases:
- **NuGet**: Also accepts `X-NuGet-ApiKey`. Add this as an alias in `extract_token()`.
- **npm, Cargo, Goproxy**: Accept both Basic and Bearer. Already handled since the middleware tries Bearer first, then Basic.
- **OCI v2**: Has a token exchange endpoint. Needs individual handling but same pattern for the auth extraction.

### 4. Fix API List Endpoints (#333)

`packages.rs` and `artifacts.rs` handlers need to:
- Extract `Extension(auth): Extension<Option<AuthExtension>>`
- Set `public_only = auth.is_none()`
- Pass visibility filter to their SQL queries (join on repositories.is_public)

Same pattern already used by `repositories.rs`.

### 5. Test Strategy

**New unit tests (auth middleware):**
- `test_extract_basic_token` - Basic auth recognized by `extract_token()`
- `test_extract_basic_token_case_insensitive` - "basic " lowercase variant
- `test_extract_basic_token_invalid_base64` - Malformed payload returns None
- `test_extract_basic_token_no_colon` - Missing password separator returns None
- `test_try_resolve_auth_basic_valid` - Valid credentials produce AuthExtension
- `test_try_resolve_auth_basic_invalid` - Bad credentials produce None

**New integration tests (private repo scenarios):**
- Create a private repo, attempt anonymous GET on format handler route, expect 404
- Create a private repo, upload with Basic auth, expect success
- Create a private repo, upload with Bearer token, expect success
- Create a private repo, upload with token restricted to different repo, expect 404
- List `/api/v1/repositories` without auth, verify private repos excluded
- List `/api/v1/packages` without auth, verify private repo packages excluded
- List `/api/v1/artifacts` without auth, verify private repo artifacts excluded

**Regression (existing tests):**
- All 37 existing auth middleware unit tests must pass (Bearer/ApiKey/Cookie paths unchanged)
- All 18 existing integration tests must pass (public repo workflows unchanged)
- All 6 `require_visible()` tests must pass

## Scope

### Files Modified

| File | Change |
|------|--------|
| `backend/src/api/middleware/auth.rs` | Add Basic variant, extend try_resolve_auth, add require_auth_basic helper, add unit tests |
| `backend/src/api/handlers/packages.rs` | Add auth extraction, visibility filtering |
| `backend/src/api/handlers/artifacts.rs` | Add auth extraction, visibility filtering |
| `backend/src/api/handlers/maven.rs` | Use middleware auth, remove local authenticate() |
| `backend/src/api/handlers/pypi.rs` | Same pattern |
| `backend/src/api/handlers/npm.rs` | Same pattern |
| `backend/src/api/handlers/nuget.rs` | Same pattern + X-NuGet-ApiKey handling |
| `backend/src/api/handlers/oci_v2.rs` | Same pattern + token endpoint |
| ... (26 more format handlers) | Same mechanical pattern |
| `backend/tests/integration_tests.rs` | Add private repo test scenarios |
| `backend/src/services/repository_service.rs` | No changes (SQL already supports public_only) |

### Files NOT Modified

- Database migrations (no schema changes)
- Route registration (`routes.rs` - middleware already wired up)
- Download/read handlers (remain anonymous-accessible)
- Frontend code (backend-only fix)

## Risks

- **OCI v2 token endpoint** has its own auth flow (issues Bearer tokens after Basic auth). Needs careful handling to not break Docker push/pull.
- **NuGet X-NuGet-ApiKey** is a non-standard header. Need to verify the middleware extracts it before the handler, or keep it as a handler-level concern.
- **Performance**: Basic auth validation hits the database (password check) on every request. Currently this happens in the handler anyway, so no net change. The middleware just moves it earlier in the pipeline.
