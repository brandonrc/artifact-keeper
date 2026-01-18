# Artifactory Client Reference

**Date**: 2026-01-17
**Feature**: 004-artifactory-migration

This document describes the JFrog Artifactory REST API endpoints used by the migration tool.

## Authentication

All requests require authentication via one of:
- **API Token**: `Authorization: Bearer <token>` or `X-JFrog-Art-Api: <token>`
- **Basic Auth**: `Authorization: Basic <base64(username:password)>`

## Endpoints Used

### System Information

```http
GET /api/system/ping
```
Returns `OK` if Artifactory is running.

```http
GET /api/system/version
```
Returns Artifactory version information.

**Response**:
```json
{
  "version": "7.55.10",
  "revision": "75510900",
  "addons": ["docker", "maven", "npm", ...],
  "license": "Enterprise Plus"
}
```

---

### Repositories

```http
GET /api/repositories
```
List all repositories.

**Response**:
```json
[
  {
    "key": "libs-release-local",
    "type": "LOCAL",
    "packageType": "maven",
    "url": "https://artifactory.example.com/artifactory/libs-release-local",
    "description": "Release repository"
  },
  ...
]
```

```http
GET /api/repositories/{repoKey}
```
Get detailed repository configuration.

**Response (LOCAL)**:
```json
{
  "key": "libs-release-local",
  "rclass": "local",
  "packageType": "maven",
  "description": "Release repository",
  "notes": "",
  "includesPattern": "**/*",
  "excludesPattern": "",
  "repoLayoutRef": "maven-2-default",
  "handleReleases": true,
  "handleSnapshots": false,
  ...
}
```

---

### Artifacts (AQL)

```http
POST /api/search/aql
Content-Type: text/plain
```

**Request Body (AQL Query)**:
```
items.find({
  "repo": "libs-release-local"
}).include("repo", "path", "name", "size", "created", "modified", "sha256", "actual_sha1")
.sort({"$asc": ["path", "name"]})
.offset(0)
.limit(1000)
```

**Response**:
```json
{
  "results": [
    {
      "repo": "libs-release-local",
      "path": "com/example/mylib/1.0.0",
      "name": "mylib-1.0.0.jar",
      "size": 1234567,
      "created": "2024-01-15T10:30:00.000Z",
      "modified": "2024-01-15T10:30:00.000Z",
      "sha256": "abc123...",
      "actual_sha1": "def456..."
    },
    ...
  ],
  "range": {
    "start_pos": 0,
    "end_pos": 1000,
    "total": 5432
  }
}
```

---

### Artifact Download

```http
GET /api/storage/{repoKey}/{itemPath}
```
Get artifact metadata (not the file itself).

**Response**:
```json
{
  "repo": "libs-release-local",
  "path": "/com/example/mylib/1.0.0/mylib-1.0.0.jar",
  "created": "2024-01-15T10:30:00.000Z",
  "createdBy": "admin",
  "lastModified": "2024-01-15T10:30:00.000Z",
  "modifiedBy": "admin",
  "lastUpdated": "2024-01-15T10:30:00.000Z",
  "downloadUri": "https://artifactory.example.com/artifactory/libs-release-local/com/example/mylib/1.0.0/mylib-1.0.0.jar",
  "mimeType": "application/java-archive",
  "size": "1234567",
  "checksums": {
    "sha1": "def456...",
    "md5": "789abc...",
    "sha256": "abc123..."
  },
  "originalChecksums": {
    "sha256": "abc123..."
  },
  "uri": "https://artifactory.example.com/artifactory/api/storage/libs-release-local/com/example/mylib/1.0.0/mylib-1.0.0.jar"
}
```

```http
GET /{repoKey}/{itemPath}
```
Download artifact binary (direct URL, not via /api/).

---

### Artifact Properties

```http
GET /api/storage/{repoKey}/{itemPath}?properties
```
Get artifact properties/metadata.

**Response**:
```json
{
  "properties": {
    "build.name": ["my-build"],
    "build.number": ["123"],
    "custom.property": ["value1", "value2"]
  },
  "uri": "..."
}
```

---

### Users

```http
GET /api/security/users
```
List all users.

**Response**:
```json
[
  {
    "name": "admin",
    "email": "admin@example.com",
    "admin": true,
    "profileUpdatable": true,
    "realm": "internal"
  },
  ...
]
```

```http
GET /api/security/users/{username}
```
Get user details.

**Response**:
```json
{
  "name": "jsmith",
  "email": "jsmith@example.com",
  "admin": false,
  "profileUpdatable": true,
  "internalPasswordDisabled": false,
  "groups": ["developers", "readers"],
  "realm": "ldap"
}
```

---

### Groups

```http
GET /api/security/groups
```
List all groups.

**Response**:
```json
[
  {
    "name": "developers",
    "description": "Development team",
    "autoJoin": false,
    "realm": "internal",
    "realmAttributes": ""
  },
  ...
]
```

```http
GET /api/security/groups/{groupName}
```
Get group details with members (if `includeUsers=true`).

---

### Permissions

```http
GET /api/v2/security/permissions
```
List permission targets (v2 API for newer Artifactory).

**Response**:
```json
{
  "permissions": [
    {
      "name": "release-deployers",
      "repo": {
        "repositories": ["libs-release-local"],
        "actions": {
          "users": {
            "jsmith": ["read", "deploy"]
          },
          "groups": {
            "developers": ["read", "deploy", "delete"]
          }
        },
        "includePatterns": ["**"],
        "excludePatterns": []
      }
    },
    ...
  ]
}
```

---

## Error Handling

### Common Error Responses

| Status | Meaning | Action |
|--------|---------|--------|
| 401 | Unauthorized | Check credentials |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 429 | Too Many Requests | Back off and retry |
| 500 | Server Error | Retry with backoff |
| 503 | Service Unavailable | Retry with backoff |

### Rate Limiting

Artifactory may return 429 when rate-limited. Headers to check:
- `X-RateLimit-Limit`: Max requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `Retry-After`: Seconds to wait before retry

**Strategy**:
1. If 429 received, wait `Retry-After` seconds (or 60s if not present)
2. Use exponential backoff: 1s, 2s, 4s, 8s, max 60s
3. Log warning after 3 retries, fail after 5 retries

---

## Pagination

AQL queries support pagination via `.offset()` and `.limit()`:
```
items.find({...}).offset(1000).limit(1000)
```

User/group/permission APIs do not support pagination; expect full list in response.

---

## Notes for Implementation

1. **Large Files**: Use streaming download, don't buffer entire file in memory
2. **Concurrent Requests**: Limit to 4-8 concurrent downloads to avoid overwhelming source
3. **Checksums**: Always verify SHA-256 after download
4. **Virtual Repos**: Cannot download from virtual repos directly; resolve to underlying local/remote
5. **Remote Repo Cache**: Cached artifacts in remote repos have different storage path
