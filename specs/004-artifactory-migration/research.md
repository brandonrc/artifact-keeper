# Research: Artifactory to Artifact Keeper Migration

**Date**: 2026-01-17
**Feature**: 004-artifactory-migration

## 1. Migration Approach: Export/Import vs Live API

### Decision: Support BOTH Artifactory Export/Import AND Live API Migration

**Rationale**:
Artifactory has a built-in export system that creates a structured directory/archive containing artifacts and metadata. This is significantly simpler for many use cases. However, live API migration offers more flexibility for incremental migrations.

**Option A: Artifactory Export → Artifact Keeper Import (RECOMMENDED for full migrations)**

Artifactory's [Export System API](https://jfrog.com/help/r/jfrog-rest-apis/export-system) creates a complete export:

```bash
# Export from Artifactory (run on Artifactory server or mount point)
curl -X POST "https://artifactory.example.com/api/export/system" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "exportPath": "/tmp/artifactory-export",
    "includeMetadata": true,
    "createArchive": true,
    "verbose": false,
    "failOnError": true,
    "m2": false,
    "excludeContent": false
  }'
```

Export structure:
```
artifactory-export/
├── repositories/
│   ├── libs-release-local/
│   │   ├── .artifactory-metadata/
│   │   │   └── properties.xml
│   │   └── com/example/mylib/1.0.0/
│   │       └── mylib-1.0.0.jar
│   └── ...
├── etc/
│   ├── security/
│   │   ├── users.xml
│   │   ├── groups.xml
│   │   └── permissions.xml
│   └── ...
└── metadata/
    └── ...
```

**Artifact Keeper Import** would then parse this structure:
1. Read repository configs from export
2. Create matching repositories in Artifact Keeper
3. Walk directory tree and upload artifacts
4. Parse metadata XML and apply properties
5. Import users/groups/permissions from security XMLs

**Advantages of Export/Import approach**:
- ✅ Much simpler implementation (no live API calls during transfer)
- ✅ Complete consistency snapshot
- ✅ Works offline (export once, import anytime)
- ✅ No rate limiting concerns
- ✅ Better for large migrations (can be done over multiple sessions)
- ✅ Artifactory handles the complexity of export structure

**Disadvantages**:
- ❌ Requires filesystem access to export (either on Artifactory server or mounted volume)
- ❌ Export can be large (full artifact storage)
- ❌ Not suitable for incremental/live sync

---

**Option B: Live REST API Migration (for incremental/selective migrations)**

Use REST API when:
- You need incremental migration (only changed artifacts)
- You don't have filesystem access to Artifactory server
- You want real-time progress without creating large export files

---

### Final Decision: Implement BOTH, with Export/Import as the PRIMARY approach

1. **Primary flow**: User exports from Artifactory, then runs `artifact-keeper migrate import /path/to/export`
2. **Secondary flow**: Live API migration for incremental updates or when export isn't available

This reduces complexity significantly for the common case while maintaining flexibility.

---

## 2. Artifactory REST API Integration (for Live Migration Option)

### When to use: Incremental migrations, selective repository migration, no filesystem access

**Rationale**:
- Artifactory REST API v2 is the modern, documented API available in Artifactory 6.x+
- AQL (Artifactory Query Language) enables efficient bulk artifact discovery with filtering
- REST API provides all necessary endpoints for repositories, artifacts, users, groups, and permissions

**Alternatives Considered**:
- **Artifactory CLI (jfrog-cli)**: Viable alternative, but adds external dependency
- **Direct database access**: Rejected as it requires database credentials, bypasses security, and is unsupported

**Key API Endpoints**:
| Purpose | Endpoint | Method |
|---------|----------|--------|
| List repositories | `/api/repositories` | GET |
| Get repository config | `/api/repositories/{repoKey}` | GET |
| List artifacts (AQL) | `/api/search/aql` | POST |
| Download artifact | `/api/storage/{repoKey}/{path}` | GET |
| Get artifact properties | `/api/storage/{repoKey}/{path}?properties` | GET |
| List users | `/api/security/users` | GET |
| List groups | `/api/security/groups` | GET |
| Get permissions | `/api/security/permissions` | GET |

**Rate Limiting Approach**:
- Implement exponential backoff on 429 responses
- Configurable concurrent request limit (default: 4)
- Configurable delay between requests (default: 100ms)

---

## 2. Artifact Transfer Strategy

### Decision: Stream-based transfer with checksum verification

**Rationale**:
- Streaming avoids loading entire artifacts into memory (critical for large files)
- Checksum verification ensures 100% data integrity (spec requirement SC-002)
- Artifactory provides SHA-256 checksums in artifact metadata

**Implementation Pattern**:
```
1. Query artifact metadata from Artifactory (includes checksums)
2. Stream download artifact to temp file
3. Calculate SHA-256 of downloaded file
4. Compare with source checksum
5. If match: move to Artifact Keeper storage
6. If mismatch: log error, mark as failed, continue
```

**Alternatives Considered**:
- **In-memory buffering**: Rejected due to memory exhaustion risk with large files
- **No verification**: Rejected as it violates data integrity requirement

---

## 3. Migration State Management

### Decision: PostgreSQL-backed job state with checkpoint-based resumability

**Rationale**:
- Existing Artifact Keeper uses PostgreSQL; no new infrastructure needed
- Checkpoints enable resuming interrupted migrations (spec requirement SC-003)
- Database state enables both CLI and Web UI to track same jobs

**State Model**:
- `migration_jobs`: Top-level job with status, configuration, timestamps
- `migration_items`: Individual items (repos, artifacts, users) with status and error details
- Status transitions: `pending` → `in_progress` → `completed|failed|skipped`

**Checkpoint Strategy**:
- Update item status after each successful transfer
- On resume: query items with status = `pending` or `in_progress`
- Idempotent operations (skip if destination exists with matching checksum)

---

## 4. Permission Mapping

### Decision: Map Artifactory permissions to Artifact Keeper equivalents

**Rationale**:
- Both systems use similar RBAC concepts (users, groups, repository permissions)
- Exact mapping may not be 1:1; log warnings for unmappable permissions

**Mapping Table**:
| Artifactory Permission | Artifact Keeper Equivalent |
|------------------------|---------------------------|
| read | read |
| annotate | read (metadata read-only in AK) |
| deploy | write |
| delete | delete |
| admin | admin |
| managedXrayMeta | (skipped - Xray not supported) |
| distribute | (skipped - federation not supported) |

**Edge Cases**:
- Permissions on non-migrated repositories: skip with warning
- Permissions for non-migrated users: skip with warning
- Include-pattern permissions: convert to path-based rules where possible

---

## 5. Package Format Compatibility

### Decision: Support all Artifact Keeper formats, warn on unsupported Artifactory formats

**Rationale**:
- Artifact Keeper supports: Maven, npm, Docker, PyPI, Helm, NuGet, Cargo, Go, Generic
- Artifactory has additional formats not yet in AK (Conan, Conda, Chef, Puppet, etc.)

**Compatibility Matrix**:
| Artifactory Format | Artifact Keeper Support | Migration Action |
|-------------------|------------------------|------------------|
| maven | ✅ Supported | Migrate fully |
| npm | ✅ Supported | Migrate fully |
| docker | ✅ Supported | Migrate fully |
| pypi | ✅ Supported | Migrate fully |
| helm | ✅ Supported | Migrate fully |
| nuget | ✅ Supported | Migrate fully |
| cargo | ✅ Supported | Migrate fully |
| go | ✅ Supported | Migrate fully |
| generic | ✅ Supported | Migrate fully |
| conan | ⚠️ Migrate as generic | Warning in assessment |
| conda | ⚠️ Migrate as generic | Warning in assessment |
| debian | ⚠️ Migrate as generic | Warning in assessment |
| rpm | ⚠️ Migrate as generic | Warning in assessment |

---

## 6. Virtual Repository Handling

### Decision: Migrate virtual repositories as references after underlying repos exist

**Rationale**:
- Virtual repositories aggregate other repositories
- Must migrate real (local/remote) repos first
- Virtual repo config references underlying repo keys

**Migration Order**:
1. Local repositories (contain actual artifacts)
2. Remote repositories (proxy configs, cached artifacts optional)
3. Virtual repositories (references to above)

**Remote Repository Handling**:
- Migrate configuration (URL, layout, auth settings)
- Optionally migrate cached artifacts (user-selectable)
- Note: upstream credentials need reconfiguration in Artifact Keeper

---

## 7. CLI Design

### Decision: Subcommand-based CLI with YAML configuration support

**Rationale**:
- Subcommands allow clear separation of operations (assess, migrate, status, resume)
- YAML config enables complex migrations to be version-controlled
- Consistent with modern CLI tools (kubectl, gh, docker)

**Command Structure**:
```
artifact-keeper migrate assess --source <url> --token <token>
artifact-keeper migrate start --config migration.yaml
artifact-keeper migrate status --job-id <uuid>
artifact-keeper migrate resume --job-id <uuid>
artifact-keeper migrate report --job-id <uuid> --format json|html
```

**Configuration File** (migration.yaml):
```yaml
source:
  url: https://artifactory.example.com
  token: ${ARTIFACTORY_TOKEN}
options:
  include_repos: ["libs-*", "plugins-*"]
  exclude_paths: ["*-SNAPSHOT/*"]
  include_users: true
  include_permissions: true
  dry_run: false
  concurrent_transfers: 4
```

---

## 8. Progress Reporting

### Decision: Server-Sent Events (SSE) for real-time web UI updates, polling for CLI

**Rationale**:
- SSE provides efficient server-push for web UI without WebSocket complexity
- CLI can poll job status endpoint at configurable interval
- Both consume same underlying job state from database

**Web UI Updates**:
- Connect to `/api/v1/migrations/{id}/stream` via SSE
- Events: `progress`, `item_complete`, `item_failed`, `job_complete`

**CLI Progress**:
- Poll `/api/v1/migrations/{id}` every 2 seconds
- Display progress bar with ETA
- `--quiet` flag for scripting (exit code only)

---

## Summary of Key Decisions

| Area | Decision |
|------|----------|
| **Primary Approach** | **Artifactory Export → Artifact Keeper Import (SIMPLE)** |
| Secondary Approach | Live REST API for incremental/selective migrations |
| Transfer Method | Filesystem copy for export, streaming for API |
| State Storage | PostgreSQL with checkpoint-based resume |
| Permission Mapping | RBAC mapping with warnings for unsupported |
| Format Handling | Native for supported, generic fallback with warning |
| Virtual Repos | Migrate after underlying repos |
| CLI Design | Subcommand-based with YAML config |
| Progress | SSE for web, polling for CLI |

---

## Simplified MVP Scope

Given the export/import approach, the **MVP can be significantly simpler**:

### Phase 1 MVP: Import from Artifactory Export
1. CLI command: `artifact-keeper migrate import /path/to/artifactory-export`
2. Parse Artifactory export directory structure
3. Create repositories based on export structure
4. Walk and upload all artifacts
5. Parse metadata XML and apply properties
6. Import users/groups (warn about email requirement)
7. Basic progress output to console

**This can be done WITHOUT**:
- Complex Artifactory API client
- Rate limiting logic
- Live connection management
- SSE streaming

### Phase 2: Web UI + Live Migration
- Add web UI for import monitoring
- Add live API migration option for incremental updates
- Add SSE progress streaming
