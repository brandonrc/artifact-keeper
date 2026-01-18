# Data Model: Artifactory Migration

**Date**: 2026-01-17
**Feature**: 004-artifactory-migration

## Entity Diagram

```
┌─────────────────────┐       ┌─────────────────────┐
│   MigrationJob      │       │  SourceConnection   │
├─────────────────────┤       ├─────────────────────┤
│ id (PK)             │──────<│ id (PK)             │
│ source_connection_id│       │ name                │
│ status              │       │ url                 │
│ config              │       │ auth_type           │
│ started_at          │       │ credentials_enc     │
│ finished_at         │       │ created_at          │
│ created_by          │       │ verified_at         │
└────────┬────────────┘       └─────────────────────┘
         │
         │ 1:N
         ▼
┌─────────────────────┐
│   MigrationItem     │
├─────────────────────┤
│ id (PK)             │
│ job_id (FK)         │
│ item_type           │
│ source_path         │
│ target_path         │
│ status              │
│ size_bytes          │
│ checksum_source     │
│ checksum_target     │
│ error_message       │
│ started_at          │
│ completed_at        │
└─────────────────────┘
```

---

## Entities

### SourceConnection

Stores connection details for an Artifactory instance. Credentials are encrypted at rest.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(255) | NOT NULL, UNIQUE | User-friendly name |
| url | VARCHAR(512) | NOT NULL | Artifactory base URL |
| auth_type | ENUM | NOT NULL | `api_token`, `basic_auth` |
| credentials_enc | BYTEA | NOT NULL | Encrypted credentials |
| created_at | TIMESTAMPTZ | NOT NULL | Creation timestamp |
| created_by | UUID | FK → users.id | Creator user |
| verified_at | TIMESTAMPTZ | NULL | Last successful connection test |

**Validation Rules**:
- `url` must be valid HTTPS URL (HTTP allowed only for localhost/dev)
- `name` must be unique per user
- `credentials_enc` encrypted using Artifact Keeper's encryption key

---

### MigrationJob

Represents a single migration session with its configuration and overall status.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| source_connection_id | UUID | FK → source_connections.id | Source Artifactory |
| status | ENUM | NOT NULL | Job status |
| job_type | ENUM | NOT NULL | `full`, `incremental`, `assessment` |
| config | JSONB | NOT NULL | Migration configuration |
| total_items | INTEGER | DEFAULT 0 | Total items to migrate |
| completed_items | INTEGER | DEFAULT 0 | Successfully migrated |
| failed_items | INTEGER | DEFAULT 0 | Failed items |
| skipped_items | INTEGER | DEFAULT 0 | Skipped items |
| total_bytes | BIGINT | DEFAULT 0 | Total bytes to transfer |
| transferred_bytes | BIGINT | DEFAULT 0 | Bytes transferred |
| started_at | TIMESTAMPTZ | NULL | Migration start time |
| finished_at | TIMESTAMPTZ | NULL | Migration end time |
| created_at | TIMESTAMPTZ | NOT NULL | Job creation time |
| created_by | UUID | FK → users.id | Creator user |
| error_summary | TEXT | NULL | High-level error if job failed |

**Status Values**:
| Status | Description |
|--------|-------------|
| `pending` | Job created, not started |
| `assessing` | Running pre-migration assessment |
| `ready` | Assessment complete, ready to start |
| `running` | Migration in progress |
| `paused` | User paused migration |
| `completed` | All items processed |
| `failed` | Job failed with unrecoverable error |
| `cancelled` | User cancelled migration |

**Config Schema** (JSONB):
```json
{
  "include_repos": ["libs-*", "plugins-*"],
  "exclude_repos": ["temp-*"],
  "exclude_paths": ["*-SNAPSHOT/*"],
  "include_users": true,
  "include_groups": true,
  "include_permissions": true,
  "include_cached_remote": false,
  "dry_run": false,
  "conflict_resolution": "skip|overwrite|rename",
  "concurrent_transfers": 4,
  "throttle_delay_ms": 100,
  "date_from": "2024-01-01T00:00:00Z",
  "date_to": null
}
```

---

### MigrationItem

Tracks individual items being migrated (repositories, artifacts, users, groups, permissions).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| job_id | UUID | FK → migration_jobs.id | Parent job |
| item_type | ENUM | NOT NULL | Type of item |
| source_path | TEXT | NOT NULL | Path/identifier in Artifactory |
| target_path | TEXT | NULL | Path/identifier in Artifact Keeper |
| status | ENUM | NOT NULL | Item status |
| size_bytes | BIGINT | DEFAULT 0 | Size in bytes (for artifacts) |
| checksum_source | VARCHAR(64) | NULL | SHA-256 from source |
| checksum_target | VARCHAR(64) | NULL | SHA-256 after transfer |
| metadata | JSONB | NULL | Additional item metadata |
| error_message | TEXT | NULL | Error details if failed |
| retry_count | INTEGER | DEFAULT 0 | Number of retry attempts |
| started_at | TIMESTAMPTZ | NULL | Processing start time |
| completed_at | TIMESTAMPTZ | NULL | Processing end time |

**Item Types**:
| Type | Description |
|------|-------------|
| `repository` | Repository configuration |
| `artifact` | Individual artifact file |
| `user` | User account |
| `group` | Group definition |
| `permission` | Permission rule |
| `property` | Artifact property/metadata |

**Status Values**:
| Status | Description |
|--------|-------------|
| `pending` | Not yet processed |
| `in_progress` | Currently processing |
| `completed` | Successfully migrated |
| `failed` | Failed after all retries |
| `skipped` | Skipped (already exists, excluded, etc.) |

**Indexes**:
- `idx_migration_items_job_status` on (job_id, status)
- `idx_migration_items_job_type` on (job_id, item_type)

---

### MigrationReport

Generated report for a completed migration job.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| job_id | UUID | FK → migration_jobs.id, UNIQUE | Associated job |
| generated_at | TIMESTAMPTZ | NOT NULL | Report generation time |
| summary | JSONB | NOT NULL | Summary statistics |
| warnings | JSONB | NOT NULL | List of warnings |
| errors | JSONB | NOT NULL | List of errors with details |
| recommendations | JSONB | NOT NULL | Post-migration recommendations |

**Summary Schema**:
```json
{
  "duration_seconds": 1847,
  "repositories": { "total": 12, "migrated": 12, "failed": 0 },
  "artifacts": { "total": 8432, "migrated": 8430, "failed": 2, "skipped": 0 },
  "users": { "total": 45, "migrated": 45, "failed": 0, "no_email": 3 },
  "groups": { "total": 8, "migrated": 8, "failed": 0 },
  "permissions": { "total": 24, "migrated": 22, "skipped": 2 },
  "total_bytes_transferred": 48573920481
}
```

---

## State Transitions

### MigrationJob State Machine

```
                    ┌──────────┐
                    │ pending  │
                    └────┬─────┘
                         │ start assessment
                         ▼
                    ┌──────────┐
            ┌───────│assessing │───────┐
            │       └────┬─────┘       │
            │ cancel     │ complete    │ error
            ▼            ▼             ▼
     ┌──────────┐   ┌──────────┐  ┌──────────┐
     │cancelled │   │  ready   │  │  failed  │
     └──────────┘   └────┬─────┘  └──────────┘
                         │ start migration
                         ▼
                    ┌──────────┐
            ┌───────│ running  │◄──────┐
            │       └────┬─────┘       │
            │ pause      │ complete    │ resume
            ▼            ▼             │
     ┌──────────┐   ┌──────────┐       │
     │  paused  │───┤completed │       │
     └────┬─────┘   └──────────┘       │
          │                            │
          └────────────────────────────┘
```

### MigrationItem State Machine

```
     ┌──────────┐
     │ pending  │
     └────┬─────┘
          │ worker picks up
          ▼
     ┌──────────┐
     │in_progress│
     └────┬─────┘
          │
    ┌─────┼─────┬─────────┐
    │     │     │         │
    ▼     ▼     ▼         ▼
┌──────┐┌────┐┌──────┐┌───────┐
│complete││skip││failed││retry  │
└──────┘└────┘└──────┘└───┬───┘
                          │ back to in_progress
                          └─────────────────────►
```

---

## Database Migrations

Migration file: `backend/migrations/020_migration_tables.sql`

```sql
-- Source connections for Artifactory instances
CREATE TABLE IF NOT EXISTS source_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url VARCHAR(512) NOT NULL,
    auth_type VARCHAR(50) NOT NULL CHECK (auth_type IN ('api_token', 'basic_auth')),
    credentials_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    verified_at TIMESTAMPTZ,
    UNIQUE(name, created_by)
);

-- Migration jobs
CREATE TABLE IF NOT EXISTS migration_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_connection_id UUID NOT NULL REFERENCES source_connections(id),
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'assessing', 'ready', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    job_type VARCHAR(50) NOT NULL DEFAULT 'full'
        CHECK (job_type IN ('full', 'incremental', 'assessment')),
    config JSONB NOT NULL DEFAULT '{}',
    total_items INTEGER DEFAULT 0,
    completed_items INTEGER DEFAULT 0,
    failed_items INTEGER DEFAULT 0,
    skipped_items INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    transferred_bytes BIGINT DEFAULT 0,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    error_summary TEXT
);

-- Migration items
CREATE TABLE IF NOT EXISTS migration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES migration_jobs(id) ON DELETE CASCADE,
    item_type VARCHAR(50) NOT NULL
        CHECK (item_type IN ('repository', 'artifact', 'user', 'group', 'permission', 'property')),
    source_path TEXT NOT NULL,
    target_path TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'skipped')),
    size_bytes BIGINT DEFAULT 0,
    checksum_source VARCHAR(64),
    checksum_target VARCHAR(64),
    metadata JSONB,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Migration reports
CREATE TABLE IF NOT EXISTS migration_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE REFERENCES migration_jobs(id) ON DELETE CASCADE,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    summary JSONB NOT NULL DEFAULT '{}',
    warnings JSONB NOT NULL DEFAULT '[]',
    errors JSONB NOT NULL DEFAULT '[]',
    recommendations JSONB NOT NULL DEFAULT '[]'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_migration_jobs_status ON migration_jobs(status);
CREATE INDEX IF NOT EXISTS idx_migration_jobs_created_by ON migration_jobs(created_by);
CREATE INDEX IF NOT EXISTS idx_migration_items_job_status ON migration_items(job_id, status);
CREATE INDEX IF NOT EXISTS idx_migration_items_job_type ON migration_items(job_id, item_type);
CREATE INDEX IF NOT EXISTS idx_source_connections_created_by ON source_connections(created_by);
```
