# Data Model: WASM Plugin System

**Date**: 2026-01-17
**Feature**: 002-wasm-plugin-system

## Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          plugins                                 │
│ (modified - add WASM fields)                                    │
├─────────────────────────────────────────────────────────────────┤
│ id: UUID [PK]                                                   │
│ name: VARCHAR(100) [UNIQUE]                                     │
│ version: VARCHAR(50)                                            │
│ display_name: VARCHAR(200)                                      │
│ description: TEXT                                               │
│ author: VARCHAR(200)                                            │
│ homepage: VARCHAR(500)                                          │
│ license: VARCHAR(100)                                           │
│ status: plugin_status [ENUM]                                    │
│ plugin_type: plugin_type [ENUM]                                 │
│ source_type: plugin_source_type [ENUM]  [NEW]                   │
│ source_url: VARCHAR(1000)               [NEW]                   │
│ source_ref: VARCHAR(200)                [NEW]                   │
│ wasm_path: VARCHAR(500)                 [NEW]                   │
│ manifest: JSONB                         [NEW]                   │
│ capabilities: JSONB                     [NEW]                   │
│ resource_limits: JSONB                  [NEW]                   │
│ config: JSONB                                                   │
│ config_schema: JSONB                                            │
│ error_message: TEXT                                             │
│ installed_at: TIMESTAMP                                         │
│ enabled_at: TIMESTAMP                                           │
│ updated_at: TIMESTAMP                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ 1:1 (for format_handler plugins)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      format_handlers                            │
│ (new table)                                                     │
├─────────────────────────────────────────────────────────────────┤
│ id: UUID [PK]                                                   │
│ format_key: VARCHAR(50) [UNIQUE]                                │
│ plugin_id: UUID [FK -> plugins.id, NULLABLE]                    │
│ handler_type: format_handler_type [ENUM]                        │
│ display_name: VARCHAR(200)                                      │
│ description: TEXT                                               │
│ extensions: TEXT[]                                              │
│ is_enabled: BOOLEAN                                             │
│ priority: INTEGER                                               │
│ created_at: TIMESTAMP                                           │
│ updated_at: TIMESTAMP                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ uses format_key
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       repositories                              │
│ (existing - reference only)                                     │
├─────────────────────────────────────────────────────────────────┤
│ format: repository_format [ENUM - may need extension]           │
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

## Enumerations

### plugin_source_type (NEW)

```sql
CREATE TYPE plugin_source_type AS ENUM (
    'core',      -- Compiled-in Rust handler
    'wasm_git',  -- Installed from Git repository
    'wasm_zip',  -- Installed from ZIP file
    'wasm_local' -- Installed from local file path
);
```

### format_handler_type (NEW)

```sql
CREATE TYPE format_handler_type AS ENUM (
    'core',    -- Compiled-in Rust handler
    'wasm'     -- WASM plugin handler
);
```

### plugin_status (EXISTING)

```sql
-- Already exists
CREATE TYPE plugin_status AS ENUM (
    'active',
    'disabled',
    'error'
);
```

### plugin_type (EXISTING - may need extension)

```sql
-- Already exists, FormatHandler already present
CREATE TYPE plugin_type AS ENUM (
    'format_handler',
    'storage_backend',
    'authentication',
    'authorization',
    'webhook',
    'custom'
);
```

## Entity Definitions

### Plugin (Modified)

Extended with WASM-specific fields:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(100) | UNIQUE, NOT NULL | Plugin identifier (lowercase, hyphens) |
| version | VARCHAR(50) | NOT NULL | Semantic version |
| display_name | VARCHAR(200) | NOT NULL | Human-readable name |
| description | TEXT | | Plugin description |
| author | VARCHAR(200) | | Plugin author |
| homepage | VARCHAR(500) | | Homepage URL |
| license | VARCHAR(100) | | License identifier (SPDX) |
| status | plugin_status | NOT NULL, DEFAULT 'disabled' | Current status |
| plugin_type | plugin_type | NOT NULL | Plugin type |
| **source_type** | plugin_source_type | NOT NULL | How plugin was installed |
| **source_url** | VARCHAR(1000) | | Git URL or file path |
| **source_ref** | VARCHAR(200) | | Git tag, branch, or commit |
| **wasm_path** | VARCHAR(500) | | Path to stored .wasm file |
| **manifest** | JSONB | | Full parsed plugin.toml |
| **capabilities** | JSONB | | Parsed capabilities section |
| **resource_limits** | JSONB | | Memory/timeout limits |
| config | JSONB | | Plugin configuration |
| config_schema | JSONB | | JSON Schema for config |
| error_message | TEXT | | Last error message |
| installed_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Installation time |
| enabled_at | TIMESTAMP | | Last enabled time |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last update time |

**New fields marked in bold.**

### FormatHandler (NEW)

Tracks all format handlers (core and WASM):

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| format_key | VARCHAR(50) | UNIQUE, NOT NULL | Format identifier (lowercase, hyphens) |
| plugin_id | UUID | FK -> plugins.id, NULL for core | Associated plugin (NULL = core) |
| handler_type | format_handler_type | NOT NULL | Core or WASM |
| display_name | VARCHAR(200) | NOT NULL | Human-readable name |
| description | TEXT | | Format description |
| extensions | TEXT[] | NOT NULL | File extensions (e.g., ['.jar', '.pom']) |
| is_enabled | BOOLEAN | NOT NULL, DEFAULT true | Whether handler is active |
| priority | INTEGER | NOT NULL, DEFAULT 0 | Resolution priority (higher = preferred) |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation time |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last update time |

### PluginEvent (EXISTING - unchanged)

Already tracks plugin lifecycle events. No changes needed.

### PluginConfig (EXISTING - unchanged)

Already stores plugin configuration. No changes needed.

## JSONB Structures

### manifest

Full parsed `plugin.toml` stored as JSONB for reference:

```json
{
  "plugin": {
    "name": "unity-assetbundle",
    "version": "1.0.0",
    "author": "Unity Technologies",
    "license": "MIT",
    "description": "Unity AssetBundle format handler"
  },
  "format": {
    "key": "unity-assetbundle",
    "display_name": "Unity AssetBundle",
    "extensions": [".assetbundle", ".unity3d"]
  },
  "capabilities": {
    "parse_metadata": true,
    "generate_index": true,
    "validate_artifact": true
  },
  "requirements": {
    "min_wasmtime": "21.0",
    "min_memory_mb": 32,
    "max_memory_mb": 256,
    "timeout_secs": 5
  }
}
```

### capabilities

Extracted from manifest for quick access:

```json
{
  "parse_metadata": true,
  "generate_index": true,
  "validate_artifact": true
}
```

### resource_limits

Merged from manifest requirements and system defaults:

```json
{
  "memory_mb": 64,
  "timeout_secs": 5,
  "fuel": 500000000
}
```

## Database Migration

```sql
-- Migration 014: WASM Plugin System

-- Add new enum type
CREATE TYPE plugin_source_type AS ENUM (
    'core',
    'wasm_git',
    'wasm_zip',
    'wasm_local'
);

CREATE TYPE format_handler_type AS ENUM (
    'core',
    'wasm'
);

-- Extend plugins table
ALTER TABLE plugins
    ADD COLUMN IF NOT EXISTS source_type plugin_source_type NOT NULL DEFAULT 'core',
    ADD COLUMN IF NOT EXISTS source_url VARCHAR(1000),
    ADD COLUMN IF NOT EXISTS source_ref VARCHAR(200),
    ADD COLUMN IF NOT EXISTS wasm_path VARCHAR(500),
    ADD COLUMN IF NOT EXISTS manifest JSONB,
    ADD COLUMN IF NOT EXISTS capabilities JSONB,
    ADD COLUMN IF NOT EXISTS resource_limits JSONB,
    ADD COLUMN IF NOT EXISTS license VARCHAR(100);

-- Create format_handlers table
CREATE TABLE IF NOT EXISTS format_handlers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    format_key VARCHAR(50) UNIQUE NOT NULL,
    plugin_id UUID REFERENCES plugins(id) ON DELETE SET NULL,
    handler_type format_handler_type NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    extensions TEXT[] NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index for format lookups
CREATE INDEX IF NOT EXISTS idx_format_handlers_format_key ON format_handlers(format_key);
CREATE INDEX IF NOT EXISTS idx_format_handlers_plugin_id ON format_handlers(plugin_id);
CREATE INDEX IF NOT EXISTS idx_format_handlers_enabled ON format_handlers(is_enabled) WHERE is_enabled = true;

-- Seed core format handlers
INSERT INTO format_handlers (format_key, handler_type, display_name, description, extensions, is_enabled, priority)
VALUES
    ('maven', 'core', 'Maven', 'Maven repository format', ARRAY['.jar', '.pom', '.war', '.ear'], true, 100),
    ('npm', 'core', 'npm', 'Node.js package manager', ARRAY['.tgz'], true, 100),
    ('pypi', 'core', 'PyPI', 'Python Package Index', ARRAY['.whl', '.tar.gz'], true, 100),
    ('nuget', 'core', 'NuGet', '.NET package manager', ARRAY['.nupkg'], true, 100),
    ('cargo', 'core', 'Cargo', 'Rust package manager', ARRAY['.crate'], true, 100),
    ('go', 'core', 'Go Modules', 'Go module proxy', ARRAY['.zip', '.mod'], true, 100),
    ('oci', 'core', 'OCI/Docker', 'Container images', ARRAY[], true, 100),
    ('helm', 'core', 'Helm', 'Kubernetes package manager', ARRAY['.tgz'], true, 100),
    ('debian', 'core', 'Debian', 'Debian packages', ARRAY['.deb'], true, 100),
    ('rpm', 'core', 'RPM', 'Red Hat packages', ARRAY['.rpm'], true, 100),
    ('rubygems', 'core', 'RubyGems', 'Ruby gems', ARRAY['.gem'], true, 100),
    ('conan', 'core', 'Conan', 'C/C++ package manager', ARRAY['.tgz'], true, 100),
    ('generic', 'core', 'Generic', 'Generic artifact storage', ARRAY[], true, 0)
ON CONFLICT (format_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    extensions = EXCLUDED.extensions;

-- Add trigger for updated_at
CREATE OR REPLACE FUNCTION update_format_handlers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER format_handlers_updated_at
    BEFORE UPDATE ON format_handlers
    FOR EACH ROW
    EXECUTE FUNCTION update_format_handlers_updated_at();
```

## Validation Rules

### Plugin Name
- Lowercase letters, numbers, hyphens only
- 3-100 characters
- Must start with a letter
- Pattern: `^[a-z][a-z0-9-]{2,99}$`

### Format Key
- Same rules as plugin name
- Must be unique across all handlers (core + WASM)
- Pattern: `^[a-z][a-z0-9-]{2,49}$`

### Version
- Semantic versioning (semver)
- Pattern: `^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$`

### Source URL
- Valid URL for git sources
- Valid file path for local sources
- Git URL: `https://` or `git@` prefixed
- Local path: Absolute path starting with `/`

### Resource Limits
- memory_mb: 1-1024 (default 64)
- timeout_secs: 1-300 (default 5)

## State Transitions

### Plugin Status

```
                 ┌─────────┐
     install     │         │     error
    ─────────►   │ disabled│ ◄──────────┐
                 │         │            │
                 └────┬────┘            │
                      │                 │
                      │ enable          │
                      ▼                 │
                 ┌─────────┐            │
                 │         │────────────┘
                 │  active │
                 │         │◄───────────┐
                 └────┬────┘            │
                      │                 │
                      │ disable         │ reload
                      ▼                 │
                 ┌─────────┐            │
                 │         │────────────┘
                 │ disabled│
                 │         │
                 └─────────┘
```

### FormatHandler State

```
enabled: true  ◄─────► enabled: false
     │                       │
     │                       │
     ▼                       ▼
 Handler active         Handler inactive
 (processes requests)   (returns 404)
```
