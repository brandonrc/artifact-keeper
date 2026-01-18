# Quickstart: Migrating from Artifactory to Artifact Keeper

This guide walks you through migrating your JFrog Artifactory instance to Artifact Keeper.

## Prerequisites

- Artifact Keeper instance running and accessible
- Sufficient storage space for migrated artifacts
- For export/import: Access to Artifactory server filesystem or export archive
- For live API migration: Artifactory API token or admin credentials

---

## Option 1: Import from Artifactory Export (Recommended)

The simplest migration path uses Artifactory's built-in export system. This approach is recommended for full migrations.

### Step 1: Export from Artifactory

On your Artifactory server, run the system export:

```bash
# Via REST API
curl -X POST "https://artifactory.example.com/api/export/system" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "exportPath": "/tmp/artifactory-export",
    "includeMetadata": true,
    "createArchive": true,
    "verbose": false,
    "failOnError": true,
    "excludeContent": false
  }'
```

Or use the Artifactory Admin UI: **Admin** → **Import & Export** → **System** → **Export**

This creates a structured export containing:
```
artifactory-export/
├── repositories/
│   ├── libs-release-local/
│   │   ├── .artifactory-metadata/
│   │   └── com/example/mylib/1.0.0/
│   │       └── mylib-1.0.0.jar
│   └── ...
├── etc/
│   └── security/
│       ├── users.xml
│       ├── groups.xml
│       └── permissions.xml
└── metadata/
```

### Step 2: Import into Artifact Keeper

```bash
# Import the export directory
artifact-keeper migrate import /path/to/artifactory-export

# Or import a compressed archive
artifact-keeper migrate import /path/to/artifactory-export.zip
```

Progress output:
```
Importing from Artifactory export...

Scanning export structure...
  Found 12 repositories
  Found 8,432 artifacts (48.5 GB)
  Found 45 users, 8 groups, 24 permission rules

[=========>          ] 45% | 3,794/8,432 artifacts | 21.8 GB

Imported: libs-release-local (1,234 artifacts)
Imported: libs-snapshot-local (892 artifacts)
Currently: plugins-release-local (1,668 artifacts)
```

### Step 3: Configure Options (Optional)

```bash
# Selective import with options
artifact-keeper migrate import /path/to/artifactory-export \
  --include-repos "libs-*" \
  --exclude-repos "temp-*" \
  --include-users \
  --include-permissions \
  --dry-run  # Preview without changes
```

### Step 4: Review Results

```bash
# View import report
artifact-keeper migrate report --format html > report.html
```

**Advantages of Export/Import**:
- ✅ Simplest approach - no live API calls during transfer
- ✅ Complete consistency snapshot
- ✅ Works offline (export once, import anytime)
- ✅ No rate limiting concerns
- ✅ Can be done over multiple sessions

---

## Option 2: Web UI Migration (Live API)

Use this approach when you don't have filesystem access to Artifactory or need incremental migrations.

### Step 1: Add Source Connection

1. Log in to Artifact Keeper as an administrator
2. Navigate to **Admin** → **Migration** → **Source Connections**
3. Click **Add Connection**
4. Fill in:
   - **Name**: A friendly name (e.g., "Production Artifactory")
   - **URL**: Your Artifactory URL (e.g., `https://artifactory.example.com`)
   - **Authentication**: Choose API Token or Basic Auth
   - **Credentials**: Enter your token or username/password
5. Click **Test Connection** to verify
6. Click **Save**

### Step 2: Run Assessment

1. Go to **Admin** → **Migration** → **Jobs**
2. Click **New Migration**
3. Select your source connection
4. Click **Run Assessment**
5. Wait for assessment to complete
6. Review:
   - Total repositories, artifacts, users
   - Storage requirements
   - Compatibility warnings (unsupported package types)

### Step 3: Configure Migration

1. From the assessment results, click **Configure Migration**
2. Select repositories to migrate:
   - Use checkboxes to include/exclude specific repositories
   - Or use patterns: `libs-*` includes all repos starting with "libs-"
3. Configure options:
   - **Include Users**: Migrate user accounts (email-matched to your auth provider)
   - **Include Groups**: Migrate group definitions and memberships
   - **Include Permissions**: Migrate repository permission rules
   - **Exclude Paths**: Skip specific paths (e.g., `*-SNAPSHOT/*`)
   - **Conflict Resolution**: Skip, Overwrite, or Rename existing items
4. Optionally enable **Dry Run** to preview without making changes

### Step 4: Start Migration

1. Review your configuration summary
2. Click **Start Migration**
3. Monitor progress in real-time:
   - Items migrated / remaining
   - Current transfer speed
   - Estimated time remaining
4. If needed, click **Pause** to temporarily halt

### Step 5: Review Results

1. When complete, review the migration report:
   - Summary statistics
   - Failed items with error details
   - Warnings and recommendations
2. For failed items, you can:
   - Fix issues and retry individual items
   - Run an incremental migration to catch remaining items

---

## Option 3: CLI Migration (Live API)

Use the CLI for scripted migrations when you need live API access without the Web UI.

### Installation

The migration CLI is included with Artifact Keeper:

```bash
# If running from source
cargo build --release --bin artifact-keeper

# The binary is at target/release/artifact-keeper
```

### Step 1: Create Configuration File

Create `migration.yaml`:

```yaml
# Artifactory source configuration
source:
  url: https://artifactory.example.com
  auth_type: api_token
  # Token from environment variable (recommended)
  token: ${ARTIFACTORY_TOKEN}
  # Or use basic auth:
  # auth_type: basic_auth
  # username: admin
  # password: ${ARTIFACTORY_PASSWORD}

# Migration options
options:
  # Repository selection (glob patterns supported)
  include_repos:
    - "libs-release-*"
    - "plugins-*"
  exclude_repos:
    - "temp-*"
    - "*-old"

  # Path exclusions
  exclude_paths:
    - "*-SNAPSHOT/*"
    - "*/internal/*"

  # What to migrate
  include_users: true
  include_groups: true
  include_permissions: true
  include_cached_remote: false

  # Behavior
  dry_run: false
  conflict_resolution: skip  # skip, overwrite, rename

  # Performance tuning
  concurrent_transfers: 4
  throttle_delay_ms: 100

  # Optional date range filter
  # date_from: "2024-01-01T00:00:00Z"
  # date_to: null
```

### Step 2: Run Assessment

```bash
export ARTIFACTORY_TOKEN="your-api-token"

artifact-keeper migrate assess --config migration.yaml
```

Output:
```
Assessment Results
==================
Repositories: 12 (10 local, 2 remote, 0 virtual)
Artifacts:    8,432
Total Size:   48.5 GB
Users:        45
Groups:       8
Permissions:  24

Compatibility:
  ✓ 10 repositories fully compatible
  ⚠ 2 repositories will migrate as generic (conan format)

Estimated Duration: ~45 minutes

Warnings:
  - 3 users have no email address (manual assignment required)
  - 2 repositories use unsupported package type 'conan'

Run 'artifact-keeper migrate start --config migration.yaml' to begin.
```

### Step 3: Start Migration

```bash
artifact-keeper migrate start --config migration.yaml
```

Progress output:
```
Starting migration...
Job ID: 550e8400-e29b-41d4-a716-446655440000

[=========>          ] 45% | 3,794/8,432 artifacts | 21.8 GB | ETA: 25m

Migrated: libs-release-local (1,234 artifacts)
Migrated: libs-snapshot-local (892 artifacts)
Currently: plugins-release-local (1,668 artifacts)
```

### Step 4: Monitor and Manage

Check status:
```bash
artifact-keeper migrate status --job-id 550e8400-e29b-41d4-a716-446655440000
```

Pause if needed:
```bash
artifact-keeper migrate pause --job-id 550e8400-e29b-41d4-a716-446655440000
```

Resume:
```bash
artifact-keeper migrate resume --job-id 550e8400-e29b-41d4-a716-446655440000
```

### Step 5: Get Report

```bash
# JSON report
artifact-keeper migrate report --job-id 550e8400-... --format json > report.json

# HTML report
artifact-keeper migrate report --job-id 550e8400-... --format html > report.html
```

---

## Incremental Migration

After your initial migration, run incremental migrations to sync new artifacts:

```bash
artifact-keeper migrate start --config migration.yaml --incremental
```

This only migrates artifacts modified since the last successful migration.

---

## Troubleshooting

### Connection Issues

```
Error: Failed to connect to Artifactory
```

- Verify URL is correct and accessible from Artifact Keeper server
- Check firewall rules allow outbound HTTPS
- Verify API token has read permissions

### Authentication Errors

```
Error: 401 Unauthorized
```

- Regenerate API token in Artifactory
- Ensure token has not expired
- For basic auth, verify username/password

### Rate Limiting

```
Warning: Rate limited, backing off...
```

- Normal behavior; migration will continue automatically
- Increase `throttle_delay_ms` if frequent
- Reduce `concurrent_transfers` to lower load

### Checksum Mismatch

```
Error: Checksum mismatch for artifact X
```

- Source artifact may be corrupted
- Retry the specific artifact
- If persists, download manually from Artifactory and verify

### Users Without Email

```
Warning: 3 users have no email address
```

- These users are migrated but cannot authenticate until email is set
- Manually assign emails in Artifact Keeper admin panel
- Users will match to OAuth/SSO providers by email

---

## Post-Migration Steps

1. **Configure Authentication**: Set up OAuth (Google, GitHub) or LDAP in Admin → Settings → Authentication
2. **Notify Users**: Migrated users need to log in via the new auth provider
3. **Update CI/CD**: Point build systems to Artifact Keeper URLs
4. **Verify Artifacts**: Spot-check critical artifacts are accessible
5. **Run Builds**: Test that builds can download dependencies
6. **Decommission Artifactory**: After validation period, retire old instance
