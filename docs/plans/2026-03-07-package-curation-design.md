# Package Curation

**Date:** 2026-03-07
**Status:** Approved

## Problem

Organizations consuming packages from public registries and mirrors have no way to vet packages before they reach internal systems. JFrog Artifactory does not support curation for RPM or DEB formats, and its curation for other formats operates at download time (causing broken installs when dependencies are blocked mid-transaction). There is a gap in supply chain security across the full stack, from OS packages to application dependencies.

## Overview

Package curation uses the existing staging repo and promotion workflow to intercept packages flowing from upstream registries and mirrors. A remote repo syncs upstream metadata, a staging repo holds packages pending review, and approved packages are promoted to a local repo that generates the client-facing package index. Native clients only see approved packages. Unapproved packages simply don't exist from the client's perspective, producing clean "package not found" behavior instead of broken installs or cryptic 403 errors.

This is a backend-only feature. No new repo types are introduced. The design is format-agnostic: any format with an index endpoint and remote proxy support can be curated.

## Architecture

```
Upstream registry (mirror.centos.org / archive.ubuntu.com / registry.npmjs.org / pypi.org / ...)
    |
    v
Remote Repo (fetches upstream metadata, caches package bytes on demand)
    |
    v
Staging Repo (curation_enabled=true, linked to remote repo)
    |-- Auto-approved (passes all policies) --> promotes immediately
    |-- Flagged (CVE, license, pattern rule) --> queued for manual review
    v
Local Repo (approved packages only, generates native index for the format)
    |
    v
Virtual Repo (what clients point at, can combine multiple curated repos)
```

No new repo types. Reuses remote, staging, local, and virtual repos with a `curation_enabled` flag on the staging repo.

### Why Curated Index, Not Download-Time Blocking

Native package clients (apt, yum, pip, npm, cargo, helm, etc.) resolve dependencies locally based on the package index before downloading. If a package isn't listed in the index, the client doesn't know it exists and won't request it. This means:

- Approved packages: install works exactly like a normal registry/mirror
- Unapproved packages: client reports "package not found," same as a typo
- No partial installs, no broken dependency state, no mid-transaction 403 errors

The index IS the curation surface.

### Supported Formats

Curation works with any format that has an index endpoint and a native client that resolves from it. Two patterns exist:

**Bulk index formats** (client fetches a single index listing all packages):
Curation controls what's included in the generated index.

| Format | Index Endpoint | Native Client |
|--------|---------------|---------------|
| RPM | repodata/repomd.xml + primary.xml.gz | yum, dnf |
| Debian | dists/.../Release + Packages | apt |
| Helm | index.yaml | helm |
| Conda | repodata.json | conda, mamba |
| Cargo | Sparse registry (NDJSON) | cargo |
| Alpine | APKINDEX.tar.gz | apk |
| CRAN | PACKAGES | R install.packages() |
| RubyGems | specs.4.8.gz | gem |
| Composer | packages.json | composer |

**Per-package lookup formats** (client queries metadata per package name):
Curation controls whether the query returns a result or 404.

| Format | Index Endpoint | Native Client |
|--------|---------------|---------------|
| PyPI | /simple/{pkg}/ | pip, poetry |
| NPM | /{pkg} | npm, yarn, pnpm |
| Maven | maven-metadata.xml | mvn, gradle |
| NuGet | /v3/registration/{id}/index.json | dotnet |
| Go | /@v/list | go get |
| Hex | /packages/{name} | mix hex |
| Pub | /api/packages/{name} | dart pub |
| Terraform | /v1/.../versions | terraform |
| Ansible | /api/v3/collections/.../ | ansible-galaxy |

All 18 formats already have remote proxy support in the backend. The curation layer sits between the remote repo and the local repo, using the same `curation_packages` table and rules engine regardless of format.

## Curation Rules Engine

Three layers of rules, evaluated in order. First match wins.

### Layer 1: Explicit Block/Allow Lists (highest priority)

Individual package rules that override everything else.

Examples:
- block `telnet*`, reason: "insecure protocol, use ssh"
- block `openssl` version < 3.0, reason: "EOL branch"
- allow `curl` version = 8.5.0-1, reason: "pinned for compliance"

Fields per rule:
- `package_pattern` (glob: `telnet*`, `lib*-dev`, exact: `nginx`)
- `version_constraint` (e.g., `>= 3.0`, `< 2.17`, `= 1.24.0-1.el9`, or `*` for all versions)
- `action` (allow or block)
- `reason` (required, for audit trail)
- `architecture` (optional filter: `x86_64`, `amd64`, or `*` for all)

### Layer 2: Policy-Based Auto-Evaluation

Uses existing scanning and quality gate infrastructure:

- Security scan passes (no CVEs above threshold): auto-approve
- License check passes: auto-approve
- GPG signature valid: auto-approve (optional, per-repo)
- Any policy violation: hold for manual review

This reuses `scan_policies`, `quality_gates`, and the health scoring system. The only new wiring is triggering evaluation when a package enters staging from the upstream metadata sync.

### Layer 3: Default Stance (lowest priority)

Per-staging-repo setting: `default_action`

- `allow`: everything that isn't explicitly blocked and passes policies flows through automatically. Suitable for repos where you trust the upstream and only want to catch known-bad packages.
- `review`: everything that isn't explicitly allowed requires manual approval. Strict mode for high-security environments.

## Upstream Metadata Sync

When `curation_enabled` is set on a staging repo linked to a remote repo, a background sync job runs periodically.

### Bulk Index Formats

For formats where the upstream provides a complete package listing:

| Format | Sync Source | Parsed Fields |
|--------|------------|---------------|
| RPM | repomd.xml + primary.xml.gz | name, version, release, arch, checksum, deps |
| Debian | Release + Packages.gz | package, version, arch, component, checksum, deps |
| Helm | index.yaml | chart name, version, appVersion, digest |
| Conda | repodata.json | name, version, build, subdir, sha256 |
| Alpine | APKINDEX.tar.gz | package, version, arch, checksum, deps |
| CRAN | PACKAGES | Package, Version, Depends, License |
| RubyGems | specs.4.8.gz | gem name, version, platform |
| Composer | packages.json | vendor/name, version, require |
| Cargo | Sparse registry entries | name, vers, cksum, deps |

The sync job fetches the upstream index, parses it, and inserts each package as a pending record in the `curation_packages` table.

### Per-Package Lookup Formats

For formats without a bulk index (NPM, PyPI, Maven, NuGet, Go, Hex, Pub, Terraform, Ansible), curation operates on-demand:

1. Client requests a package through the remote repo proxy
2. Before caching/serving, the proxy checks the package against curation rules
3. If no rule exists yet, the package is recorded in `curation_packages` with status based on `default_action`
4. If `default_action=allow` and no blocking rule matches, the package flows through immediately
5. If `default_action=review` or a blocking rule matches, the proxy returns 404

This means per-package formats don't need a bulk sync job. Curation is evaluated at proxy fetch time, which is when the package is first requested.

### Sync Behavior (Bulk Index Formats)

- Runs on configurable interval (default: 1 hour, configurable per repo)
- Diff-based: compares upstream checksums against existing records, only processes new/changed packages
- New packages are immediately evaluated against the rules engine (Layer 1, then 2, then 3)
- Auto-approved packages are promoted to the target local repo
- Actual package bytes are fetched lazily (only when a client requests an approved package), or optionally pre-fetched in bulk for approved packages

### Index Generation

The target local repo's native index (primary.xml, Packages, index.yaml, repodata.json, etc.) only includes artifacts that were promoted from staging. This is already how the format handlers work: they generate metadata from the `artifacts` table. If a package isn't promoted, it's not in the table, it's not in the index, the native client can't see it.

## Database Schema

### New table: `curation_packages`

```
id                  UUID PRIMARY KEY
staging_repo_id     UUID FK -> repositories
remote_repo_id      UUID FK -> repositories
format              TEXT (rpm, debian, pypi, npm, helm, etc.)
package_name        TEXT
version             TEXT
release             TEXT (RPM only, nullable)
architecture        TEXT (nullable, not all formats use this)
checksum_sha256     TEXT
upstream_path       TEXT (where to fetch the actual bytes)
status              TEXT (pending | approved | blocked | review)
evaluated_at        TIMESTAMP
evaluated_by        UUID (nullable, null for auto-evaluation)
evaluation_reason   TEXT
rule_id             UUID FK -> curation_rules (nullable, null for policy-based)
metadata            JSONB (raw upstream metadata: dependencies, description, license, etc.)
first_seen_at       TIMESTAMP
upstream_updated_at TIMESTAMP
```

### New table: `curation_rules`

```
id                  UUID PRIMARY KEY
staging_repo_id     UUID FK -> repositories (nullable for global rules)
package_pattern     TEXT (glob pattern)
version_constraint  TEXT (e.g., ">= 3.0", "< 2.17", "*")
architecture        TEXT (default "*")
action              TEXT (allow | block)
priority            INT (lower = higher priority)
reason              TEXT (required)
enabled             BOOLEAN (default true)
created_by          UUID FK -> users
created_at          TIMESTAMP
updated_at          TIMESTAMP
```

### New columns on `repositories` table (staging repos)

```
curation_enabled            BOOLEAN (default false)
curation_source_repo_id     UUID FK -> repositories (the linked remote repo)
curation_target_repo_id     UUID FK -> repositories (the local repo to promote into)
curation_default_action     TEXT (allow | review)
curation_sync_interval_secs INT (default 3600)
curation_auto_fetch         BOOLEAN (default false, pre-fetch approved package bytes)
```

## API Endpoints

All under `/api/v1/curation`.

### Rules Management

```
GET    /curation/rules?repo_id=...              List rules (filterable)
POST   /curation/rules                          Create rule
PUT    /curation/rules/{id}                     Update rule
DELETE /curation/rules/{id}                     Delete rule
```

### Package Catalog

```
GET    /curation/packages?repo_id=...&status=   List packages by status
GET    /curation/packages/{id}                   Package detail with evaluation history
POST   /curation/packages/{id}/approve           Manual approve
POST   /curation/packages/{id}/block             Manual block with reason
POST   /curation/packages/bulk-approve           Bulk approve by IDs or filter
POST   /curation/packages/bulk-block             Bulk block by IDs or filter
```

### Re-Evaluation

```
POST   /curation/packages/re-evaluate?repo_id=  Re-run rules against all pending
POST   /curation/rules/{id}/preview              Dry-run: show what this rule would affect
```

### Sync Control

```
POST   /curation/sync/{staging_repo_id}          Trigger immediate sync
GET    /curation/sync/{staging_repo_id}/status    Last sync time, next scheduled, stats
```

### Dashboard

```
GET    /curation/stats?repo_id=...               Counts by status, recent activity
```

### Audit Trail

All approve/block actions reuse the existing `promotion_approvals` table pattern with `reviewed_by`, `reviewed_at`, `review_notes`.

## Testing Strategy

### E2E Test Environment

Docker Compose setup with mock upstream registries and real native clients.

```
docker-compose.curation-e2e.yml

  mock-rpm-repo     mock-deb-repo     mock-pypi-repo    mock-npm-repo
  (nginx serving    (nginx serving    (nginx serving    (nginx serving
   static RPMs)      static DEBs)      simple index)     registry JSON)
       |                 |                  |                  |
       v                 v                  v                  v
                   artifact-keeper (backend)
            remote repo -> staging repo -> local -> virtual
       |                 |                  |                  |
       v                 v                  v                  v
  rpm-client        deb-client        pip-client        npm-client
  (rocky/alma       (debian/ubuntu    (python           (node
   container)        container)        container)        container)
```

Mock upstream repos: nginx containers serving small sets of static packages with proper indexes. Controlled test data, no dependency on real registries or mirrors.

Test fixture packages: custom packages built with format-specific tools (fpm for RPM/DEB, twine-compatible wheels for PyPI, npm pack for NPM). Names like `e2e-clean-pkg`, `e2e-bad-pkg`, `e2e-dep-parent`, `e2e-dep-child`. Deterministic and fast.

### Test Scenarios

**Happy path:**
1. Sync upstream metadata, verify curation_packages populated
2. Auto-approve clean packages, verify they appear in local repo index
3. `yum install approved-pkg` succeeds
4. `apt-get install approved-pkg` succeeds

**Blocking:**
5. Add block rule for `bad-pkg`, verify it stays in staging
6. `yum install bad-pkg` returns "No package bad-pkg available" (not 403)
7. `apt-get install bad-pkg` returns "Unable to locate package" (not 403)

**Pattern rules:**
8. Block `telnet*`, both telnet and telnet-server blocked
9. Allow `lib*`, libcurl approved while telnet still blocked

**Policy-based:**
10. Package with mock CVE held for review, not in index
11. Admin approves flagged package, it appears in index
12. Admin blocks flagged package, stays out of index

**Dependency handling:**
13. Package A depends on B, both approved: `yum install A` succeeds
14. Package A depends on B, B blocked: yum reports "missing dependency" (clean error, no partial install)

**Bulk operations:**
15. Bulk approve 50 packages, all appear in index
16. Re-evaluate after adding new block rule, affected packages removed from index

**Sync behavior:**
17. Upstream adds new package, next sync picks it up in staging
18. Upstream removes package, no change to already-approved packages
19. Upstream updates package version, new version enters staging separately

**Version constraints:**
20. Block openssl < 3.0: openssl 1.1.1 blocked, openssl 3.2.0 approved

**Default stance:**
21. `default_action=allow`: new packages auto-approved (unless policy blocks)
22. `default_action=review`: new packages held until manual review

**Per-package lookup formats (PyPI, NPM):**
23. `pip install approved-pkg` through curated remote: succeeds
24. `pip install blocked-pkg` through curated remote: "No matching distribution found"
25. `npm install approved-pkg` through curated remote: succeeds
26. `npm install blocked-pkg` through curated remote: "404 Not Found"
27. First request for unknown package with `default_action=allow`: flows through, recorded in curation_packages
28. First request for unknown package with `default_action=review`: returns 404, recorded as pending

### Implementation Priority

Phase 1 (primary targets): RPM, Debian (OS-level supply chain, biggest gap in the market)
Phase 2 (high value): PyPI, NPM, Maven (application dependencies, high attack surface)
Phase 3 (remaining): Helm, Cargo, Conda, NuGet, Go, Composer, Alpine, CRAN, RubyGems, Hex, Pub, Terraform, Ansible

The rules engine, database schema, and API are format-agnostic from day one. Each phase adds format-specific sync adapters and E2E tests.

## Decisions

- **Curated index, not download-time blocking.** apt/yum resolve dependencies from the index. Blocking at download time causes broken partial installs. Controlling the index gives clean "package not found" behavior.
- **Reuse staging repos, not a new repo type.** The existing staging + promotion + approval infrastructure handles the workflow. A `curation_enabled` flag activates the new behavior without adding repo type complexity.
- **Three-layer rules engine.** Explicit rules for precision, policies for automation, default stance for bulk management. OS mirrors have thousands of packages, so pattern matching and auto-approval are essential.
- **Metadata-first sync.** Sync the upstream package index, not the actual bytes. Bytes are fetched lazily on demand or optionally pre-fetched for approved packages. Avoids pulling terabytes of packages that may never be needed.
- **Format-agnostic core.** The rules engine, curation_packages table, and API endpoints work identically for all 18 supported formats. Only the sync adapter (how to parse the upstream index) and the enforcement point (index generation vs proxy-time check) are format-specific.
- **Two enforcement patterns.** Bulk index formats filter at index generation time. Per-package lookup formats filter at proxy fetch time. Both use the same rules evaluation.
- **Mock upstream repos for E2E.** Custom test packages served from nginx containers. No dependency on real registries, fully deterministic.
- **Phased rollout.** RPM and DEB first (biggest market gap), then PyPI/NPM/Maven (highest attack surface), then remaining formats. Core infrastructure built once in phase 1.
