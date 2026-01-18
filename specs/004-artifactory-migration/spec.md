# Feature Specification: Artifactory to Artifact Keeper Migration

**Feature Branch**: `004-artifactory-migration`
**Created**: 2026-01-17
**Status**: Draft
**Input**: User description: "Artifactory to Artifact Keeper migration tool - help users migrate from JFrog Artifactory (expensive proprietary solution) to Artifact Keeper (open-source alternative). Should support migrating repositories, artifacts, metadata, permissions, and configurations from existing Artifactory infrastructure."

## Clarifications

### Session 2026-01-17

- Q: Should migration include auth provider configuration (OAuth, LDAP, SSO) or just user records? → A: Migrate user records only; auth provider configuration handled separately in Artifact Keeper admin panel
- Q: How should migrated users be matched to auth provider identities? → A: Match by email address (migrated user email must match auth provider email)
- Q: How should administrators initiate and monitor migrations? → A: Both CLI and web UI (CLI for automation/scripting, web UI integrated into admin panel for interactive use)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Repository Migration (Priority: P1)

As a DevOps engineer, I want to migrate my Artifactory repositories to Artifact Keeper so that I can preserve my existing artifact structure without manually recreating everything.

**Why this priority**: Repositories are the foundational structure. Without migrating repositories first, artifacts have nowhere to go. This is the minimum viable migration capability.

**Independent Test**: Can be fully tested by connecting to an Artifactory instance, selecting repositories, and verifying they appear in Artifact Keeper with correct configuration (type, format, layout).

**Acceptance Scenarios**:

1. **Given** I have valid Artifactory credentials, **When** I connect to my Artifactory instance, **Then** I see a list of all repositories I have access to with their types (local, remote, virtual) and package formats (Maven, npm, Docker, etc.)
2. **Given** I have selected repositories to migrate, **When** I initiate migration, **Then** corresponding repositories are created in Artifact Keeper with matching configurations
3. **Given** a repository already exists in Artifact Keeper with the same key, **When** I attempt to migrate, **Then** I am prompted to skip, rename, or merge with the existing repository
4. **Given** I am migrating a virtual repository, **When** migration completes, **Then** the virtual repository references the correct underlying repositories in Artifact Keeper

---

### User Story 2 - Artifact and Metadata Migration (Priority: P1)

As a DevOps engineer, I want to migrate all artifacts along with their metadata from Artifactory so that I maintain full artifact history and properties in Artifact Keeper.

**Why this priority**: Artifacts are the core data - without them, the migration has no value. This must be co-prioritized with repository migration.

**Independent Test**: Can be fully tested by migrating a repository with known artifacts, then verifying each artifact exists in Artifact Keeper with correct checksums, sizes, and metadata properties.

**Acceptance Scenarios**:

1. **Given** I have selected repositories for migration, **When** artifact migration runs, **Then** all artifacts are transferred with their original paths preserved
2. **Given** artifacts have custom properties in Artifactory, **When** migration completes, **Then** those properties appear as metadata in Artifact Keeper
3. **Given** an artifact already exists in Artifact Keeper, **When** I attempt to migrate the same artifact, **Then** the system compares checksums and skips if identical or prompts for conflict resolution if different
4. **Given** migration is interrupted mid-transfer, **When** I resume migration, **Then** it continues from where it left off without re-transferring completed artifacts

---

### User Story 3 - Migration Progress and Reporting (Priority: P2)

As a system administrator, I want to monitor migration progress in real-time and receive detailed reports so that I can ensure the migration completed successfully and troubleshoot any issues.

**Why this priority**: Essential for production migrations where visibility into progress and errors is critical, but the core migration functionality must work first.

**Independent Test**: Can be fully tested by starting a migration and observing real-time progress updates, then reviewing the final migration report for completeness.

**Acceptance Scenarios**:

1. **Given** a migration is in progress, **When** I view the migration status, **Then** I see real-time progress including items migrated, items remaining, current transfer rate, and estimated time remaining
2. **Given** migration encounters errors, **When** I view the migration log, **Then** I see detailed error information including which items failed and why
3. **Given** migration completes, **When** I request a migration report, **Then** I receive a summary showing total items migrated, failed items, warnings, and any items requiring attention
4. **Given** I want to verify migration integrity, **When** I run a validation check, **Then** the system compares source and destination counts and checksums

---

### User Story 4 - User and Permission Migration (Priority: P2)

As an IT administrator, I want to migrate users, groups, and permissions from Artifactory so that access controls are preserved in Artifact Keeper.

**Why this priority**: Important for enterprise migrations but can be done manually for small teams. Not blocking for initial artifact availability.

**Independent Test**: Can be fully tested by migrating users and groups, then verifying those users can log in and access the same repositories they could in Artifactory.

**Acceptance Scenarios**:

1. **Given** I choose to migrate users, **When** migration runs, **Then** user accounts are created in Artifact Keeper (passwords require reset or SSO reconfiguration)
2. **Given** I choose to migrate groups, **When** migration completes, **Then** groups exist in Artifact Keeper with correct member associations
3. **Given** repositories have permission rules in Artifactory, **When** I migrate permissions, **Then** equivalent permission rules are applied in Artifact Keeper
4. **Given** Artifactory uses external authentication (LDAP/SSO/OAuth), **When** migration completes, **Then** migrated users can authenticate via whatever auth provider is configured in Artifact Keeper's admin panel (auth provider setup is separate from migration)

---

### User Story 5 - Selective and Incremental Migration (Priority: P3)

As a DevOps engineer, I want to migrate specific repositories or artifacts selectively and run incremental migrations so that I can migrate gradually or exclude unwanted content.

**Why this priority**: Advanced capability for complex migrations. Basic full migration should work before optimizing for partial migrations.

**Independent Test**: Can be fully tested by selecting specific repositories/paths for migration and verifying only selected items are transferred.

**Acceptance Scenarios**:

1. **Given** I want to migrate specific repositories only, **When** I configure migration, **Then** I can select/deselect individual repositories
2. **Given** I want to exclude certain paths, **When** I configure migration, **Then** I can specify path patterns to exclude (e.g., `*-SNAPSHOT/*`)
3. **Given** I have run a migration before, **When** I run incremental migration, **Then** only new or changed artifacts since last migration are transferred
4. **Given** I want to migrate a date range, **When** I specify start/end dates, **Then** only artifacts modified within that range are migrated

---

### User Story 6 - Pre-Migration Assessment (Priority: P3)

As a system administrator, I want to analyze my Artifactory instance before migration so that I can plan for storage requirements, estimate migration time, and identify potential issues.

**Why this priority**: Helpful for planning but not blocking for the migration itself.

**Independent Test**: Can be fully tested by running assessment against an Artifactory instance and reviewing the generated report.

**Acceptance Scenarios**:

1. **Given** I connect to Artifactory, **When** I run a pre-migration assessment, **Then** I receive a report showing total repositories, artifacts, storage size, and estimated migration duration
2. **Given** assessment runs, **When** I review results, **Then** I see warnings about potential compatibility issues (unsupported package types, very large files, etc.)
3. **Given** I need to plan storage, **When** I view assessment, **Then** I see storage requirements broken down by repository

---

### Edge Cases

- What happens when Artifactory rate-limits API requests during migration?
- How does system handle artifacts larger than 5GB?
- What happens when artifact paths contain special characters not supported by Artifact Keeper?
- How does system handle corrupted artifacts in Artifactory (checksum mismatch)?
- What happens when Artifactory connection drops mid-migration?
- How does system handle migrating from Artifactory Cloud vs self-hosted?
- What happens when repository package type isn't supported in Artifact Keeper?
- What happens when an Artifactory user has no email address? (Migration report should flag these users as requiring manual email assignment before they can authenticate)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST connect to Artifactory instances using API token or username/password authentication
- **FR-002**: System MUST discover and list all repositories the authenticated user has access to
- **FR-003**: System MUST support migrating local, remote, and virtual repository types
- **FR-004**: System MUST support migrating common package formats: Maven, npm, Docker, PyPI, Helm, NuGet, Cargo, Go, and generic
- **FR-005**: System MUST transfer artifacts with their original paths preserved
- **FR-006**: System MUST verify artifact integrity using checksum comparison after transfer
- **FR-007**: System MUST migrate artifact properties/metadata as Artifact Keeper metadata
- **FR-008**: System MUST provide real-time progress updates during migration
- **FR-009**: System MUST log all migration activities with timestamps and outcomes
- **FR-010**: System MUST support resuming interrupted migrations from the last successful point
- **FR-011**: System MUST detect and handle duplicate artifacts (same checksum) efficiently
- **FR-012**: System MUST provide conflict resolution options when target items already exist
- **FR-013**: System MUST generate migration reports summarizing success/failure counts and details
- **FR-014**: System MUST support dry-run mode to preview migration without making changes
- **FR-015**: System MUST migrate user accounts with email (required for identity matching), username, and group memberships (passwords and auth provider configs excluded; users authenticate via Artifact Keeper's configured auth providers using email-based identity matching)
- **FR-016**: System MUST migrate groups and their member associations
- **FR-017**: System MUST migrate repository permission rules to equivalent Artifact Keeper permissions
- **FR-018**: System MUST support selective migration by repository, path pattern, or date range
- **FR-019**: System MUST support incremental migration (only new/changed items since last run)
- **FR-020**: System MUST provide pre-migration assessment with storage and time estimates
- **FR-021**: System MUST handle network interruptions gracefully with automatic retry
- **FR-022**: System MUST respect Artifactory rate limits and implement appropriate throttling
- **FR-023**: System MUST provide a web UI integrated into Artifact Keeper's admin panel for interactive migration management
- **FR-024**: System MUST provide a CLI tool for scripted/automated migrations with equivalent functionality to the web UI

### Key Entities

- **Migration Job**: Represents a migration session with configuration, status, progress, and results. Tracks source/destination, selected items, start/end times, and outcome.
- **Migration Item**: Individual artifact, repository, or permission being migrated. Tracks source path, destination path, status, and any errors.
- **Migration Report**: Summary of a completed migration including statistics, errors, warnings, and verification results.
- **Source Connection**: Configuration for connecting to Artifactory including URL, credentials, and connection parameters.
- **Conflict Resolution Rule**: User-defined rules for handling items that already exist in destination (skip, overwrite, rename, merge).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Administrators can migrate 1000 artifacts within 30 minutes on standard network connection
- **SC-002**: Migration achieves 100% data integrity (all migrated artifacts pass checksum verification)
- **SC-003**: Users can resume interrupted migrations and complete successfully without data loss
- **SC-004**: 95% of migration issues are resolvable through provided error messages and guidance
- **SC-005**: Pre-migration assessment accurately estimates storage requirements within 10% margin
- **SC-006**: Migrated users can access the same repositories they had access to in Artifactory
- **SC-007**: System handles migrations of 100,000+ artifacts without memory exhaustion or crashes
- **SC-008**: Migration can run during business hours with throttling that doesn't impact Artifactory performance by more than 10%

## Assumptions

- Artifactory REST API (v2) is accessible from the environment running Artifact Keeper
- Users have sufficient permissions in Artifactory to read the content they want to migrate
- Artifact Keeper has sufficient storage capacity to accommodate migrated artifacts
- Network bandwidth is adequate for transferring artifact data
- Artifactory version is 6.x or higher (modern REST API support)
- User passwords are not migrated for security reasons; users will need to reset passwords or use SSO
- Remote repository configurations are migrated as references but actual upstream connections need reconfiguration in Artifact Keeper

## Out of Scope

- Migrating Artifactory-specific features not supported in Artifact Keeper (e.g., Xray security data, proprietary build integrations)
- Real-time bidirectional sync between Artifactory and Artifact Keeper
- Migrating Artifactory plugins or custom user plugins
- Migrating Access Federation or multi-site replication configurations
- Automatic DNS/routing cutover from Artifactory to Artifact Keeper
- Migrating authentication provider configurations (LDAP, SAML, OAuth clients/secrets) — auth providers are configured separately in Artifact Keeper's admin panel
