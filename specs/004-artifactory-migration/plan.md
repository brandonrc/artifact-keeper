# Implementation Plan: Artifactory to Artifact Keeper Migration

**Branch**: `004-artifactory-migration` | **Date**: 2026-01-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/004-artifactory-migration/spec.md`

## Summary

Implement a migration tool that enables organizations to migrate from JFrog Artifactory to Artifact Keeper. The tool will support migrating repositories (local, remote, virtual), artifacts with metadata, users, groups, and permissions. It provides both a CLI interface for scripted/automated migrations and a web UI integrated into Artifact Keeper's admin panel for interactive use. Authentication configuration is handled separately in Artifact Keeper's admin panel; migration focuses on user records matched by email address.

## Technical Context

**Language/Version**: Rust 1.75+ (backend), TypeScript 5.x (frontend)
**Primary Dependencies**: axum, sqlx, tokio, reqwest (backend); React 19, Ant Design 6, TanStack Query 5 (frontend)
**Storage**: PostgreSQL (migration job state), existing Artifact Keeper storage (migrated artifacts)
**Testing**: cargo test (Rust), vitest + Playwright (frontend)
**Target Platform**: Linux server (backend), modern browsers (frontend)
**Project Type**: Web application (backend + frontend)
**Performance Goals**: 1000 artifacts migrated in 30 minutes, handle 100k+ artifacts without memory exhaustion
**Constraints**: Must not impact Artifactory source performance by >10%, resumable migrations, checksum verification for 100% data integrity
**Scale/Scope**: Single Artifactory instance to single Artifact Keeper instance, supports all major package formats

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. API-First Design | ✅ PASS | API contracts defined before implementation (see contracts/) |
| II. Security by Default | ✅ PASS | Credentials encrypted, no secrets in logs, auth required for all migration endpoints |
| III. Simplicity & YAGNI | ✅ PASS | Single migration flow, no bidirectional sync, no complex federation |
| IV. Documentation Standards | ✅ PASS | CLI help, web UI guidance, quickstart guide, API docs |
| V. Accessibility Standards | ✅ PASS | Web UI follows WCAG 2.1 AA (Ant Design components), keyboard navigation |
| VI. Test Coverage | ✅ PASS | Contract tests for API, unit tests for migration logic, integration tests for E2E flows |
| VII. Observability | ✅ PASS | Structured logging, progress tracking, correlation IDs, migration reports |

## Project Structure

### Documentation (this feature)

```text
specs/004-artifactory-migration/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (OpenAPI specs)
│   ├── migration-api.yaml
│   └── artifactory-client.md
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
backend/
├── src/
│   ├── api/
│   │   └── handlers/
│   │       └── migration.rs      # NEW: Migration API endpoints
│   ├── models/
│   │   ├── migration_job.rs      # NEW: Migration job entity
│   │   └── migration_item.rs     # NEW: Individual migration item
│   ├── services/
│   │   ├── migration_service.rs  # NEW: Core migration orchestration
│   │   ├── artifactory_client.rs # NEW: Artifactory REST API client
│   │   └── migration_worker.rs   # NEW: Background migration worker
│   └── cli/
│       └── migrate.rs            # NEW: CLI entrypoint for migrations
└── tests/
    ├── integration/
    │   └── migration_tests.rs    # NEW: E2E migration tests
    └── unit/
        └── artifactory_client_tests.rs # NEW

frontend/
├── src/
│   ├── pages/
│   │   └── admin/
│   │       └── Migration.tsx     # NEW: Migration management page
│   ├── components/
│   │   └── migration/
│   │       ├── MigrationWizard.tsx      # NEW: Step-by-step wizard
│   │       ├── SourceConnectionForm.tsx  # NEW: Artifactory connection
│   │       ├── RepositorySelector.tsx    # NEW: Repo selection
│   │       ├── MigrationProgress.tsx     # NEW: Real-time progress
│   │       └── MigrationReport.tsx       # NEW: Final report
│   └── api/
│       └── migration.ts          # NEW: Migration API client
└── tests/
    └── e2e/
        └── migration.spec.ts     # NEW: E2E tests
```

**Structure Decision**: Extends existing web application structure. Migration functionality added as new modules within existing backend/frontend layout. CLI added as additional binary target in backend.

## Complexity Tracking

> No constitution violations requiring justification.

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| Dual Interface (CLI + Web) | Accepted | Clarified requirement; CLI enables automation, web enables interactive use |
| Background Worker | Accepted | Large migrations can take hours; async processing with progress updates required |
| Artifactory Client | New module | Encapsulates Artifactory REST API complexity; single responsibility |
