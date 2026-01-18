# Tasks: Artifactory to Artifact Keeper Migration

**Input**: Design documents from `/specs/004-artifactory-migration/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Tests are NOT explicitly requested in the specification. Test tasks omitted.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Backend**: `backend/src/` (Rust)
- **Frontend**: `frontend/src/` (TypeScript/React)
- **Migrations**: `backend/migrations/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and database schema

- [ ] T001 Create database migration file for migration tables in backend/migrations/020_migration_tables.sql
- [ ] T002 [P] Add migration feature dependencies to backend/Cargo.toml (reqwest, tokio-stream for SSE)
- [ ] T003 [P] Create migration module structure in backend/src/api/handlers/migration.rs
- [ ] T004 [P] Create migration models directory structure in backend/src/models/
- [ ] T005 [P] Create migration services directory structure in backend/src/services/
- [ ] T006 [P] Create frontend migration pages directory in frontend/src/pages/admin/Migration/
- [ ] T007 [P] Create frontend migration components directory in frontend/src/components/migration/
- [ ] T008 [P] Create frontend migration API client in frontend/src/api/migration.ts

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T009 Implement SourceConnection model in backend/src/models/source_connection.rs
- [ ] T010 Implement MigrationJob model in backend/src/models/migration_job.rs
- [ ] T011 Implement MigrationItem model in backend/src/models/migration_item.rs
- [ ] T012 Implement MigrationReport model in backend/src/models/migration_report.rs
- [ ] T013 [P] Implement credential encryption utility for storing Artifactory credentials in backend/src/services/encryption.rs
- [ ] T014 Implement Artifactory REST client base with authentication in backend/src/services/artifactory_client.rs
- [ ] T015 [P] Add Artifactory ping and version check to backend/src/services/artifactory_client.rs
- [ ] T016 Register migration API routes in backend/src/api/routes.rs
- [ ] T017 [P] Create shared TypeScript types for migration entities in frontend/src/types/migration.ts

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Repository Migration (Priority: P1) 🎯 MVP

**Goal**: Migrate Artifactory repositories to Artifact Keeper with correct configuration

**Independent Test**: Connect to Artifactory, select repositories, verify they appear in Artifact Keeper with correct type, format, and layout

### Implementation for User Story 1

- [ ] T018 [US1] Implement Artifactory repository listing via AQL in backend/src/services/artifactory_client.rs
- [ ] T019 [US1] Implement source connection CRUD handlers in backend/src/api/handlers/migration.rs
- [ ] T020 [US1] Implement connection test endpoint in backend/src/api/handlers/migration.rs
- [ ] T021 [US1] Implement list source repositories endpoint in backend/src/api/handlers/migration.rs
- [ ] T022 [US1] Implement repository type mapping (local/remote/virtual) in backend/src/services/migration_service.rs
- [ ] T023 [US1] Implement package format compatibility checking in backend/src/services/migration_service.rs
- [ ] T024 [US1] Implement repository creation in Artifact Keeper from Artifactory config in backend/src/services/migration_service.rs
- [ ] T025 [US1] Implement conflict detection for existing repositories in backend/src/services/migration_service.rs
- [ ] T026 [US1] Implement virtual repository reference resolution in backend/src/services/migration_service.rs
- [ ] T027 [P] [US1] Create SourceConnectionForm component in frontend/src/components/migration/SourceConnectionForm.tsx
- [ ] T028 [P] [US1] Create RepositorySelector component with checkboxes in frontend/src/components/migration/RepositorySelector.tsx
- [ ] T029 [US1] Create MigrationWizard step 1 (connection) in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T030 [US1] Create MigrationWizard step 2 (repository selection) in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T031 [US1] Wire up API calls for connection and repository listing in frontend/src/api/migration.ts

**Checkpoint**: Repository migration fully functional - can migrate repo configs from Artifactory to Artifact Keeper

---

## Phase 4: User Story 2 - Artifact and Metadata Migration (Priority: P1)

**Goal**: Transfer all artifacts with metadata, checksums verified, resumable on interruption

**Independent Test**: Migrate repository with known artifacts, verify each exists with correct checksums, sizes, and metadata properties

### Implementation for User Story 2

- [ ] T032 [US2] Implement artifact listing via AQL with pagination in backend/src/services/artifactory_client.rs
- [ ] T033 [US2] Implement streaming artifact download from Artifactory in backend/src/services/artifactory_client.rs
- [ ] T034 [US2] Implement artifact property/metadata fetch in backend/src/services/artifactory_client.rs
- [ ] T035 [US2] Implement checksum verification (SHA-256) after download in backend/src/services/migration_worker.rs
- [ ] T036 [US2] Implement artifact upload to Artifact Keeper storage in backend/src/services/migration_worker.rs
- [ ] T037 [US2] Implement metadata property mapping and storage in backend/src/services/migration_worker.rs
- [ ] T038 [US2] Implement duplicate detection (skip if same checksum exists) in backend/src/services/migration_worker.rs
- [ ] T039 [US2] Implement conflict resolution (skip/overwrite/rename) in backend/src/services/migration_worker.rs
- [ ] T040 [US2] Implement checkpoint saving after each successful transfer in backend/src/services/migration_worker.rs
- [ ] T041 [US2] Implement migration resume from last checkpoint in backend/src/services/migration_service.rs
- [ ] T042 [US2] Implement background worker for async migration processing in backend/src/services/migration_worker.rs
- [ ] T043 [US2] Implement migration job start/pause/resume/cancel handlers in backend/src/api/handlers/migration.rs
- [ ] T044 [P] [US2] Create conflict resolution dialog component in frontend/src/components/migration/ConflictResolutionDialog.tsx
- [ ] T045 [US2] Add artifact migration configuration to MigrationWizard step 3 in frontend/src/components/migration/MigrationWizard.tsx

**Checkpoint**: Complete artifact migration with integrity verification and resume capability

---

## Phase 5: User Story 3 - Migration Progress and Reporting (Priority: P2)

**Goal**: Real-time progress monitoring and detailed migration reports

**Independent Test**: Start migration, observe real-time progress updates, review final report for completeness

### Implementation for User Story 3

- [ ] T046 [US3] Implement progress tracking updates in migration worker in backend/src/services/migration_worker.rs
- [ ] T047 [US3] Implement Server-Sent Events (SSE) endpoint for live progress in backend/src/api/handlers/migration.rs
- [ ] T048 [US3] Implement migration items listing endpoint with filtering in backend/src/api/handlers/migration.rs
- [ ] T049 [US3] Implement migration report generation on completion in backend/src/services/migration_service.rs
- [ ] T050 [US3] Implement HTML report template rendering in backend/src/services/migration_service.rs
- [ ] T051 [US3] Implement migration report endpoint (JSON and HTML) in backend/src/api/handlers/migration.rs
- [ ] T052 [US3] Implement validation check comparing source/destination counts in backend/src/services/migration_service.rs
- [ ] T053 [P] [US3] Create MigrationProgress component with real-time SSE updates in frontend/src/components/migration/MigrationProgress.tsx
- [ ] T054 [P] [US3] Create MigrationReport component for viewing results in frontend/src/components/migration/MigrationReport.tsx
- [ ] T055 [US3] Create MigrationItemsList component with status filtering in frontend/src/components/migration/MigrationItemsList.tsx
- [ ] T056 [US3] Add progress display to MigrationWizard step 4 in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T057 [US3] Implement SSE connection handling in frontend/src/api/migration.ts

**Checkpoint**: Full visibility into migration progress and comprehensive reporting

---

## Phase 6: User Story 4 - User and Permission Migration (Priority: P2)

**Goal**: Migrate users, groups, and repository permissions preserving access controls

**Independent Test**: Migrate users/groups, verify users can log in and access same repositories as in Artifactory

### Implementation for User Story 4

- [ ] T058 [US4] Implement user listing from Artifactory API in backend/src/services/artifactory_client.rs
- [ ] T059 [US4] Implement group listing from Artifactory API in backend/src/services/artifactory_client.rs
- [ ] T060 [US4] Implement permission targets listing from Artifactory API in backend/src/services/artifactory_client.rs
- [ ] T061 [US4] Implement user creation in Artifact Keeper (email-based, no password) in backend/src/services/migration_worker.rs
- [ ] T062 [US4] Implement group creation with member associations in backend/src/services/migration_worker.rs
- [ ] T063 [US4] Implement permission mapping (Artifactory → Artifact Keeper) in backend/src/services/migration_service.rs
- [ ] T064 [US4] Implement permission rule creation in Artifact Keeper in backend/src/services/migration_worker.rs
- [ ] T065 [US4] Add user/group/permission migration items to job processing in backend/src/services/migration_worker.rs
- [ ] T066 [US4] Handle users without email (flag in report) in backend/src/services/migration_worker.rs
- [ ] T067 [P] [US4] Add user/group/permission toggles to MigrationWizard config step in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T068 [US4] Display user migration warnings in MigrationReport component in frontend/src/components/migration/MigrationReport.tsx

**Checkpoint**: Access control migration complete - users can authenticate and access migrated repos

---

## Phase 7: User Story 5 - Selective and Incremental Migration (Priority: P3)

**Goal**: Enable partial migrations and incremental syncs for complex migration scenarios

**Independent Test**: Select specific repositories/paths, verify only selected items transfer; run incremental and verify only new items migrate

### Implementation for User Story 5

- [ ] T069 [US5] Implement repository include/exclude pattern matching in backend/src/services/migration_service.rs
- [ ] T070 [US5] Implement path exclusion pattern matching in backend/src/services/migration_service.rs
- [ ] T071 [US5] Implement date range filtering for artifacts in backend/src/services/artifactory_client.rs
- [ ] T072 [US5] Implement incremental migration (track last sync time) in backend/src/services/migration_service.rs
- [ ] T073 [US5] Add incremental job type support to migration handlers in backend/src/api/handlers/migration.rs
- [ ] T074 [P] [US5] Add include/exclude repo patterns to MigrationWizard config in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T075 [P] [US5] Add path exclusion patterns input to MigrationWizard config in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T076 [US5] Add date range picker to MigrationWizard config in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T077 [US5] Add incremental migration option to MigrationWizard in frontend/src/components/migration/MigrationWizard.tsx

**Checkpoint**: Flexible migration options for complex enterprise scenarios

---

## Phase 8: User Story 6 - Pre-Migration Assessment (Priority: P3)

**Goal**: Analyze Artifactory before migration to plan storage, estimate time, identify issues

**Independent Test**: Run assessment against Artifactory instance, review generated report

### Implementation for User Story 6

- [ ] T078 [US6] Implement repository analysis with artifact counts in backend/src/services/artifactory_client.rs
- [ ] T079 [US6] Implement storage size calculation per repository in backend/src/services/migration_service.rs
- [ ] T080 [US6] Implement compatibility checking for package types in backend/src/services/migration_service.rs
- [ ] T081 [US6] Implement migration duration estimation algorithm in backend/src/services/migration_service.rs
- [ ] T082 [US6] Implement assessment run endpoint in backend/src/api/handlers/migration.rs
- [ ] T083 [US6] Implement assessment results endpoint in backend/src/api/handlers/migration.rs
- [ ] T084 [US6] Generate warnings for potential issues (large files, special chars, etc.) in backend/src/services/migration_service.rs
- [ ] T085 [P] [US6] Create AssessmentResults component with storage breakdown in frontend/src/components/migration/AssessmentResults.tsx
- [ ] T086 [US6] Add assessment step to MigrationWizard before config in frontend/src/components/migration/MigrationWizard.tsx
- [ ] T087 [US6] Display compatibility warnings in assessment results in frontend/src/components/migration/AssessmentResults.tsx

**Checkpoint**: Full pre-migration planning capability

---

## Phase 9: CLI Tool (Cross-cutting)

**Goal**: Provide CLI interface for scripted/automated migrations

### Implementation for CLI

- [ ] T088 Implement CLI argument parsing with clap in backend/src/cli/migrate.rs
- [ ] T089 Implement YAML config file parsing in backend/src/cli/migrate.rs
- [ ] T090 Implement CLI assess command in backend/src/cli/migrate.rs
- [ ] T091 Implement CLI start command with progress output in backend/src/cli/migrate.rs
- [ ] T092 Implement CLI status command in backend/src/cli/migrate.rs
- [ ] T093 Implement CLI pause/resume/cancel commands in backend/src/cli/migrate.rs
- [ ] T094 Implement CLI report command (JSON/HTML output) in backend/src/cli/migrate.rs
- [ ] T095 Add CLI binary target to backend/Cargo.toml
- [ ] T096 Implement environment variable substitution for credentials in backend/src/cli/migrate.rs

---

## Phase 10: Artifactory Export Import (Primary Flow)

**Goal**: Support importing from Artifactory export archives (simplest migration path)

### Implementation for Export Import

- [ ] T097 Implement Artifactory export directory parser in backend/src/services/artifactory_import.rs
- [ ] T098 Implement repository config parsing from export metadata in backend/src/services/artifactory_import.rs
- [ ] T099 Implement artifact file walking and upload from export in backend/src/services/artifactory_import.rs
- [ ] T100 Implement properties.xml parsing for artifact metadata in backend/src/services/artifactory_import.rs
- [ ] T101 Implement users.xml parsing for user migration in backend/src/services/artifactory_import.rs
- [ ] T102 Implement groups.xml and permissions.xml parsing in backend/src/services/artifactory_import.rs
- [ ] T103 Implement ZIP archive extraction support in backend/src/services/artifactory_import.rs
- [ ] T104 Implement CLI import command for export directories in backend/src/cli/migrate.rs
- [ ] T105 [P] Create ImportFromExport component for web UI in frontend/src/components/migration/ImportFromExport.tsx
- [ ] T106 Add import from export tab to Migration admin page in frontend/src/pages/admin/Migration/index.tsx

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T107 [P] Implement rate limiting and exponential backoff in backend/src/services/artifactory_client.rs
- [ ] T108 [P] Implement throttling (configurable delay between requests) in backend/src/services/migration_worker.rs
- [ ] T109 Implement network interruption retry logic in backend/src/services/migration_worker.rs
- [ ] T110 [P] Add structured logging with correlation IDs in backend/src/services/migration_service.rs
- [ ] T111 [P] Implement dry-run mode for preview without changes in backend/src/services/migration_worker.rs
- [ ] T112 Add large file handling (>5GB streaming) in backend/src/services/migration_worker.rs
- [ ] T113 [P] Add special character path sanitization in backend/src/services/migration_service.rs
- [ ] T114 Create Migration admin page layout in frontend/src/pages/admin/Migration/index.tsx
- [ ] T115 Add migration routes to React Router in frontend/src/routes.tsx
- [ ] T116 Run quickstart.md validation against implementation

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-8)**: All depend on Foundational phase completion
- **CLI (Phase 9)**: Depends on Foundational, can parallel with user stories
- **Export Import (Phase 10)**: Can start after Foundational, independent of live API stories
- **Polish (Phase 11)**: Can interleave with user stories, some tasks are parallel

### User Story Dependencies

| Story | Dependencies | Notes |
|-------|--------------|-------|
| US1 (Repos) | Foundational only | MVP - do first |
| US2 (Artifacts) | US1 (needs repos to exist) | Co-priority with US1 |
| US3 (Progress) | US2 (needs migration running) | Can start backend early |
| US4 (Users/Perms) | Foundational only | Independent of US1-3 |
| US5 (Selective) | US1, US2 | Extends existing migration |
| US6 (Assessment) | Foundational only | Independent, can parallel |

### Within Each User Story

- Models before services
- Services before handlers
- Backend before frontend
- Core implementation before integration

### Parallel Opportunities

**Phase 1 (Setup)**: T002-T008 can all run in parallel

**Phase 2 (Foundational)**: T013, T015, T017 can run in parallel after T009-T012

**User Stories**:
- US1: T027, T028 can parallel (different components)
- US2: T044 can parallel with backend tasks
- US3: T053, T054 can parallel
- US4: T067 can parallel with backend
- US5: T074, T075 can parallel
- US6: T085 can parallel with backend

**Different stories can run in parallel if team capacity allows**

---

## Parallel Example: User Story 1

```bash
# Launch frontend components in parallel:
Task: "Create SourceConnectionForm component in frontend/src/components/migration/SourceConnectionForm.tsx"
Task: "Create RepositorySelector component in frontend/src/components/migration/RepositorySelector.tsx"

# Launch after form components ready:
Task: "Create MigrationWizard step 1 (connection) in frontend/src/components/migration/MigrationWizard.tsx"
```

---

## Implementation Strategy

### MVP First (User Stories 1 + 2)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Repository Migration)
4. Complete Phase 4: User Story 2 (Artifact Migration)
5. **STOP and VALIDATE**: Test repository + artifact migration independently
6. Optionally complete Phase 10 (Export Import) for simpler path
7. Deploy/demo if ready

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. US1 + US2 → Test → Deploy (Core Migration MVP!)
3. US3 → Test → Deploy (Visibility into migrations)
4. US4 → Test → Deploy (Access control migration)
5. US5 + US6 → Test → Deploy (Advanced features)
6. CLI + Polish → Complete feature

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 (Repository Migration) backend
   - Developer B: US1 frontend + US3 frontend components
   - Developer C: Export Import (Phase 10) - independent path
3. After US1:
   - Developer A: US2 backend
   - Developer B: US2 frontend + US4 frontend
   - Developer C: CLI (Phase 9)

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Export Import (Phase 10) is the RECOMMENDED primary path - simpler than live API
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
