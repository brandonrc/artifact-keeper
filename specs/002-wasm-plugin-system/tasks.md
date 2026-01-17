# Tasks: WASM Plugin System

**Input**: Design documents from `/specs/002-wasm-plugin-system/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Backend**: `backend/src/`, `backend/migrations/`, `backend/tests/`
- **Plugins**: `plugins/` at repository root
- **WIT**: `backend/src/wit/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, dependencies, and basic WASM infrastructure

- [X] T001 Add wasmtime and git2 dependencies to backend/Cargo.toml
- [X] T002 [P] Create WIT interface definition in backend/src/wit/format-plugin.wit
- [X] T003 [P] Create plugin storage directory structure and .gitignore for plugins/
- [X] T004 Create database migration 014_wasm_plugins.sql in backend/migrations/

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core WASM runtime and registry infrastructure that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 Extend Plugin model with WASM fields (source_type, source_url, source_ref, wasm_path, manifest, capabilities, resource_limits) in backend/src/models/plugin.rs
- [X] T006 [P] Create FormatHandler model in backend/src/models/format_handler.rs
- [X] T007 [P] Create PluginManifest struct for plugin.toml parsing in backend/src/models/plugin_manifest.rs
- [X] T008 Implement ResourceLimiter for WASM memory/fuel limits in backend/src/services/wasm_runtime.rs
- [X] T009 Implement WasmRuntime with Engine, Linker, and Store management in backend/src/services/wasm_runtime.rs
- [X] T010 Implement PluginRegistry for hot-swap storage (Arc<RwLock<HashMap>>) in backend/src/services/plugin_registry.rs
- [X] T011 Create WasmFormatHandler wrapper implementing FormatHandler trait in backend/src/formats/wasm.rs
- [X] T012 Update FormatHandler trait to support dynamic format keys (Custom variant) in backend/src/formats/mod.rs
- [X] T013 Add format_handlers table CRUD operations in backend/src/services/wasm_plugin_service.rs
- [X] T014 Implement manifest validation (required fields, format key pattern) in backend/src/services/wasm_plugin_service.rs
- [X] T015 Add logging for plugin lifecycle events in backend/src/services/wasm_plugin_service.rs

**Checkpoint**: Foundation ready - WASM runtime operational, registry initialized, base handlers available

---

## Phase 3: User Story 1 - Install Plugin from Git Repository (Priority: P1)

**Goal**: Admins can install plugins from Git URLs without server restart

**Independent Test**: Install sample plugin from Git URL, verify format becomes available

### Implementation for User Story 1

- [X] T016 [US1] Implement Git clone with ref checkout using git2 in backend/src/services/wasm_plugin_service.rs
- [X] T017 [US1] Implement plugin.toml discovery and parsing from cloned repo in backend/src/services/wasm_plugin_service.rs
- [X] T018 [US1] Implement WASM binary location and validation from cloned repo in backend/src/services/wasm_plugin_service.rs
- [X] T019 [US1] Implement plugin storage (copy WASM to plugins/ directory) in backend/src/services/wasm_plugin_service.rs
- [X] T020 [US1] Implement plugin activation (load into registry, create format handler) in backend/src/services/wasm_plugin_service.rs
- [X] T021 [US1] Add POST /api/v1/plugins/install/git endpoint in backend/src/api/handlers/plugins.rs
- [X] T022 [US1] Add GET /api/v1/plugins endpoint (list with filters) in backend/src/api/handlers/plugins.rs
- [X] T023 [US1] Add GET /api/v1/plugins/:id endpoint in backend/src/api/handlers/plugins.rs
- [X] T024 [US1] Add POST /api/v1/plugins/:id/enable endpoint in backend/src/api/handlers/plugins.rs
- [X] T025 [US1] Add POST /api/v1/plugins/:id/disable endpoint in backend/src/api/handlers/plugins.rs
- [X] T026 [US1] Add GET /api/v1/plugins/:id/events endpoint in backend/src/api/handlers/plugins.rs
- [X] T027 [US1] Register plugin routes in backend/src/api/routes.rs
- [X] T028 [US1] Handle Git clone errors (invalid URL, timeout, unreachable) with clear messages in backend/src/services/wasm_plugin_service.rs
- [X] T029 [US1] Handle manifest validation errors with descriptive messages in backend/src/services/wasm_plugin_service.rs
- [X] T030 [US1] Handle duplicate plugin name conflicts in backend/src/services/wasm_plugin_service.rs

**Checkpoint**: Git installation fully functional - can install, list, enable, disable plugins

---

## Phase 4: User Story 2 - Install Plugin from ZIP File (Priority: P2)

**Goal**: Admins can install plugins from uploaded ZIP files for offline/proprietary scenarios

**Independent Test**: Upload ZIP file via API, verify plugin activates

### Implementation for User Story 2

- [X] T031 [US2] Implement ZIP extraction to temp directory in backend/src/services/wasm_plugin_service.rs
- [X] T032 [US2] Implement required file validation (plugin.toml, plugin.wasm present) in backend/src/services/wasm_plugin_service.rs
- [X] T033 [US2] Handle corrupted ZIP files gracefully in backend/src/services/wasm_plugin_service.rs
- [X] T034 [US2] Add POST /api/v1/plugins/install/zip multipart endpoint in backend/src/api/handlers/plugins.rs
- [X] T035 [US2] Clean up temp files on success or failure in backend/src/services/wasm_plugin_service.rs (tempfile auto-cleanup)

**Checkpoint**: ZIP installation works - can upload and install plugins offline

---

## Phase 5: User Story 3 - Enable/Disable Core Format Handlers (Priority: P2)

**Goal**: Admins can disable unused core format handlers to reduce attack surface

**Independent Test**: Disable RubyGems, verify it's unavailable for new repos but existing repos remain accessible

### Implementation for User Story 3

- [X] T036 [US3] Seed core format handlers in database on startup in backend/migrations/014_wasm_plugins.sql
- [X] T037 [US3] Implement format handler enable/disable logic in backend/src/services/wasm_plugin_service.rs
- [X] T038 [US3] Add check for "at least one format enabled" constraint in backend/src/services/wasm_plugin_service.rs
- [X] T039 [US3] Add GET /api/v1/formats endpoint (list all handlers) in backend/src/api/handlers/plugins.rs
- [X] T040 [US3] Add GET /api/v1/formats/:format_key endpoint in backend/src/api/handlers/plugins.rs
- [X] T041 [US3] Add POST /api/v1/formats/:format_key/enable endpoint in backend/src/api/handlers/plugins.rs
- [X] T042 [US3] Add POST /api/v1/formats/:format_key/disable endpoint in backend/src/api/handlers/plugins.rs
- [X] T043 [US3] Register format routes in backend/src/api/routes.rs
- [X] T044 [US3] Update repository creation to check format handler enabled status in backend/src/services/repository_service.rs

**Checkpoint**: Core format handlers toggleable via API

---

## Phase 6: User Story 4 - Hot-Reload Plugin (Priority: P3)

**Goal**: Admins can update plugins to new versions without disrupting in-flight requests

**Independent Test**: Install v1.0.0, reload to v2.0.0, verify new version active while old completes

### Implementation for User Story 4

- [X] T045 [US4] Implement version isolation in PluginRegistry (per-version Engine) in backend/src/services/plugin_registry.rs
- [X] T046 [US4] Implement reload logic (fetch new version, validate, swap atomically) in backend/src/services/wasm_plugin_service.rs
- [X] T047 [US4] Handle reload validation failures (keep old version active) in backend/src/services/wasm_plugin_service.rs
- [X] T048 [US4] Add POST /api/v1/plugins/:id/reload endpoint in backend/src/api/handlers/plugins.rs
- [X] T049 [US4] Add event logging for reload operations in backend/src/services/wasm_plugin_service.rs

**Checkpoint**: Hot-reload works with zero downtime

---

## Phase 7: User Story 5 - Uninstall Plugin (Priority: P3)

**Goal**: Admins can remove plugins that are no longer needed

**Independent Test**: Uninstall plugin, verify format no longer available

### Implementation for User Story 5

- [X] T050 [US5] Implement dependency check (repositories using format) in backend/src/services/wasm_plugin_service.rs
- [X] T051 [US5] Implement uninstall with force flag for dependent repos in backend/src/services/wasm_plugin_service.rs
- [X] T052 [US5] Clean up WASM files and database records on uninstall in backend/src/services/wasm_plugin_service.rs
- [X] T053 [US5] Add DELETE /api/v1/plugins/:id endpoint in backend/src/api/handlers/plugins.rs

**Checkpoint**: Uninstall works with dependency warnings

---

## Phase 8: User Story 6 - Plugin Developer Creates New Format Handler (Priority: P4)

**Goal**: Developers can create custom plugins using provided template and documentation

**Independent Test**: Follow quickstart.md to build minimal plugin, install and use it

### Implementation for User Story 6

- [X] T054 [P] [US6] Create plugin template Cargo.toml in plugins/plugin-template/Cargo.toml
- [X] T055 [P] [US6] Create plugin template plugin.toml in plugins/plugin-template/plugin.toml
- [X] T056 [P] [US6] Create plugin template lib.rs with FormatHandler implementation in plugins/plugin-template/src/lib.rs
- [X] T057 [P] [US6] Copy WIT interface to plugin template in plugins/plugin-template/wit/format-plugin.wit
- [X] T058 [P] [US6] Create sample plugin (echo format) Cargo.toml in plugins/sample-plugin/Cargo.toml
- [X] T059 [P] [US6] Create sample plugin plugin.toml in plugins/sample-plugin/plugin.toml
- [X] T060 [P] [US6] Create sample plugin lib.rs with working implementation in plugins/sample-plugin/src/lib.rs
- [X] T061 [P] [US6] Copy WIT interface to sample plugin in plugins/sample-plugin/wit/format-plugin.wit
- [X] T062 [US6] Add POST /api/v1/formats/:format_key/test endpoint for plugin testing in backend/src/api/handlers/plugins.rs
- [X] T063 [US6] Support local file path installation for development in backend/src/services/wasm_plugin_service.rs

**Checkpoint**: Developers can create, build, and test plugins locally

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Final improvements, error handling, and validation

- [X] T064 [P] Add WASM plugin execution metrics (time, memory) in backend/src/services/wasm_runtime.rs
- [X] T065 [P] Add format key conflict detection and clear error messages in backend/src/services/wasm_plugin_service.rs
- [X] T066 [P] Implement plugin crash isolation (sandbox contains crash) in backend/src/services/wasm_runtime.rs
- [X] T067 [P] Implement timeout cleanup (kill WASM execution after limit) in backend/src/services/wasm_runtime.rs
- [X] T068 Add startup initialization (load active plugins from DB) in backend/src/main.rs
- [X] T069 Run cargo clippy and fix warnings
- [X] T070 Run cargo test and fix any failures
- [X] T071 Validate quickstart.md instructions work end-to-end

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Story 1-6 (Phase 3-8)**: All depend on Foundational phase completion
  - US1 can start immediately after Foundational
  - US2 can run in parallel with US1 (different endpoints)
  - US3 can run in parallel with US1/US2 (different files)
  - US4 depends on US1 (needs installed plugin to reload)
  - US5 depends on US1 (needs installed plugin to uninstall)
  - US6 can run in parallel (plugin templates)
- **Polish (Phase 9)**: Depends on all user stories being complete

### User Story Dependencies

| Story | Can Start After | Dependencies |
|-------|-----------------|--------------|
| US1 | Phase 2 | None |
| US2 | Phase 2 | None (parallel with US1) |
| US3 | Phase 2 | None (parallel with US1, US2) |
| US4 | US1 complete | Needs plugin installation working |
| US5 | US1 complete | Needs plugin installation working |
| US6 | Phase 2 | None (parallel with US1-3) |

### Parallel Opportunities

Within Phase 2 (Foundational):
- T005, T006, T007 can run in parallel (different model files)
- T008, T009 must be sequential (wasm_runtime.rs)
- T011, T012 can run in parallel (formats/wasm.rs vs formats/mod.rs)

Within User Stories:
- All [P] marked tasks can run in parallel
- API endpoints within same story can often be parallelized
- Plugin template tasks (T054-T061) can all run in parallel

Across User Stories:
- US1, US2, US3, US6 can run in parallel after Foundational
- US4, US5 must wait for US1

---

## Parallel Example: User Story 6 (Plugin Developer)

```bash
# All plugin template tasks can run in parallel:
Task: "T054 [P] [US6] Create plugin template Cargo.toml"
Task: "T055 [P] [US6] Create plugin template plugin.toml"
Task: "T056 [P] [US6] Create plugin template lib.rs"
Task: "T057 [P] [US6] Copy WIT interface to plugin template"
Task: "T058 [P] [US6] Create sample plugin Cargo.toml"
Task: "T059 [P] [US6] Create sample plugin plugin.toml"
Task: "T060 [P] [US6] Create sample plugin lib.rs"
Task: "T061 [P] [US6] Copy WIT interface to sample plugin"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Foundational (T005-T015)
3. Complete Phase 3: User Story 1 - Git Installation (T016-T030)
4. **STOP and VALIDATE**: Test Git installation end-to-end
5. Deploy/demo if ready

### Incremental Delivery

| Increment | Stories | Value Delivered |
|-----------|---------|-----------------|
| MVP | Setup + Foundational + US1 | Git-based plugin installation |
| +1 | US2 | ZIP file installation (offline support) |
| +2 | US3 | Core handler enable/disable |
| +3 | US4 | Hot-reload (zero-downtime updates) |
| +4 | US5 | Uninstall (cleanup) |
| +5 | US6 | Developer experience (templates) |
| Final | Polish | Metrics, error handling, validation |

### Team Parallel Strategy

With 3 developers after Foundational:
- Developer A: US1 (Git installation) → US4 (Hot-reload) → US5 (Uninstall)
- Developer B: US2 (ZIP installation) → Polish tasks
- Developer C: US3 (Core handlers) → US6 (Plugin templates)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Total tasks: 71
- Task breakdown by phase:
  - Setup: 4 tasks
  - Foundational: 11 tasks
  - US1: 15 tasks
  - US2: 5 tasks
  - US3: 9 tasks
  - US4: 5 tasks
  - US5: 4 tasks
  - US6: 10 tasks
  - Polish: 8 tasks
