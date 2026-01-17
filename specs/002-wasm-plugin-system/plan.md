# Implementation Plan: WASM Plugin System

**Branch**: `002-wasm-plugin-system` | **Date**: 2026-01-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/002-wasm-plugin-system/spec.md`

## Summary

A hot-loadable plugin architecture using WebAssembly (WASM) that allows extending Artifact Keeper with custom format handlers. Plugins are distributed via Git URLs or ZIP files, loaded at runtime without server restart, and execute in a sandboxed environment with configurable resource limits. Core format handlers remain compiled-in Rust but follow the same trait interface and can be enabled/disabled via API.

## Technical Context

**Language/Version**: Rust 1.75+ (backend), TypeScript 5.x (frontend)
**Primary Dependencies**: wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum
**Storage**: PostgreSQL (existing), filesystem for WASM binaries
**Testing**: cargo test, tokio-test, integration tests with sample plugins
**Target Platform**: Linux server (primary), macOS (development)
**Project Type**: Web application (existing Rust backend + React frontend)
**Performance Goals**: Plugin load <60s, handler execution <5s per artifact, hot-reload with zero downtime
**Constraints**: Memory limit 64MB default per plugin, sandbox isolation, no network access from plugins
**Scale/Scope**: Support 10+ concurrent plugins, 100+ requests/second through plugin handlers

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. API-First Design | PASS | API contracts defined in contracts/ before implementation |
| II. Security by Default | PASS | WASM sandbox, resource limits, admin-only endpoints |
| III. Simplicity & YAGNI | PASS | Per-plugin Engine isolation is simplest hot-reload pattern |
| IV. Documentation Standards | PASS | WIT interfaces are self-documenting, quickstart.md for developers |
| V. Accessibility Standards | N/A | Backend feature, no UI changes |
| VI. Test Coverage | PASS | Contract tests, integration tests, plugin unit tests |
| VII. Observability | PASS | Plugin events logged, metrics for execution time/memory |

**Pre-Design Check**: PASS - All applicable principles satisfied.

## Project Structure

### Documentation (this feature)

```text
specs/002-wasm-plugin-system/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0 research findings
├── data-model.md        # Entity definitions
├── quickstart.md        # Plugin development guide
├── contracts/           # API contracts (OpenAPI)
│   ├── plugins-api.yaml # Plugin lifecycle endpoints
│   └── formats-api.yaml # Format handler endpoints
├── checklists/          # Quality checklists
│   └── requirements.md  # Spec validation checklist
└── tasks.md             # Implementation tasks (Phase 2)
```

### Source Code (repository root)

```text
backend/
├── src/
│   ├── api/
│   │   └── handlers/
│   │       └── plugins.rs       # Plugin API handlers (modify)
│   ├── formats/
│   │   ├── mod.rs               # FormatHandler trait (modify)
│   │   └── wasm.rs              # WASM format handler wrapper (new)
│   ├── models/
│   │   ├── plugin.rs            # Plugin entity (modify)
│   │   └── format_handler.rs    # FormatHandler entity (new)
│   ├── services/
│   │   ├── plugin_service.rs    # Plugin service (modify heavily)
│   │   ├── wasm_runtime.rs      # Wasmtime integration (new)
│   │   └── plugin_registry.rs   # Hot-reload registry (new)
│   └── wit/
│       └── format-plugin.wit    # WIT interface definition (new)
├── migrations/
│   └── 014_wasm_plugins.sql     # Schema changes (new)
└── tests/
    └── wasm_plugin_test.rs      # Integration tests (new)

plugins/                         # Plugin development directory (new)
├── plugin-template/             # Template for new plugins
│   ├── Cargo.toml
│   ├── plugin.toml
│   ├── src/
│   │   └── lib.rs
│   └── wit/
│       └── format-plugin.wit
└── sample-plugin/               # Sample implementation for testing
    ├── Cargo.toml
    ├── plugin.toml
    ├── src/
    │   └── lib.rs
    └── wit/
        └── format-plugin.wit
```

**Structure Decision**: Web application structure. All changes are in the existing `backend/` directory with new files for WASM runtime integration. New `plugins/` directory at repo root for plugin development templates and samples.

## Complexity Tracking

> No constitution violations requiring justification.

| Component | Justification |
|-----------|---------------|
| wasmtime dependency | Required for WASM execution - industry standard runtime |
| wit-bindgen | Required for type-safe WASM interfaces - official tooling |
| git2 | Required for Git clone installation - mature library |

## Key Technical Decisions

### 1. Hot-Reload Architecture

**Pattern**: Per-plugin Engine isolation with Arc-wrapped registry.

Each plugin version gets its own wasmtime Engine and Component. When a plugin is reloaded:
1. New Engine/Component created for new version
2. Registry updated atomically (RwLock write)
3. Old version continues serving in-flight requests
4. Old Engine deallocated when last reference dropped

This avoids complex request draining logic and ensures zero-downtime updates.

### 2. Format Handler Unification

**Pattern**: WasmFormatHandler wrapper implementing existing FormatHandler trait.

```rust
pub struct WasmFormatHandler {
    plugin_id: String,
    format_key: String,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl FormatHandler for WasmFormatHandler {
    // Delegates to registry.execute_*() methods
}
```

Services don't need to know if a handler is core (Rust) or plugin (WASM).

### 3. Resource Limits

**Default limits**:
- Memory: 64MB per plugin instance
- Execution timeout: 5 seconds
- Fuel: 500M units (calibrated for ~5 seconds of computation)

Plugins can request different limits in manifest; system admin can override.

### 4. WIT Interface

```wit
package artifact-keeper:format@1.0.0

interface handler {
    type metadata = record {
        path: string,
        version: option<string>,
        content-type: string,
        size-bytes: u64,
        checksum-sha256: option<string>,
    }

    format-key: func() -> string
    parse-metadata: func(path: string, data: list<u8>) -> result<metadata, string>
    validate: func(path: string, data: list<u8>) -> result<unit, string>
    generate-index: func(artifacts: list<metadata>) -> result<option<list<tuple<string, list<u8>>>>, string>
}

world format-plugin {
    export handler
    import wasi:io/streams@0.2.1
}
```

## Dependencies to Add

**Cargo.toml**:
```toml
# WASM runtime
wasmtime = { version = "21", features = ["component-model", "async"] }
wasmtime-wasi = "21"

# Git operations
git2 = "0.19"

# Already present: zip, toml, async-trait
```

## Migration Plan

1. **Phase 1**: Add WASM infrastructure without breaking existing handlers
2. **Phase 2**: Implement plugin lifecycle API
3. **Phase 3**: Create sample plugin and documentation
4. **Phase 4**: Integration testing and optimization

No breaking changes to existing API endpoints. New endpoints are additive.
