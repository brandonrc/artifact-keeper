# Research: WASM Plugin System

**Date**: 2026-01-17
**Feature**: 002-wasm-plugin-system
**Status**: Complete

## 1. Wasmtime Integration with Tokio

### Decision
Use wasmtime with `async_support(true)` and ambient Tokio runtime integration via `wasmtime_wasi::with_ambient_tokio_runtime()`.

### Rationale
- WASI host functions are modeled as Rust Futures, enabling suspension during blocking operations
- When WASM blocks, the Future is suspended and control yields back to Tokio's event loop
- Existing Axum-based backend already runs on Tokio, so seamless integration

### Alternatives Considered
- **Synchronous execution**: Would block Tokio worker threads, degrading concurrency
- **Separate thread pool**: Adds complexity and context switching overhead

### Implementation Pattern
```rust
let mut config = wasmtime::Config::new();
config.async_support(true);

let engine = wasmtime::Engine::new(&config)?;
let mut store = wasmtime::Store::new(&engine, plugin_context);

// Execute with timeout
tokio::time::timeout(
    std::time::Duration::from_secs(5),
    instance.parse_metadata(&mut store, &data),
).await
```

---

## 2. Component Model and WIT Interfaces

### Decision
Use WebAssembly Component Model with WIT (Wasm Interface Types) for defining the FormatHandler interface between host and guest.

### Rationale
- **Type safety**: Automatic marshaling eliminates manual memory layout management
- **Language neutrality**: Plugins can be written in Rust, C, AssemblyScript, Go, etc.
- **Versioned interfaces**: Component model supports interface evolution
- **Resource tracking**: Automatic cleanup of cross-boundary resources

### Alternatives Considered
- **Raw WASM exports**: Requires manual memory management, error-prone
- **msgpack/JSON serialization**: Higher overhead, no compile-time type checking
- **Custom ABI**: More work, less portable

### Interface Design
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

    type validation-error = record {
        message: string,
        field: option<string>,
    }

    // Core operations
    format-key: func() -> string
    parse-metadata: func(path: string, data: list<u8>) -> result<metadata, validation-error>
    validate: func(path: string, data: list<u8>) -> result<unit, validation-error>
    generate-index: func(artifacts: list<metadata>) -> result<option<list<tuple<string, list<u8>>>>, string>
}

world format-plugin {
    export handler
    import wasi:io/streams@0.2.1
}
```

---

## 3. Memory Limits and Resource Control

### Decision
Implement ResourceLimiter trait with configurable per-plugin memory limits (default 64MB) and table element limits.

### Rationale
- Prevents runaway plugins from exhausting system memory
- Per-plugin configuration allows different limits based on format complexity
- ResourceLimiter integrates naturally with wasmtime Store

### Implementation Pattern
```rust
pub struct PluginResourceLimiter {
    max_memory: u64,
    memory_used: u64,
}

impl ResourceLimiter for PluginResourceLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, _max: Option<usize>) -> Result<bool> {
        if desired as u64 > self.max_memory {
            return Ok(false); // Deny growth
        }
        self.memory_used = desired as u64;
        Ok(true)
    }
}
```

### Configuration
```toml
[plugin.requirements]
min_memory_mb = 32
max_memory_mb = 256  # Plugin-declared maximum
timeout_secs = 5
```

---

## 4. Execution Timeouts

### Decision
Use dual-layer timeout strategy: fuel metering for deterministic per-operation limits plus tokio::time::timeout for wall-clock defense.

### Rationale
- **Fuel metering**: Deterministic, same input always consumes same fuel
- **Wall-clock timeout**: Catches cases where fuel isn't decremented (host function calls)
- **Defense in depth**: If one mechanism fails, the other catches it

### Implementation Pattern
```rust
const FUEL_PER_SECOND: u64 = 100_000_000;

store.set_fuel(timeout_secs * FUEL_PER_SECOND)?;

let result = tokio::time::timeout(
    Duration::from_secs(timeout_secs + 1), // Wall-clock slightly longer
    instance.parse_metadata(&mut store, &data),
).await;

match result {
    Ok(Ok(output)) => Ok(output),
    Ok(Err(wasmtime::Error::FuelExhausted)) => Err(PluginTimeout),
    Ok(Err(e)) => Err(PluginError(e)),
    Err(_) => Err(PluginTimeout),
}
```

---

## 5. Hot-Reload Architecture

### Decision
Use per-plugin Engine/Component isolation with Arc-wrapped registry. New version loads into new Engine; old requests drain naturally on old Engine.

### Rationale
- Wasmtime does not support in-place module unloading
- Per-plugin isolation ensures new version doesn't affect in-flight requests
- Arc reference counting naturally cleans up old versions when last request completes
- No explicit "drain" logic needed

### Alternatives Considered
- **Shared Engine, reload Component**: Engine caches compiled modules, would need complex invalidation
- **Process restart**: Defeats the purpose of hot-reload
- **Request queuing during reload**: Adds latency, complex to implement correctly

### Implementation Pattern
```rust
pub struct PluginRegistry {
    plugins: Arc<RwLock<HashMap<String, ActivePlugin>>>,
}

pub struct ActivePlugin {
    engine: Arc<wasmtime::Engine>,
    component: wasmtime::component::Component,
    linker: wasmtime::component::Linker<PluginContext>,
    version: u64,
}

// Reload creates new Engine, doesn't touch old one
pub async fn reload(&self, manifest: Manifest, wasm: Vec<u8>) -> Result<()> {
    let new_version = self.get_next_version(&manifest.id).await;
    let engine = Arc::new(wasmtime::Engine::new(&config)?);
    let component = wasmtime::component::Component::new(&engine, &wasm)?;
    // Insert into registry; old version still valid for in-flight requests
    self.plugins.write().await.insert(manifest.id.clone(), ActivePlugin {
        engine, component, linker, version: new_version
    });
}
```

---

## 6. Plugin Distribution (Git + ZIP)

### Decision
Support two installation methods:
1. **Git URL**: Clone repository, checkout tag/commit, build WASM, install
2. **ZIP file**: Extract to temp directory, validate manifest, install WASM binary

### Rationale
- Git is the standard distribution method for open-source plugins
- ZIP supports air-gapped environments and pre-built binaries
- Both use the same manifest validation and installation path

### Git Installation Flow
1. Clone repository to temp directory
2. Checkout specified ref (tag, branch, or commit)
3. Parse and validate `plugin.toml` manifest
4. Build WASM (if source only) or locate pre-built `plugin.wasm`
5. Validate WASM component against expected WIT interface
6. Copy to plugin storage directory
7. Load into plugin registry

### ZIP Installation Flow
1. Extract ZIP to temp directory
2. Validate required files exist (`plugin.toml`, `plugin.wasm`)
3. Parse and validate manifest
4. Validate WASM component
5. Copy to plugin storage directory
6. Load into plugin registry

### Dependencies
- **git2**: Rust binding for libgit2 (already common in Rust ecosystem)
- **zip**: ZIP extraction (already in Cargo.toml)

---

## 7. Plugin Manifest Format

### Decision
Use TOML format for `plugin.toml` manifest with structured sections for plugin metadata, format handler configuration, capabilities, and resource requirements.

### Rationale
- TOML is human-readable and well-supported in Rust
- Already used in Rust ecosystem (Cargo.toml)
- Hierarchical structure maps well to plugin configuration

### Schema
```toml
[plugin]
name = "unity-assetbundle"      # Required: unique identifier (lowercase, hyphens)
version = "1.0.0"               # Required: semver
author = "Unity Technologies"   # Optional
license = "MIT"                 # Optional
description = "..."             # Optional
homepage = "https://..."        # Optional

[format]
key = "unity-assetbundle"       # Required: format key for API (lowercase, hyphens)
display_name = "Unity AssetBundle" # Required: human-readable name
extensions = [".assetbundle", ".unity3d"] # Required: file extensions

[capabilities]
parse_metadata = true           # Required: must be true
generate_index = false          # Optional: default false
validate_artifact = true        # Optional: default true

[requirements]
min_wasmtime = "21.0"           # Optional: minimum wasmtime version
min_memory_mb = 32              # Optional: minimum memory allocation
max_memory_mb = 256             # Optional: maximum memory limit
timeout_secs = 5                # Optional: execution timeout
```

---

## 8. Core Handler Coexistence

### Decision
Create a unified FormatHandler trait implemented by both core Rust handlers and WASM plugin wrappers. Registry returns Arc<dyn FormatHandler> regardless of implementation type.

### Rationale
- Services don't need to know if handler is core or plugin
- Same trait interface across entire codebase
- Core handlers can be disabled without code changes
- WASM wrapper implements same trait, just delegates to plugin instance

### Implementation Pattern
```rust
// Existing trait (unchanged)
#[async_trait]
pub trait FormatHandler: Send + Sync {
    fn format(&self) -> RepositoryFormat;
    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value>;
    async fn validate(&self, path: &str, content: &Bytes) -> Result<()>;
    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>>;
}

// WASM wrapper
pub struct WasmFormatHandler {
    plugin_id: String,
    format_key: String,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl FormatHandler for WasmFormatHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Custom(self.format_key.clone())
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        self.registry.execute_parse(&self.plugin_id, path, content).await
    }
    // ... other methods delegate to registry
}
```

### RepositoryFormat Extension
```rust
pub enum RepositoryFormat {
    Maven,
    Npm,
    PyPi,
    // ... existing formats
    Custom(String), // For WASM plugin formats
}
```

---

## 9. Database Schema Changes

### Decision
Extend existing Plugin table with WASM-specific fields; add new tables for plugin storage and format handler registration.

### New/Modified Tables

**plugins (modified)**
- Add: `source_type` ENUM ('core', 'wasm')
- Add: `source_url` VARCHAR (Git URL or file path)
- Add: `source_ref` VARCHAR (Git tag/commit)
- Add: `wasm_path` VARCHAR (path to stored .wasm file)
- Add: `format_key` VARCHAR (for format handler plugins)
- Add: `capabilities` JSONB (parsed from manifest)
- Add: `resource_limits` JSONB (memory, timeout)

**format_handlers (new)**
- `id` UUID PRIMARY KEY
- `format_key` VARCHAR UNIQUE NOT NULL
- `plugin_id` UUID REFERENCES plugins(id) NULLABLE (NULL = core handler)
- `display_name` VARCHAR NOT NULL
- `extensions` TEXT[] NOT NULL
- `is_enabled` BOOLEAN DEFAULT true
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP

---

## 10. API Endpoints

### Decision
REST API for plugin lifecycle management under `/api/v1/plugins` path.

### Endpoints
```
POST   /api/v1/plugins/install/git    - Install from Git URL
POST   /api/v1/plugins/install/zip    - Install from uploaded ZIP
POST   /api/v1/plugins/:id/enable     - Enable plugin
POST   /api/v1/plugins/:id/disable    - Disable plugin
POST   /api/v1/plugins/:id/reload     - Hot-reload plugin
DELETE /api/v1/plugins/:id            - Uninstall plugin
GET    /api/v1/plugins                - List all plugins
GET    /api/v1/plugins/:id            - Get plugin details
GET    /api/v1/formats                - List all format handlers (core + plugins)
POST   /api/v1/formats/:key/enable    - Enable format handler
POST   /api/v1/formats/:key/disable   - Disable format handler
```

---

## 11. Security Considerations

### Decision
Plugins run in WASM sandbox with restricted capabilities. No filesystem access beyond artifact data, no network access, no environment variables.

### Sandbox Restrictions
1. **Memory isolation**: WASM linear memory cannot access host memory
2. **Capability control**: Only import wasi:io/streams for artifact data
3. **Resource limits**: Memory and execution time bounded
4. **No network**: Plugins cannot make outbound requests
5. **No filesystem**: Plugins cannot read/write arbitrary files

### Trust Model
- Plugins are installed by administrators (trusted source)
- WASM sandbox provides defense-in-depth against bugs
- Not designed to defend against malicious plugins trying to escape sandbox

---

## 12. Testing Strategy

### Plugin Testing (Guest-Side)
```rust
// In plugin crate
#[test]
fn test_parse_metadata() {
    let data = include_bytes!("../testdata/sample.unity3d");
    let result = FormatHandler::parse_metadata("test.unity3d", data);
    assert!(result.is_ok());
}
```

### Host Integration Testing
```rust
// In backend
#[tokio::test]
async fn test_wasm_plugin_lifecycle() {
    let service = create_test_plugin_service();

    // Install
    service.install_from_zip(test_zip_bytes()).await.unwrap();

    // Execute
    let metadata = service.parse_artifact("unity-assetbundle", b"test").await.unwrap();

    // Uninstall
    service.uninstall("unity-assetbundle").await.unwrap();
}
```

---

## Summary

| Aspect | Decision | Key Dependency |
|--------|----------|----------------|
| Runtime | wasmtime with async_support | wasmtime, wasmtime-wasi |
| Interface | Component Model + WIT | wit-bindgen |
| Memory limits | ResourceLimiter trait | Built into wasmtime |
| Timeouts | Fuel + wall-clock dual | wasmtime fuel, tokio timeout |
| Hot-reload | Per-plugin Engine isolation | Arc<RwLock<HashMap>> |
| Distribution | Git clone + ZIP extract | git2, zip |
| Manifest | TOML format | toml crate |
| Core coexistence | Unified FormatHandler trait | async-trait |
| Storage | Existing plugins table + format_handlers | sqlx |
| API | REST under /api/v1/plugins | axum |
