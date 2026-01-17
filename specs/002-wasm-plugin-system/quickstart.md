# Plugin Development Quickstart

**Date**: 2026-01-17
**Feature**: 002-wasm-plugin-system

This guide walks you through creating a custom format handler plugin for Artifact Keeper.

## Prerequisites

- Rust 1.75+ with `wasm32-wasip2` target
- cargo-component (optional, for easier builds)

Install the WASM target:
```bash
rustup target add wasm32-wasip2
```

## Project Structure

Create a new Rust project:

```bash
cargo new --lib my-format-plugin
cd my-format-plugin
```

Your project should have this structure:

```
my-format-plugin/
├── Cargo.toml
├── plugin.toml          # Plugin manifest (required)
├── src/
│   └── lib.rs           # Plugin implementation
└── wit/
    └── format-plugin.wit # Interface definition (copy from Artifact Keeper)
```

## Step 1: Configure Cargo.toml

```toml
[package]
name = "my-format-plugin"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.25"

[profile.release]
opt-level = "z"   # Optimize for size
lto = true        # Link-time optimization
strip = true      # Strip symbols
```

## Step 2: Create plugin.toml

The plugin manifest describes your plugin to Artifact Keeper:

```toml
[plugin]
name = "my-format"           # Unique identifier (lowercase, hyphens)
version = "1.0.0"            # Semantic version
author = "Your Name"         # Optional
license = "MIT"              # Optional: SPDX identifier
description = "My custom format handler for XYZ artifacts"
homepage = "https://github.com/you/my-format-plugin"  # Optional

[format]
key = "my-format"            # Format key used in API (lowercase, hyphens)
display_name = "My Format"   # Human-readable name
extensions = [".xyz", ".myf"] # File extensions this format handles

[capabilities]
parse_metadata = true        # Required: must be true
generate_index = false       # Optional: set true if format needs index files
validate_artifact = true     # Optional: enable artifact validation

[requirements]
min_memory_mb = 32           # Minimum memory allocation (default: 32)
max_memory_mb = 128          # Maximum memory limit (default: 64)
timeout_secs = 5             # Execution timeout (default: 5)
```

## Step 3: Copy the WIT Interface

Copy this file to `wit/format-plugin.wit`:

```wit
package artifact-keeper:format@1.0.0;

interface handler {
    /// Artifact metadata returned by parse-metadata
    record metadata {
        path: string,
        version: option<string>,
        content-type: string,
        size-bytes: u64,
        checksum-sha256: option<string>,
    }

    /// Validation error details
    record validation-error {
        message: string,
        field: option<string>,
    }

    /// Returns the format key this handler supports
    format-key: func() -> string;

    /// Parse metadata from artifact content
    /// Called when an artifact is uploaded
    parse-metadata: func(path: string, data: list<u8>) -> result<metadata, string>;

    /// Validate artifact before storage
    /// Return ok(()) for valid, err(message) for invalid
    validate: func(path: string, data: list<u8>) -> result<_, string>;

    /// Generate index files for repository (optional)
    /// Return list of (path, content) tuples, or none if not applicable
    generate-index: func(artifacts: list<metadata>) -> result<option<list<tuple<string, list<u8>>>>, string>;
}

world format-plugin {
    export handler;
}
```

## Step 4: Implement the Handler

Edit `src/lib.rs`:

```rust
wit_bindgen::generate!({
    path: "wit",
    world: "format-plugin",
});

struct MyFormatHandler;

impl Guest for MyFormatHandler {
    fn format_key() -> String {
        "my-format".to_string()
    }

    fn parse_metadata(path: String, data: Vec<u8>) -> Result<Metadata, String> {
        // Parse your artifact format here
        // This example extracts basic metadata

        // Validate file extension
        if !path.ends_with(".xyz") && !path.ends_with(".myf") {
            return Err(format!("Invalid file extension for path: {}", path));
        }

        // Extract version from path or content
        let version = extract_version(&path, &data);

        // Determine content type
        let content_type = if path.ends_with(".xyz") {
            "application/x-xyz"
        } else {
            "application/x-myf"
        };

        Ok(Metadata {
            path,
            version,
            content_type: content_type.to_string(),
            size_bytes: data.len() as u64,
            checksum_sha256: None, // Host calculates checksum
        })
    }

    fn validate(path: String, data: Vec<u8>) -> Result<(), String> {
        // Validate the artifact content

        // Check minimum size
        if data.is_empty() {
            return Err("Artifact cannot be empty".to_string());
        }

        // Check magic bytes (example)
        if data.len() >= 4 && &data[0..4] != b"MYFT" {
            return Err("Invalid magic bytes: expected MYFT header".to_string());
        }

        // Add more validation as needed
        Ok(())
    }

    fn generate_index(artifacts: Vec<Metadata>) -> Result<Option<Vec<(String, Vec<u8>)>>, String> {
        // If your format needs index files (like Maven's maven-metadata.xml),
        // generate them here. Otherwise, return None.

        // Example: generate a simple JSON index
        if artifacts.is_empty() {
            return Ok(None);
        }

        let index = serde_json::json!({
            "artifacts": artifacts.iter().map(|a| {
                serde_json::json!({
                    "path": a.path,
                    "version": a.version,
                })
            }).collect::<Vec<_>>()
        });

        let index_bytes = serde_json::to_vec_pretty(&index)
            .map_err(|e| format!("Failed to serialize index: {}", e))?;

        Ok(Some(vec![
            ("index.json".to_string(), index_bytes),
        ]))
    }
}

// Helper function to extract version
fn extract_version(path: &str, _data: &[u8]) -> Option<String> {
    // Example: extract version from path like "mylib-1.0.0.xyz"
    let filename = path.rsplit('/').next()?;
    let name_part = filename.strip_suffix(".xyz")
        .or_else(|| filename.strip_suffix(".myf"))?;

    // Find version pattern (simplified)
    if let Some(dash_pos) = name_part.rfind('-') {
        let version = &name_part[dash_pos + 1..];
        if version.chars().next()?.is_ascii_digit() {
            return Some(version.to_string());
        }
    }
    None
}

// Required: export the handler implementation
export!(MyFormatHandler);
```

## Step 5: Build the Plugin

Build the WASM component:

```bash
cargo build --release --target wasm32-wasip2
```

The output will be at `target/wasm32-wasip2/release/my_format_plugin.wasm`.

Rename it to match the manifest:
```bash
cp target/wasm32-wasip2/release/my_format_plugin.wasm plugin.wasm
```

## Step 6: Package for Distribution

### Option A: ZIP File

Create a ZIP with the manifest and WASM binary:

```bash
zip my-format-plugin-1.0.0.zip plugin.toml plugin.wasm
```

### Option B: Git Repository

Commit your project to a Git repository:

```bash
git init
git add .
git commit -m "Initial release v1.0.0"
git tag v1.0.0
git push origin main --tags
```

## Step 7: Install the Plugin

### From ZIP File

```bash
curl -X POST http://localhost:8080/api/v1/plugins/install/zip \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@my-format-plugin-1.0.0.zip"
```

### From Git URL

```bash
curl -X POST http://localhost:8080/api/v1/plugins/install/git \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://github.com/you/my-format-plugin.git",
    "ref": "v1.0.0"
  }'
```

## Step 8: Enable and Test

Enable the plugin:

```bash
curl -X POST http://localhost:8080/api/v1/plugins/{plugin_id}/enable \
  -H "Authorization: Bearer $TOKEN"
```

Test with a sample artifact:

```bash
curl -X POST http://localhost:8080/api/v1/formats/my-format/test \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample.xyz"
```

## Testing Locally

### Unit Tests

Add tests to your plugin:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metadata() {
        let data = b"MYFT\x00\x01test content".to_vec();
        let result = MyFormatHandler::parse_metadata(
            "mylib-1.0.0.xyz".to_string(),
            data,
        );

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.content_type, "application/x-xyz");
    }

    #[test]
    fn test_validate_empty_file() {
        let result = MyFormatHandler::validate(
            "test.xyz".to_string(),
            vec![],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_invalid_magic() {
        let result = MyFormatHandler::validate(
            "test.xyz".to_string(),
            b"XXXX invalid".to_vec(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("magic bytes"));
    }
}
```

Run tests:
```bash
cargo test
```

### Integration Testing

Test the compiled WASM with wasmtime CLI:

```bash
# Install wasmtime
curl https://wasmtime.dev/install.sh -sSf | bash

# Run the component (basic validation)
wasmtime compile plugin.wasm
```

## Debugging

### Enable Logging

Plugins can log messages through the host (when implemented):

```rust
// Future: host-provided logging
// host::log_debug("Processing artifact...");
```

### Common Issues

1. **Build fails with "unknown target"**
   - Run `rustup target add wasm32-wasip2`

2. **Plugin won't load: "invalid component"**
   - Ensure you're using wit-bindgen 0.25+
   - Check WIT file matches the host's interface

3. **Execution timeout**
   - Increase `timeout_secs` in plugin.toml
   - Optimize parsing logic for large files

4. **Memory limit exceeded**
   - Increase `max_memory_mb` in plugin.toml
   - Process data in chunks instead of loading entirely

## Best Practices

1. **Keep plugins focused**: One format per plugin
2. **Validate early**: Check magic bytes and structure before parsing
3. **Handle errors gracefully**: Return descriptive error messages
4. **Test with real artifacts**: Use actual files from your target format
5. **Document your format**: Include README with format specification
6. **Version properly**: Use semantic versioning for releases

## Example Plugins

See these examples for reference:

- `plugins/sample-plugin/` - Basic format handler template
- `plugins/unity-assetbundle/` - Real-world Unity format handler (future)

## Resources

- [WIT Language Reference](https://component-model.bytecodealliance.org/wit-overview.html)
- [wit-bindgen Documentation](https://github.com/bytecodealliance/wit-bindgen)
- [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
