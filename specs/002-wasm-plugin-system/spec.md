# Feature Specification: WASM Plugin System

**Feature Branch**: `002-wasm-plugin-system`
**Created**: 2026-01-17
**Status**: Draft
**Input**: User description: "WASM Plugin System for Artifact Keeper - A hot-loadable plugin architecture that allows users to add custom artifact format handlers via WASM plugins. Plugins can be installed from Git URLs or local ZIP files without restarting the server. Core format handlers (Maven, npm, PyPI, etc.) remain compiled-in but follow the same trait interface and can be enabled/disabled via configuration. The system uses wasmtime for WASM runtime, supports plugin manifests (plugin.toml), and provides REST API endpoints for plugin lifecycle management (install, uninstall, enable, disable, reload)."

## User Scenarios & Testing

### User Story 1 - Install Plugin from Git Repository (Priority: P1)

An administrator wants to extend the artifact registry with a custom format handler for Unity packages. They install a community-developed plugin directly from its Git repository without stopping the server.

**Why this priority**: This is the core value proposition - enabling extensibility without downtime. Git-based installation is the primary distribution method for plugins.

**Independent Test**: Can be fully tested by installing a sample plugin from a Git URL and verifying that the new format becomes available for repository creation. Delivers immediate value by enabling custom formats.

**Acceptance Scenarios**:

1. **Given** the server is running with no Unity format support, **When** an admin installs a plugin from `https://github.com/example/unity-plugin.git`, **Then** the Unity format becomes available within 60 seconds without server restart.

2. **Given** a plugin Git URL with a specific tag (e.g., `v1.0.0`), **When** the admin installs that version, **Then** that exact version is installed and recorded in the plugin registry.

3. **Given** an invalid Git URL or unreachable repository, **When** the admin attempts to install, **Then** a clear error message is displayed and the system remains stable.

4. **Given** a plugin with missing or invalid manifest, **When** installation is attempted, **Then** the installation fails with a descriptive validation error.

---

### User Story 2 - Install Plugin from ZIP File (Priority: P2)

An administrator has a plugin package (ZIP file) that they want to install directly, either for offline environments or internal/proprietary plugins not hosted in Git.

**Why this priority**: Essential for air-gapped environments and proprietary plugins. Secondary to Git as it's a less common distribution method.

**Independent Test**: Can be tested by uploading a ZIP file through the API and verifying the plugin activates. Delivers value for offline/enterprise scenarios.

**Acceptance Scenarios**:

1. **Given** a valid plugin ZIP file, **When** the admin uploads it via API, **Then** the plugin is extracted, validated, and activated without restart.

2. **Given** a ZIP file missing required files (plugin.toml or plugin.wasm), **When** upload is attempted, **Then** installation fails with a clear error listing missing components.

3. **Given** a corrupted ZIP file, **When** upload is attempted, **Then** the system rejects it gracefully without affecting other operations.

---

### User Story 3 - Enable/Disable Core Format Handlers (Priority: P2)

An administrator wants to reduce the system's attack surface by disabling format handlers they don't use (e.g., disabling Conan and RubyGems if only using Maven and npm).

**Why this priority**: Security best practice and resource optimization. Tied with P2 as both enhance operational flexibility.

**Independent Test**: Can be tested by disabling a core format and verifying it's no longer available for new repositories. Delivers value by reducing attack surface.

**Acceptance Scenarios**:

1. **Given** RubyGems format is enabled by default, **When** an admin disables it via API, **Then** new RubyGems repositories cannot be created, but existing ones remain accessible in read-only mode.

2. **Given** a disabled format, **When** an admin re-enables it, **Then** the format becomes available again without restart.

3. **Given** an attempt to disable all formats, **When** submitted, **Then** the system rejects the request with a message that at least one format must remain enabled.

---

### User Story 4 - Hot-Reload Plugin (Priority: P3)

An administrator needs to update a plugin to a new version without disrupting ongoing artifact operations or requiring a server restart.

**Why this priority**: Important for maintaining uptime during updates, but less frequent than initial installation.

**Independent Test**: Can be tested by installing v1.0.0, then reloading to v2.0.0, and verifying the new version is active. Delivers value by enabling zero-downtime updates.

**Acceptance Scenarios**:

1. **Given** a plugin v1.0.0 is installed, **When** admin triggers reload with a new Git tag v2.0.0, **Then** the new version replaces the old one while in-flight requests complete normally.

2. **Given** an artifact download in progress using a plugin, **When** that plugin is reloaded, **Then** the download completes successfully with the old version before the new version takes over.

3. **Given** a reload that fails validation, **When** triggered, **Then** the original plugin version remains active and an error is logged.

---

### User Story 5 - Uninstall Plugin (Priority: P3)

An administrator needs to remove a plugin that is no longer needed or has been superseded by a better alternative.

**Why this priority**: Maintenance operation that's less frequent but necessary for system hygiene.

**Independent Test**: Can be tested by uninstalling a plugin and verifying its format is no longer available. Delivers value by cleaning up unused extensions.

**Acceptance Scenarios**:

1. **Given** a plugin is installed with no repositories using its format, **When** admin uninstalls it, **Then** the plugin is removed and its format disappears from available formats.

2. **Given** repositories exist using a plugin's format, **When** admin attempts to uninstall, **Then** the system warns about affected repositories and requires confirmation.

3. **Given** a plugin is uninstalled, **When** listing plugins, **Then** it no longer appears in the registry.

---

### User Story 6 - Plugin Developer Creates New Format Handler (Priority: P4)

A developer wants to create a custom plugin for a proprietary artifact format used internally at their organization.

**Why this priority**: Enables ecosystem growth but is developer-facing, not operator-facing. Important for long-term adoption.

**Independent Test**: Can be tested by following documentation to create a minimal plugin, build it, and install it locally. Delivers value by enabling community contributions.

**Acceptance Scenarios**:

1. **Given** a developer uses a plugin template/scaffold, **When** they implement the required interface and build, **Then** they produce a valid plugin.wasm file.

2. **Given** a locally built plugin, **When** installed from local path, **Then** the plugin activates and can process artifacts.

3. **Given** plugin documentation, **When** a developer reads it, **Then** they understand the plugin manifest format, required exports, and how to test locally.

---

### Edge Cases

- What happens when two plugins claim the same format key? The second installation fails with a conflict error indicating which plugin already owns that format.
- What happens if a plugin crashes during artifact processing? The WASM sandbox contains the crash; an error is returned for that request but the server remains stable and other requests are unaffected.
- What happens during a network timeout while cloning a Git repository? Installation fails with a timeout error after 60 seconds; partial files are cleaned up automatically.
- What happens if a plugin consumes excessive memory? WASM memory limits (configurable, default 64MB) prevent runaway consumption; exceeding limit terminates the plugin execution with a clear error.
- What happens when a plugin is disabled while processing a request? In-flight requests complete with the current plugin version; new requests return "format unavailable" error.
- What happens if the plugin.wasm is missing but plugin.toml exists? Installation fails with an error indicating the WASM binary is required.

## Requirements

### Functional Requirements

- **FR-001**: System MUST allow installing plugins from Git repository URLs with optional branch, tag, or commit reference.
- **FR-002**: System MUST allow installing plugins from uploaded ZIP files containing the plugin package.
- **FR-003**: System MUST validate plugin manifests (plugin.toml) before activation, checking for required fields (name, version, format key) and valid format.
- **FR-004**: System MUST support hot-loading plugins without requiring server restart.
- **FR-005**: System MUST allow enabling and disabling individual core format handlers through the API.
- **FR-006**: System MUST provide REST API endpoints for plugin lifecycle management: install, uninstall, enable, disable, reload, and list.
- **FR-007**: System MUST sandbox WASM plugin execution to prevent plugins from crashing the main process or accessing unauthorized system resources.
- **FR-008**: System MUST log plugin installation, activation, errors, and lifecycle events for auditing and troubleshooting.
- **FR-009**: System MUST track plugin versions and prevent duplicate installations of the same plugin name.
- **FR-010**: System MUST enforce configurable resource limits on WASM plugins (memory limit, execution timeout).
- **FR-011**: System MUST gracefully handle plugin failures during artifact operations, returning appropriate errors without affecting other concurrent requests.
- **FR-012**: System MUST allow WASM plugins and core handlers to coexist, with both implementing the same format handler interface.
- **FR-013**: System MUST warn before uninstalling a plugin if repositories depend on its format, requiring explicit confirmation to proceed.
- **FR-014**: System MUST support installing plugins from local file paths for development and testing purposes.
- **FR-015**: System MUST prevent format key conflicts - only one handler (core or plugin) may own a format key at a time.

### Key Entities

- **Plugin**: An installable extension that provides a format handler. Has identity (name, version, author), source (Git URL, ZIP, or local path), status (active, disabled, error), configuration, and resource limits.

- **Plugin Manifest**: Metadata file (plugin.toml) describing the plugin's name, version, author, license, format key, display name, file extensions, capabilities (parse metadata, generate index, validate), and resource requirements.

- **Format Handler**: The functional component that processes artifacts for a specific format. Provides operations like metadata extraction, index generation, path validation, and content-type detection. Both core handlers and WASM plugins implement the same interface.

- **Plugin Registry**: Runtime collection of all available format handlers (core and external). Maintains mapping from format keys to handlers, supports hot-swapping of WASM plugins, and tracks enabled/disabled state.

- **Plugin Event Log**: Audit trail of plugin lifecycle events including installation, enabling, disabling, reloading, errors, and uninstallation with timestamps and relevant details.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Plugins installed from Git repositories are active and usable within 60 seconds of initiating installation.
- **SC-002**: Zero server restarts required for any plugin lifecycle operation (install, uninstall, enable, disable, reload).
- **SC-003**: A plugin crash or timeout does not affect other concurrent requests; system remains responsive with less than 100ms impact on unrelated operations.
- **SC-004**: Administrators can disable any core format handler; the disabled format is unavailable for new repository creation within 5 seconds of the API call.
- **SC-005**: Plugin installation errors provide actionable messages that identify the specific failure cause (network error, validation error, build error, conflict).
- **SC-006**: WASM plugins exceeding resource limits (memory, execution time) are terminated gracefully with clear error messages indicating which limit was exceeded.
- **SC-007**: A developer following documentation can create, build, and successfully install a minimal custom format plugin within 30 minutes.

## Assumptions

- Git is available on the server for cloning plugin repositories, or the system uses a library-based Git implementation.
- Plugin developers have access to a Rust toolchain or the plugin distribution includes pre-built WASM binaries.
- Plugins are installed by trusted administrators; the WASM sandbox provides defense-in-depth but is not a complete security boundary against malicious plugins.
- The existing format handler pattern in the codebase can be adapted to work across the WASM boundary with acceptable performance.
- Plugin operations (metadata parsing, validation) complete within reasonable time bounds (under 5 seconds for typical artifacts).

## Out of Scope

- Plugin marketplace or centralized registry service (future roadmap item)
- Automatic plugin updates or version checking (manual reload required for updates)
- Cryptographic plugin signing or verification (trust is established by installation source and administrator action)
- Non-format plugins such as authentication providers, storage backends, or webhook handlers (focus is on format handlers for this iteration)
- Graphical user interface for plugin management (API-only; frontend integration can be added later)
- Plugin dependency management (plugins are self-contained units)
