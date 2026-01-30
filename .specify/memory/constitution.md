<!--
  Sync Impact Report
  ==================
  Version change: 0.0.0 (template) → 1.0.0 (initial ratification)

  Modified principles: N/A (first ratification)

  Added sections:
    - Core Principles (8 principles: I–VIII)
    - Technology Stack (locked stack with amendment requirements)
    - Quality Gates (tiered CI/CD gates)
    - Governance (amendment procedure and compliance)

  Removed sections: N/A

  Templates requiring updates:
    - .specify/templates/plan-template.md — ✅ compatible
      (Constitution Check section already references constitution file)
    - .specify/templates/spec-template.md — ✅ compatible
      (User scenarios and requirements align with principles)
    - .specify/templates/tasks-template.md — ✅ compatible
      (Phase structure supports tiered testing and layered implementation)
    - .specify/templates/checklist-template.md — ✅ compatible
      (Generic template, no constitution-specific references needed)
    - .specify/templates/agent-file-template.md — ✅ compatible
      (Technology sections align with locked stack)

  Follow-up TODOs: None
-->

# Artifact Keeper Constitution

## Core Principles

### I. Layered Architecture

All backend code MUST follow the four-layer separation:

1. **HTTP Layer** — Axum route definitions, middleware, request/response
   serialization. Handlers MUST be thin: extract parameters, call a
   service, return a response.
2. **Service Layer** — Business logic, validation, orchestration.
   Services MUST NOT depend on HTTP types (StatusCode, Json extractors).
3. **Model Layer** — Data structures with sqlx derive macros. Models
   MUST NOT contain business logic beyond field-level validation.
4. **Storage/Repository Layer** — Database queries and external storage
   operations. MUST be the only layer that issues SQL or storage calls.

Cross-layer imports flow strictly downward: handlers → services →
models → storage. Upward or lateral imports are prohibited.

### II. Type Safety

- Rust code MUST compile with zero warnings under `cargo clippy -D warnings`.
- TypeScript code MUST pass `tsc --strict` with no suppressions
  (`@ts-ignore`, `@ts-expect-error`) unless documented with a linked
  issue explaining why the suppression is necessary.
- All API boundaries (request/response bodies, query parameters) MUST
  use strongly typed structs or interfaces — no `any`, no untyped JSON
  pass-through.
- Errors MUST use the centralized `AppError` enum (backend) or typed
  error interfaces (frontend). Raw string errors are prohibited at API
  boundaries.

### III. Tiered Testing

Testing follows a three-tier gate model enforced by CI:

| Tier | Trigger | Scope | Max Duration |
|------|---------|-------|-------------|
| 1 | Every push/PR | Lint (`fmt`, `clippy`, `eslint`), type-check, unit tests | 5 min |
| 2 | Merge to main | Full integration tests (requires PostgreSQL) | 15 min |
| 3 | Release tag / manual | E2E (Playwright), native client tests, stress, failure injection | 30 min |

- Tier 1 failures MUST block PR merge.
- Tier 2 failures MUST block release promotion.
- Tier 3 failures MUST block release publication.
- New backend services MUST include unit tests in inline `#[cfg(test)]`
  modules.
- New frontend components MUST include Vitest test files.
- New API endpoints MUST be covered by integration tests.

### IV. API-First Design

- All HTTP endpoints MUST be versioned under `/api/v1/`.
- Breaking changes MUST increment the API version prefix (e.g., `/api/v2/`).
- Error responses MUST use the structured JSON format:
  `{ "code": "ERROR_CODE", "message": "Human-readable message" }`.
- Health (`/health`), readiness (`/ready`), and metrics (`/metrics`)
  endpoints MUST remain unauthenticated and outside API versioning.
- New endpoints MUST define request/response types before implementation
  (contract-first). OpenAPI definitions in `specs/` contracts are
  the source of truth when present.

### V. Format Modularity

- Each package format (Maven, PyPI, NPM, Docker, etc.) MUST be
  implemented as an independent module under `backend/src/formats/`.
- Format handlers MUST NOT depend on other format handlers.
- Adding or removing a format MUST NOT require changes to core
  services, routing infrastructure, or other format modules.
- Format-specific metadata parsing and validation MUST live within the
  format module, not in shared services.

### VI. Security by Default

- Authentication MUST use JWT with short-lived access tokens and
  separate refresh tokens.
- Passwords MUST be hashed with bcrypt; raw passwords MUST NOT appear
  in logs, error messages, or API responses.
- Administrative endpoints (`/admin`, `/users`, `/permissions`,
  `/webhooks`, `/migrations`) MUST require authentication middleware.
- Secrets (JWT secret, S3 credentials, OIDC secrets) MUST be loaded
  from environment variables, never committed to source control.
- All dependencies MUST pass `cargo audit` and `npm audit` with no
  critical or high severity vulnerabilities. Known exceptions MUST be
  documented in an allow-list with justification.

### VII. Observability

- All request errors MUST be logged via `tracing::error!` with
  structured fields (error type, error code).
- Services MUST use the `tracing` crate for structured logging — no
  `println!` or `eprintln!` in production code paths.
- Prometheus-compatible metrics MUST be exposed at `/metrics`.
- Audit-sensitive operations (create, delete, permission changes) MUST
  produce audit log entries.

### VIII. Simplicity

- YAGNI: features MUST NOT be implemented until a spec in `specs/`
  defines the requirement.
- New abstractions MUST justify their existence — three concrete use
  cases minimum before extracting a shared utility.
- Configuration MUST use environment variables with sensible defaults.
  No configuration file formats unless a spec explicitly requires it.
- Dependencies MUST be justified. Adding a new crate or npm package
  requires confirming no existing dependency covers the use case.

## Technology Stack

The following stack is locked. Changes require a constitution amendment
(MAJOR version bump) with migration plan.

| Layer | Technology | Version Floor |
|-------|-----------|--------------|
| Backend runtime | Rust | 1.75+ |
| Backend framework | Axum | 0.7+ |
| Async runtime | Tokio | 1.35+ |
| Database | PostgreSQL | 16+ |
| Database driver | sqlx | 0.8+ |
| Plugin runtime | wasmtime | 21.0+ |
| Frontend language | TypeScript | 5.3+ |
| Frontend framework | React | 19+ |
| UI components | Ant Design | 6+ |
| Build tool | Vite | 7+ |
| Data fetching | TanStack Query | 5+ |
| E2E testing | Playwright | 1.41+ |
| Unit testing (FE) | Vitest | 4+ |
| CI/CD | GitHub Actions | N/A |
| Containerization | Docker + Compose | N/A |

**Permitted without amendment**: Patch and minor version upgrades that
do not change public APIs or require migration.

**Requires amendment**: Major version upgrades, replacing a technology
(e.g., switching from Axum to Actix), or adding a new infrastructure
dependency (e.g., Redis, message queue).

## Quality Gates

### PR Merge Gate (Tier 1)

All of the following MUST pass before a PR can be merged:

```
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --lib
cd frontend && npm run lint
cd frontend && npm run type-check
cd frontend && npm run test:run
```

### Main Branch Gate (Tier 2)

After merge to main, the following MUST pass:

```
cargo test --workspace          # Full integration tests
```

Failures at this tier MUST be treated as P0 and fixed before further
merges.

### Release Gate (Tier 3)

Before publishing a release, the following MUST pass:

```
./scripts/run-e2e-tests.sh --profile all
./scripts/run-e2e-tests.sh --stress --failure
```

Failures at this tier MUST block the release.

### Security Gate (Continuous)

```
cargo audit
npm audit --audit-level=high
```

Critical and high vulnerabilities MUST be resolved or documented in an
allow-list within 7 days of detection.

## Governance

1. **Supremacy**: This constitution supersedes all other development
   practices. Conflicting guidance in READMEs, comments, or external
   docs MUST defer to this document.

2. **Amendment procedure**:
   - Propose changes via a PR modifying this file.
   - PR description MUST include: rationale, impact assessment, and
     migration plan (if breaking).
   - Version bump follows semver:
     - **MAJOR**: Principle removal, redefinition, or stack change.
     - **MINOR**: New principle or section added.
     - **PATCH**: Clarification, wording, or typo fix.

3. **Compliance review**: All PRs and code reviews MUST verify that
   changes comply with the principles above. Reviewers SHOULD reference
   the specific principle number (e.g., "Principle III requires...") when
   requesting changes.

4. **Complexity justification**: Any deviation from these principles
   MUST be documented in the relevant spec's `plan.md` under
   "Complexity Tracking" with: the violation, why it is needed, and
   why the simpler alternative was rejected.

5. **Spec-driven development**: All features MUST have a specification
   in `specs/` before implementation begins. The spec framework
   (`/speckit.*` commands) is the standard tool for creating and
   managing specifications.

**Version**: 1.0.0 | **Ratified**: 2026-01-30 | **Last Amended**: 2026-01-30
