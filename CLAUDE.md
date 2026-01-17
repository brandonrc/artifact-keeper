# Artifact Keeper Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-01-14

## Active Technologies
- Rust 1.75+ (backend), TypeScript 5.x (frontend) + wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum (002-wasm-plugin-system)
- PostgreSQL (existing), filesystem for WASM binaries (002-wasm-plugin-system)
- TypeScript 5.3, React 19.x + Ant Design 6.x, React Router 7.x, TanStack Query 5.x, Axios (003-frontend-ui-parity)
- N/A (frontend only, uses backend APIs) (003-frontend-ui-parity)

- Rust 1.75+ (backend), TypeScript 5.x (frontend) (001-artifact-registry)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust 1.75+ (backend), TypeScript 5.x (frontend): Follow standard conventions

## Recent Changes
- 003-frontend-ui-parity: Added TypeScript 5.3, React 19.x + Ant Design 6.x, React Router 7.x, TanStack Query 5.x, Axios
- 002-wasm-plugin-system: Added Rust 1.75+ (backend), TypeScript 5.x (frontend) + wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum
- 001-artifact-registry: Added Rust 1.75+ (backend), TypeScript 5.x (frontend)


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
