# Repository Guidelines

## Project Structure & Module Organization
- Root binary crate `vopono/`: entry at `src/main.rs`; CLI modules in `src/*.rs`.
- Core library crate `vopono_core/`: main code under `src/` with `config/`, `network/`, and `util/` modules. Add providers in `vopono_core/src/config/providers/`.
- Docs and assets: `README.md`, `USERGUIDE.md`, images in `logos/`, CI in `.github/workflows/`.
- User config lives in `~/.config/vopono/` (e.g., `config.toml`).

## Build, Test, and Development Commands
- Build: `cargo build` (workspace by default).
- Run tests: `cargo test --workspace`.
- Lint/format (CI-enforced):
  - `cargo fmt --all`
  - `cargo clippy --all-features --all-targets -- -D warnings`
- Run locally (example):
  - `cargo run -- exec --provider mullvad --server se firefox`
  - Start root daemon (recommended for local runs): `sudo -E cargo run -- daemon`
    - With the daemon running, non-root `cargo run -- exec ...` forwards over `/run/vopono.sock`.
- Install from repo: `./install.sh` (invokes `cargo install`).

## Coding Style & Naming Conventions
- Rust 2024 edition; use `rustfmt` defaults (4-space indent). Keep code simple and modular.
- Names: modules/files `snake_case`; functions/vars `snake_case`; types/traits/enums `PascalCase`.
- Errors: prefer `anyhow::Result<T>` and propagate with `?`.
- Logging via `log`/`pretty_env_logger`; avoid println for non-user output.

## Testing Guidelines
- Place unit tests next to code (`#[cfg(test)] mod tests { ... }`). Most tests live in `vopono_core` (e.g., parsing and config).
- Add tests for new providers, parsers, and utilities; keep them deterministic and offline.
- Run `cargo test --workspace` before pushing. CI runs fmt, clippy, and tests on PRs.

## Commit & Pull Request Guidelines
- Commits: concise, imperative mood (e.g., "Add IPv6 endpoint support"). Reference issues/PRs when relevant (e.g., "Fix #123", "(#456)").
- PRs should include: clear description of the change, rationale, CLI examples if applicable, and tests for new logic. Confirm fmt, clippy, and tests pass locally.
- Keep PRs focused; avoid unrelated refactors and churn.

## Security & Configuration Tips
- Run `vopono` as your user; it escalates privileges only when required. Avoid running the whole session as root.
- External deps: install `wireguard-tools` and/or `openvpn` when testing respective flows.
- Treat files under `~/.config/vopono/` as sensitive (may contain credentials). Do not commit real credentials.

## Agent-Specific Instructions
- Keep changes minimal and aligned with existing modules. Prefer provider logic in `vopono_core`; keep CLI glue in `src/`.
- Do not rename files or alter public APIs without prior discussion.
 - Daemon mode lives in `src/daemon.rs` and is started via `vopono daemon` (root). The CLI attempts to forward `exec` to the daemon when available.
