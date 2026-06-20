# fs-confine

[![CI](https://github.com/hibiki-automatic/fs-confine/actions/workflows/ci.yml/badge.svg)](https://github.com/hibiki-automatic/fs-confine/actions/workflows/ci.yml)

`fs-confine` is the **web-free filesystem confinement kernel** extracted from the mycelium editor stack (ADR-0008, Phase 2 — the security phase). It provides a multi-root registry (`Roots`) and a single hardened confinement funnel (`confine_path`): canonicalize + `O_NOFOLLOW` + `fstat` on a held file descriptor, dirfd-relative atomic save, the sensitive-path denylist, and a `Confine` trait that builds the root union and fans out exactly once. The crate depends only on `std` and `libc` — no web, no async, no edge to the other kernels (`doc-core`/`md-render`). It is an independent DAG leaf: verify with `cargo tree -p fs-confine -e normal`. `research-thin-server` (D1) reuses this funnel to close its `PathBuf::join` traversal hole without pulling in the daemon stack.

## Build

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

Requires stable Rust (edition 2024) on Linux / macOS (Unix-only: uses `libc` `openat`/`renameat`/`fstat`).

## API surface

```rust
use fs_confine::{Roots, Confine, confine_read, confine_save, confine_path};

// Build a root set from project directories
let roots = Roots::new(vec!["/home/user/docs".into()]);

// Gate a user-supplied path through the confinement funnel
let safe = confine_path(&roots, "/home/user/docs/notes.md")?;

// TOCTOU-free read (held fd)
let bytes = confine_read(&roots, "/home/user/docs/notes.md")?;

// Dirfd-relative atomic save (symlink-safe)
confine_save(&roots, "/home/user/docs/notes.md", &bytes)?;
```

The sole production `unsafe` (libc `openat`/`renameat`/`fstat`) is contained in `backend.rs` (`UnixBackend`) and documented at each call site.

## Policy / mechanism seam (Phase A)

The funnel is split into two concerns so a future macOS/Windows (or `cap-std`) backend can slot in without touching policy:

- **Portable policy** (`confine.rs`): roots registry, sensitive-path denylist, root-union containment, `/outside` classification, lexical/canonical gating. No OS-specific syscalls — only `std::path::Path::canonicalize`.
- **Unix mechanism** (`backend.rs`, crate-private): the `ConfineBackend` trait abstracts three syscall clusters — `open_nofollow` (`O_NOFOLLOW` open), `stat_fd` (`fstat` on the held fd), and `atomic_save` (dirfd-relative `openat`/`renameat`/`unlinkat`). The production `UnixBackend` struct implements this trait and contains all production `unsafe`.

The public API is unchanged. A future platform backend implements `ConfineBackend` and wires into the policy layer without altering `confine.rs`.

## Modules

- `roots` — multi-root registry: project-root detection, sensitive-path denylist, sliding-TTL registry, plain-text persistence
- `confine` — the sole confinement funnel (portable policy): `confine_path`, `confine_read`, `confine_save`, `confine_link`
- `backend` (crate-private) — OS-specific mechanism: `ConfineBackend` trait + `UnixBackend` (contains all `unsafe`)

## Part of the [mycelium](https://github.com/hibiki-automatic) ecosystem

| Repo | Description |
|------|-------------|
| [md-render](https://github.com/hibiki-automatic/md-render) | Markdown → HTML renderer (Rust crate) |
| [doc-core](https://github.com/hibiki-automatic/doc-core) | Web-free CRDT / document kernel |
| [fs-confine](https://github.com/hibiki-automatic/fs-confine) | Web-free filesystem confinement kernel (this repo) |
| [md-preview](https://github.com/hibiki-automatic/md-preview) | Collaborative Markdown preview daemon |
| [mycelium-editor](https://github.com/hibiki-automatic/mycelium-editor) | CodeMirror 6 editor component (npm) |
| [nvim-md-preview](https://github.com/hibiki-automatic/nvim-md-preview) | Neovim live-preview plugin |
| [md-hub](https://github.com/hibiki-automatic/research-thin-server) | Research document hub (Axum server) |
