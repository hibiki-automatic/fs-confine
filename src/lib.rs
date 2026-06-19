//! `fs-confine`: the **web-free** filesystem-confinement kernel (ADR-0008
//! Phase 2 — the security phase).
//!
//! Everything here touches only `std` and `libc` — there is **zero**
//! warp/tokio/hyper/web dependency, and **no edge to the other kernels**
//! (`doc-core`/`md-render`): this is an independent DAG **leaf**, verified by
//! `cargo tree -p fs-confine -e normal`. The confinement funnel ports verbatim
//! across the network boundary, so research-thin-server (goal D1) reuses it to
//! close its `PathBuf::join` traversal hole without the daemon stack.
//!
//! ## Modules
//! - [`roots`] — the multi-root registry: project-root detection, the
//!   sensitive-path denylist ([`roots::Roots::is_sensitive`]), the sliding-TTL
//!   registry, and plain-text persistence. Std-only and pure (clock/`$HOME`/
//!   state-dir injected).
//! - [`confine`] — the SOLE confinement funnel: [`confine::confine_path`] (the
//!   canonical gate), [`confine::confine_read`] (TOCTOU-free held-fd read),
//!   [`confine::confine_save`] (dirfd-relative symlink-safe atomic write), and
//!   [`confine::confine_link`] (the `/outside` classifier). The one production
//!   `unsafe` (libc `openat`/`renameat`/`fstat`) is contained here and
//!   documented at each call site.
//!
pub mod roots;
pub mod confine;

// Re-export the load-bearing surface at the crate root so embedders (and
// md-preview's re-exports) get a flat API: `fs_confine::{confine_read, Roots,
// Confine, …}`. The funnel free functions stay addressable as
// `fs_confine::confine::confine_read` too (module path unchanged).
pub use confine::{
    ConfineError, ConfinedFile, LinkResolution, confine_link, confine_path, confine_read,
    confine_save, DEFAULT_MAX_FILE_SIZE,
};
pub use roots::{Root, RootError, RootKind, Roots, ROOT_MARKERS, ROOT_TTL};
