//! Multi-root registry for the always-on preview daemon (ADR-0005 §1,
//! `design/always-on-secure-preview.md` §1).
//!
//! The daemon serves files from *every* project the user opens. This module
//! owns the **persisted set of allowed roots** and the logic that turns a
//! freshly-opened file into a confinement root:
//!
//! - **Project-root detection** — walk a file's ancestors for a marker
//!   (`.git`, `Cargo.toml`, `package.json`, `.hg`, `.md-preview-root`),
//!   **stopping before `$HOME`** so `$HOME` is never a recursive root even if
//!   `~/.git` exists (dotfiles-in-git must not expose all of home).
//! - **Single-file fallback** — when no project root is found, or the project
//!   root would land on `$HOME`/a denylisted dir, only that one file is served
//!   (no directory scope, no recursion).
//! - **Sensitive-path denylist** ([`Roots::is_sensitive`]) — `~/.ssh`,
//!   `~/.gnupg`, `~/.aws`, `~/.config`, `~/.netrc`, `~/.kube`, `~/.docker`,
//!   `~/.local/share/keyrings`, `/etc`, and `$HOME` itself as a recursive root.
//! - **30-day sliding TTL** — a root's expiry renews on access; only abandoned
//!   roots are GC'd ([`Roots::gc`]).
//! - **Plain-text persistence** — [`Roots::save`] / [`Roots::load`] round-trip
//!   the registry to `~/.local/state/md-preview/roots`.
//!
//! ## Purity / injection
//! This module is **std-only and pure**: `$HOME`, the state-dir, and the clock
//! are all **injected** (see [`Roots::new`] / [`Roots::with_state_dir`] /
//! [`Roots::register_for_at`]). No real time, `$HOME`, or filesystem layout is
//! read from the process environment in the registry logic, so the unit tests
//! below are fully deterministic.
//!
//! ## INTEGRATOR NOTE — Track A finding (audit/02-security.md MED-4)
//! The denylist ([`Roots::is_sensitive`]) and ownership check MUST be enforced
//! **even on the empty-registry / single-file fallback path**. The earlier
//! `confine_abs` empty-registry branch confined against a primary root without
//! consulting `is_sensitive`/`owning_root`, so if the registry emptied while
//! that root pointed somewhere sensitive the denylist was bypassed. The funnel
//! that wires this module (`server::confine_abs`) must therefore call
//! [`Roots::is_sensitive`] on the canonical target **before** any single-file
//! fallback, never short-circuiting it when [`Roots::union`] is empty. This
//! module enforces it on its own paths: [`Roots::register_root`] refuses
//! sensitive recursive roots, and [`Roots::resolve`] downgrades a sensitive
//! project root to a single-file scope.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Markers that identify a project root, in priority order. `.git` first (the
/// common case), then the per-ecosystem manifests, then md-preview's own
/// escape hatch (`.md-preview-root`) for projects that have none of the above.
pub const ROOT_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "package.json",
    ".hg",
    ".md-preview-root",
];

/// The sliding TTL for a registered root: 30 days, renewed on every access.
pub const ROOT_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Whether a root grants recursive directory scope or just a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootKind {
    /// A project root: the whole directory tree is in scope (recursive).
    Directory,
    /// A single-file fallback: only the one file is served, no recursion.
    SingleFile,
}

impl RootKind {
    /// Stable lowercase token used in the plain-text persistence format.
    fn as_token(self) -> &'static str {
        match self {
            RootKind::Directory => "dir",
            RootKind::SingleFile => "file",
        }
    }

    fn from_token(token: &str) -> Option<RootKind> {
        match token {
            "dir" => Some(RootKind::Directory),
            "file" => Some(RootKind::SingleFile),
            _ => None,
        }
    }
}

/// A single registered root: its scope kind, its canonical-ish absolute path,
/// and the last time it was accessed (for the sliding TTL). `last_used` is a
/// wall-clock instant supplied by the injected clock, stored as a
/// [`SystemTime`] so it survives persistence as a Unix timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// Directory (recursive) vs. single-file (no recursion) scope.
    pub kind: RootKind,
    /// The absolute, lexically-normalized root path.
    pub path: PathBuf,
    /// When this root was last accessed; the TTL renews from here.
    pub last_used: SystemTime,
}

impl Root {
    /// Whether this root has outlived its sliding TTL as of `now`.
    fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.last_used) {
            Ok(age) => age > ROOT_TTL,
            // `now` predates `last_used` (clock skew): treat as fresh.
            Err(_) => false,
        }
    }

    /// Whether `path` falls under this root's scope. A [`RootKind::SingleFile`]
    /// root only owns its exact path; a [`RootKind::Directory`] root owns the
    /// path itself and any descendant.
    fn owns(&self, path: &Path) -> bool {
        match self.kind {
            RootKind::SingleFile => self.path == path,
            RootKind::Directory => path == self.path || path.starts_with(&self.path),
        }
    }
}

/// Errors the registry can return. The integrator maps these onto HTTP / CLI
/// responses; none of them ever panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    /// A path that should have been absolute was relative.
    NotAbsolute(PathBuf),
    /// The target is on the sensitive-path denylist and cannot be a recursive
    /// root (`~/.ssh`, `/etc`, `$HOME`, …). Carries the offending path.
    SensitivePath(PathBuf),
    /// The persisted registry file was malformed at the given (1-based) line.
    Corrupt { line: usize, reason: String },
}

impl std::fmt::Display for RootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootError::NotAbsolute(p) => write!(f, "path is not absolute: {}", p.display()),
            RootError::SensitivePath(p) => {
                write!(f, "refusing sensitive path as a recursive root: {}", p.display())
            }
            RootError::Corrupt { line, reason } => {
                write!(f, "corrupt roots file at line {line}: {reason}")
            }
        }
    }
}

impl std::error::Error for RootError {}

/// The persisted set of allowed roots, plus the injected `$HOME` and state-dir
/// it reasons about. Construct with [`Roots::new`]; mutate via
/// [`Roots::register_for`] / [`Roots::register_root`]; query the active set for
/// confinement via [`Roots::union`].
#[derive(Debug, Clone)]
pub struct Roots {
    /// Injected `$HOME` — the recursion-stop boundary and a denylisted root.
    home: PathBuf,
    /// Injected state-dir; [`Roots::save`]/[`Roots::load`] use `roots` under it.
    state_dir: PathBuf,
    /// Active roots, keyed by their normalized path so dedupe is free and the
    /// persisted ordering is stable.
    roots: BTreeMap<PathBuf, Root>,
}

impl Roots {
    /// Create an empty registry rooted at the injected `home`. The state-dir
    /// defaults to `home/.local/state/md-preview` (per the design doc); use
    /// [`Roots::with_state_dir`] to inject a different one (the tests do).
    ///
    /// `home` should be absolute; if it is relative it is still stored as-is,
    /// but path comparisons will simply never match it.
    pub fn new(home: impl Into<PathBuf>) -> Roots {
        let home = home.into();
        let state_dir = home.join(".local").join("state").join("md-preview");
        Roots {
            home,
            state_dir,
            roots: BTreeMap::new(),
        }
    }

    /// Override the state directory (where [`Roots::save`]/[`Roots::load`] read
    /// and write the `roots` file). Used to keep persistence tests hermetic.
    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Roots {
        self.state_dir = state_dir.into();
        self
    }

    /// The injected `$HOME`.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The full path of the persisted registry file.
    pub fn state_file(&self) -> PathBuf {
        self.state_dir.join("roots")
    }

    /// The set of currently-active roots (post-GC of expired entries is *not*
    /// done here — call [`Roots::gc`] for that). This is the set the
    /// confinement funnel fans out over: a path is in-workspace iff it is owned
    /// by some root in this set. Ordering is stable (by path).
    pub fn union(&self) -> Vec<&Root> {
        self.roots.values().collect()
    }

    /// Number of registered roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the registry holds no roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Is `path` a **sensitive** target that must never become a recursive
    /// root (and that the confinement funnel must refuse outright)? Denylist:
    /// `$HOME` itself, any path under `/etc`, and the home-relative
    /// credential/secret stores below. The home-relative entries are computed
    /// from the *injected* `home`, so this stays deterministic.
    ///
    /// Home-relative denylist (follow-up F2 widened this set):
    ///   * `~/.ssh`, `~/.gnupg`, `~/.aws` — key material / cloud creds;
    ///   * `~/.config` — broad app-config tree (browser profiles, tokens, …);
    ///   * `~/.netrc` — plaintext login credentials;
    ///   * `~/.kube`, `~/.docker` — cluster/registry credentials & contexts;
    ///   * `~/.local/share/keyrings` — the secret-service keyring store.
    ///
    /// A trailing component is matched both exactly and as a path prefix, so a
    /// file (`~/.netrc`) and a directory subtree (`~/.ssh/...`) are both covered.
    ///
    /// INTEGRATOR: this MUST be consulted on the empty-registry / single-file
    /// fallback path too (audit/02-security.md MED-4) — never skip it just
    /// because [`Roots::union`] is empty.
    pub fn is_sensitive(&self, path: impl AsRef<Path>) -> bool {
        let path = normalize(path.as_ref());

        // $HOME itself as a recursive root is denied (a loose home file still
        // gets single-file fallback elsewhere; this guards *recursive* scope).
        if path == self.home {
            return true;
        }

        // Home-relative sensitive dirs/files and anything beneath them. Each
        // entry is a path relative to the injected $HOME; `.local/share/keyrings`
        // is multi-component (join handles the separator).
        for rel in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".config",
            ".netrc",
            ".kube",
            ".docker",
            ".local/share/keyrings",
        ] {
            let sensitive = self.home.join(rel);
            if path == sensitive || path.starts_with(&sensitive) {
                return true;
            }
        }

        // System config tree.
        let etc = PathBuf::from("/etc");
        if path == etc || path.starts_with(&etc) {
            return true;
        }

        false
    }

    /// Walk `file`'s ancestors looking for a [`ROOT_MARKERS`] entry, **stopping
    /// before `$HOME`** — `$HOME` and any ancestor at-or-above it is never
    /// considered, so a `~/.git` cannot turn all of home into a root. The
    /// marker existence check is delegated to `exists` so callers inject a
    /// deterministic filesystem view in tests (in production, pass a closure
    /// over [`Path::exists`]).
    ///
    /// Returns the project-root directory, or `None` when no marker is found
    /// before the `$HOME` boundary (→ caller uses single-file fallback).
    pub fn detect_project_root(
        &self,
        file: impl AsRef<Path>,
        exists: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        let file = normalize(file.as_ref());
        // Search from the directory containing the file (a file's project root
        // is found among its ancestor directories). `ancestors()` yields the
        // start dir, its parent, … up to the filesystem root.
        let start = file.parent().map(Path::to_path_buf).unwrap_or(file);

        for dir in start.ancestors() {
            // Stop *before* $HOME: the home dir and anything above it can never
            // be a project root.
            if dir == self.home || self.home.starts_with(dir) {
                // `self.home.starts_with(dir)` is true for $HOME's ancestors
                // (e.g. `/home`, `/`), so we bail at the boundary.
                break;
            }
            for marker in ROOT_MARKERS {
                if exists(&dir.join(marker)) {
                    return Some(dir.to_path_buf());
                }
            }
        }
        None
    }

    /// Resolve a freshly-opened `file` into the [`Root`] that should serve it,
    /// without mutating the registry. Detects the project root via
    /// [`Roots::detect_project_root`]; if none is found, or the detected root
    /// is [`Roots::is_sensitive`], falls back to a [`RootKind::SingleFile`]
    /// scope on the file itself. `now` stamps `last_used`.
    ///
    /// This is the pure decision used by [`Roots::register_for_at`]; expose it
    /// so the funnel can preview the scope a path would get.
    pub fn resolve(
        &self,
        file: impl AsRef<Path>,
        now: SystemTime,
        exists: impl Fn(&Path) -> bool,
    ) -> Root {
        let file = normalize(file.as_ref());
        match self.detect_project_root(&file, exists) {
            // A real project root, but only if it isn't sensitive.
            Some(root) if !self.is_sensitive(&root) => Root {
                kind: RootKind::Directory,
                path: root,
                last_used: now,
            },
            // No marker, or a sensitive project root → single-file fallback.
            _ => Root {
                kind: RootKind::SingleFile,
                path: file,
                last_used: now,
            },
        }
    }

    /// Register the root that should serve `file`, using real filesystem
    /// existence checks and the system clock's `now`. This is the production
    /// convenience wrapper over [`Roots::register_for_at`].
    ///
    /// Returns the registered [`Root`] (a clone). A single-file fallback can
    /// never fail; a directory root is only rejected if sensitive (which
    /// [`Roots::resolve`] already downgrades, so this returns `Ok`).
    pub fn register_for(&mut self, file: impl AsRef<Path>) -> Result<Root, RootError> {
        let now = SystemTime::now();
        self.register_for_at(file, now, |p| p.exists())
    }

    /// Register the root for `file` with an injected clock and filesystem view
    /// (the deterministic core of [`Roots::register_for`]). Resolves the scope
    /// via [`Roots::resolve`], then folds it into the registry with
    /// dedupe/collapse semantics ([`Roots::register_resolved`]).
    pub fn register_for_at(
        &mut self,
        file: impl AsRef<Path>,
        now: SystemTime,
        exists: impl Fn(&Path) -> bool,
    ) -> Result<Root, RootError> {
        let root = self.resolve(file, now, exists);
        Ok(self.register_resolved(root))
    }

    /// Register an explicit recursive directory `root` (the `md --root <dir>`
    /// override). Refuses [`Roots::is_sensitive`] targets with
    /// [`RootError::SensitivePath`] and requires an absolute path. `now` stamps
    /// `last_used`.
    pub fn register_root(
        &mut self,
        root: impl AsRef<Path>,
        now: SystemTime,
    ) -> Result<Root, RootError> {
        let path = normalize(root.as_ref());
        if !path.is_absolute() {
            return Err(RootError::NotAbsolute(path));
        }
        if self.is_sensitive(&path) {
            return Err(RootError::SensitivePath(path));
        }
        Ok(self.register_resolved(Root {
            kind: RootKind::Directory,
            path,
            last_used: now,
        }))
    }

    /// Fold a resolved [`Root`] into the registry with **normalize + dedupe +
    /// collapse** semantics:
    /// - A nested directory root collapses into an existing parent directory
    ///   root (the parent's TTL renews; the child is dropped).
    /// - An existing root at the same path renews its `last_used` (and upgrades
    ///   a single-file scope to directory if the new one is recursive).
    /// - A directory root absorbs (removes) any existing roots strictly beneath
    ///   it, and any single-file root for a path it now covers.
    ///
    /// Returns the effective root that owns the requested path afterwards.
    fn register_resolved(&mut self, incoming: Root) -> Root {
        // 1. If an existing *directory* root already covers this path, just
        //    renew it and return it — the new (narrower or equal) scope
        //    collapses into the parent.
        let covering_parent = self
            .roots
            .values()
            .filter(|r| r.kind == RootKind::Directory && r.owns(&incoming.path))
            .map(|r| r.path.clone())
            // Deepest covering parent wins (most specific).
            .max_by_key(|p| p.components().count())
            .filter(|parent| *parent != incoming.path);
        if let Some(parent) = covering_parent
            && let Some(r) = self.roots.get_mut(&parent)
        {
            r.last_used = incoming.last_used;
            return r.clone();
        }

        // 2. If this is a directory root, absorb everything strictly beneath it.
        if incoming.kind == RootKind::Directory {
            let absorbed: Vec<PathBuf> = self
                .roots
                .keys()
                .filter(|p| **p != incoming.path && p.starts_with(&incoming.path))
                .cloned()
                .collect();
            for p in absorbed {
                self.roots.remove(&p);
            }
        }

        // 3. Insert or update at the exact path. An incoming directory scope
        //    upgrades an existing single-file entry; a single-file incoming
        //    never downgrades an existing directory entry.
        match self.roots.get_mut(&incoming.path) {
            Some(existing) => {
                existing.last_used = incoming.last_used;
                if incoming.kind == RootKind::Directory {
                    existing.kind = RootKind::Directory;
                }
                existing.clone()
            }
            None => {
                self.roots.insert(incoming.path.clone(), incoming.clone());
                incoming
            }
        }
    }

    /// Find the registered root that owns `path` (renewing its sliding TTL to
    /// `now`), or `None` if no active root covers it. The deepest (most
    /// specific) directory root wins; a single-file root only matches its exact
    /// path.
    ///
    /// This is the access path: it renews the TTL, so a root in daily use is
    /// never GC'd. Returns a clone of the owning root.
    pub fn owning_root(&mut self, path: impl AsRef<Path>, now: SystemTime) -> Option<Root> {
        let path = normalize(path.as_ref());
        let owner = self
            .roots
            .values()
            .filter(|r| r.owns(&path))
            .map(|r| r.path.clone())
            // Most specific (longest) owning root wins.
            .max_by_key(|p| p.components().count())?;
        let root = self.roots.get_mut(&owner)?;
        root.last_used = now;
        Some(root.clone())
    }

    /// Garbage-collect roots whose 30-day sliding TTL has lapsed as of `now`.
    /// Returns the number removed. A broken link after GC is recovered simply
    /// by re-running `md`, which re-registers (per ADR-0005).
    pub fn gc(&mut self, now: SystemTime) -> usize {
        let before = self.roots.len();
        self.roots.retain(|_, r| !r.is_expired(now));
        before - self.roots.len()
    }

    /// Serialize the registry to its plain-text on-disk form (one root per
    /// line: `<kind-token>\t<unix-secs>\t<path>`). Pure: returns the bytes; the
    /// caller (or [`Roots::save`]) does the I/O.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for root in self.roots.values() {
            let secs = root
                .last_used
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                // A pre-epoch instant (only via a hostile clock) clamps to 0
                // rather than panicking.
                .unwrap_or(0);
            // Paths with a literal newline can't round-trip a line-based
            // format; skip them (they would never canonicalize on Linux either).
            if root.path.to_string_lossy().contains('\n') {
                continue;
            }
            out.push_str(root.kind.as_token());
            out.push('\t');
            out.push_str(&secs.to_string());
            out.push('\t');
            out.push_str(&root.path.to_string_lossy());
            out.push('\n');
        }
        out
    }

    /// Parse the plain-text form produced by [`Roots::serialize`] into a fresh
    /// registry (sharing this registry's `home`/`state_dir`). Pure counterpart
    /// to [`Roots::load`]. Blank lines are ignored; a malformed line is a
    /// [`RootError::Corrupt`].
    pub fn deserialize(&self, text: &str) -> Result<Roots, RootError> {
        let mut roots = BTreeMap::new();
        for (idx, line) in text.lines().enumerate() {
            let line_no = idx + 1;
            if line.trim().is_empty() {
                continue;
            }
            // splitn(3): kind, secs, then the rest is the path (tabs are not
            // valid in our normalized paths beyond these two separators).
            let mut parts = line.splitn(3, '\t');
            let kind_tok = parts.next().unwrap_or("");
            let secs_tok = parts.next();
            let path_tok = parts.next();
            let (kind, secs_tok, path_tok) = match (RootKind::from_token(kind_tok), secs_tok, path_tok)
            {
                (Some(k), Some(s), Some(p)) => (k, s, p),
                _ => {
                    return Err(RootError::Corrupt {
                        line: line_no,
                        reason: "expected `<kind>\\t<unix-secs>\\t<path>`".into(),
                    });
                }
            };
            let secs: u64 = secs_tok.parse().map_err(|_| RootError::Corrupt {
                line: line_no,
                reason: format!("invalid timestamp: {secs_tok:?}"),
            })?;
            if path_tok.is_empty() {
                return Err(RootError::Corrupt {
                    line: line_no,
                    reason: "empty path".into(),
                });
            }
            let path = normalize(Path::new(path_tok));
            let last_used = UNIX_EPOCH + Duration::from_secs(secs);
            roots.insert(
                path.clone(),
                Root {
                    kind,
                    path,
                    last_used,
                },
            );
        }
        Ok(Roots {
            home: self.home.clone(),
            state_dir: self.state_dir.clone(),
            roots,
        })
    }

    /// Persist the registry to [`Roots::state_file`], creating the state dir if
    /// needed. Plain text (access is gated by auth, not path obscurity).
    pub fn save(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        std::fs::write(self.state_file(), self.serialize())
    }

    /// Load the registry from [`Roots::state_file`], keeping this registry's
    /// injected `home`/`state_dir`. A missing file yields an empty registry (a
    /// fresh daemon). A present-but-corrupt file surfaces an
    /// [`std::io::Error`] wrapping the [`RootError`].
    pub fn load(&self) -> std::io::Result<Roots> {
        let path = self.state_file();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        self.deserialize(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Lexically normalize a path: collapse `.` and `..` components without
/// touching the filesystem (no symlink resolution — that happens later in the
/// confinement funnel, on canonical paths). Keeps comparisons in this module
/// purely textual and deterministic.
///
/// A leading `..` (path that escapes its own root) is preserved as-is, since
/// there is no parent to pop; the funnel rejects such escapes.
fn normalize(path: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // Can't pop a root/prefix or another `..`: keep it.
                _ => out.push(comp),
            },
            other => out.push(other),
        }
    }
    let mut buf = PathBuf::new();
    for comp in out {
        buf.push(comp.as_os_str());
    }
    if buf.as_os_str().is_empty() {
        buf.push(".");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant for deterministic TTL math (well after the epoch).
    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn home() -> PathBuf {
        PathBuf::from("/home/alice")
    }

    /// Registry with an injected home and a hermetic state dir.
    fn reg(state_dir: &Path) -> Roots {
        Roots::new(home()).with_state_dir(state_dir)
    }

    /// A filesystem view where the given marker paths "exist".
    fn fs_with(markers: &'static [&'static str]) -> impl Fn(&Path) -> bool {
        move |p: &Path| markers.iter().any(|m| p == Path::new(m))
    }

    #[test]
    fn normalize_collapses_dot_and_dotdot() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/a/b/..")), PathBuf::from("/a"));
        // No parent to pop: leading `..` is preserved.
        assert_eq!(normalize(Path::new("../x")), PathBuf::from("../x"));
        // Empty normalizes to ".".
        assert_eq!(normalize(Path::new("")), PathBuf::from("."));
    }

    #[test]
    fn detect_stops_before_home_even_with_git_in_home() {
        let r = Roots::new(home());
        // `~/.git` exists, but the walk must stop before $HOME and find nothing.
        let exists = fs_with(&["/home/alice/.git"]);
        assert_eq!(r.detect_project_root("/home/alice/notes.md", &exists), None);
    }

    #[test]
    fn detect_finds_nearest_marker() {
        let r = Roots::new(home());
        let exists = fs_with(&["/home/alice/proj/.git"]);
        assert_eq!(
            r.detect_project_root("/home/alice/proj/src/a.md", &exists),
            Some(PathBuf::from("/home/alice/proj"))
        );
    }

    #[test]
    fn detect_honors_marker_priority_via_first_hit_walking_up() {
        let r = Roots::new(home());
        // A Cargo.toml deeper, a .git shallower: the deeper dir is found first
        // (nearest ancestor wins, regardless of which marker matched).
        let exists = fs_with(&["/home/alice/proj/.git", "/home/alice/proj/sub/Cargo.toml"]);
        assert_eq!(
            r.detect_project_root("/home/alice/proj/sub/src/a.md", &exists),
            Some(PathBuf::from("/home/alice/proj/sub"))
        );
    }

    #[test]
    fn detect_md_preview_root_marker_works() {
        let r = Roots::new(home());
        let exists = fs_with(&["/home/alice/docs/.md-preview-root"]);
        assert_eq!(
            r.detect_project_root("/home/alice/docs/a.md", &exists),
            Some(PathBuf::from("/home/alice/docs"))
        );
    }

    #[test]
    fn is_sensitive_covers_denylist() {
        let r = Roots::new(home());
        assert!(r.is_sensitive("/home/alice")); // $HOME itself
        assert!(r.is_sensitive("/home/alice/.ssh"));
        assert!(r.is_sensitive("/home/alice/.ssh/id_ed25519"));
        assert!(r.is_sensitive("/home/alice/.gnupg"));
        assert!(r.is_sensitive("/home/alice/.aws/credentials"));
        assert!(r.is_sensitive("/etc"));
        assert!(r.is_sensitive("/etc/passwd"));
        // Ordinary project paths are fine.
        assert!(!r.is_sensitive("/home/alice/proj"));
    }

    #[test]
    fn is_sensitive_covers_widened_denylist() {
        // Follow-up F2: each newly-denylisted home-relative store is refused,
        // both as the exact path and as a path beneath it.
        let r = Roots::new(home());

        // ~/.config (broad app-config tree)
        assert!(r.is_sensitive("/home/alice/.config"));
        assert!(r.is_sensitive("/home/alice/.config/gh/hosts.yml"));

        // ~/.netrc (a plaintext-credentials FILE)
        assert!(r.is_sensitive("/home/alice/.netrc"));

        // ~/.kube (cluster credentials)
        assert!(r.is_sensitive("/home/alice/.kube"));
        assert!(r.is_sensitive("/home/alice/.kube/config"));

        // ~/.docker (registry credentials)
        assert!(r.is_sensitive("/home/alice/.docker"));
        assert!(r.is_sensitive("/home/alice/.docker/config.json"));

        // ~/.local/share/keyrings (secret-service store)
        assert!(r.is_sensitive("/home/alice/.local/share/keyrings"));
        assert!(r.is_sensitive("/home/alice/.local/share/keyrings/login.keyring"));

        // Sibling paths that merely share a prefix segment are NOT swept in:
        // .local itself (and other .local/share subtrees) stay servable.
        assert!(!r.is_sensitive("/home/alice/.local"));
        assert!(!r.is_sensitive("/home/alice/.local/share/app"));
        // A path whose name only starts with a denylisted token is not matched
        // (component-wise starts_with, not a string prefix).
        assert!(!r.is_sensitive("/home/alice/.configuration"));
        assert!(!r.is_sensitive("/home/alice/.netrc-backup"));
    }

    #[test]
    fn resolve_falls_back_to_single_file_when_no_marker() {
        let r = Roots::new(home());
        let exists = fs_with(&[]);
        let root = r.resolve("/home/alice/loose.md", t0(), &exists);
        assert_eq!(root.kind, RootKind::SingleFile);
        assert_eq!(root.path, PathBuf::from("/home/alice/loose.md"));
    }

    #[test]
    fn resolve_downgrades_sensitive_project_root_to_single_file() {
        // Track A / MED-4: a dotfiles repo at $HOME-ish sensitive path must NOT
        // become a recursive root. Here a `.git` sits in ~/.ssh (contrived) —
        // detection finds it but resolve downgrades to single-file.
        let r = Roots::new(home());
        let exists = fs_with(&["/home/alice/.ssh/.git"]);
        let root = r.resolve("/home/alice/.ssh/keys.md", t0(), &exists);
        assert_eq!(root.kind, RootKind::SingleFile, "sensitive root must downgrade");
        assert_eq!(root.path, PathBuf::from("/home/alice/.ssh/keys.md"));
    }

    #[test]
    fn register_for_creates_directory_root_at_project() {
        let mut r = Roots::new(home());
        let exists = fs_with(&["/home/alice/proj/.git"]);
        let root = r
            .register_for_at("/home/alice/proj/src/a.md", t0(), &exists)
            .unwrap();
        assert_eq!(root.kind, RootKind::Directory);
        assert_eq!(root.path, PathBuf::from("/home/alice/proj"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_root_refuses_sensitive_targets() {
        let mut r = Roots::new(home());
        assert_eq!(
            r.register_root("/home/alice/.ssh", t0()),
            Err(RootError::SensitivePath(PathBuf::from("/home/alice/.ssh")))
        );
        assert_eq!(
            r.register_root("/home/alice", t0()),
            Err(RootError::SensitivePath(home()))
        );
        assert_eq!(
            r.register_root("/etc", t0()),
            Err(RootError::SensitivePath(PathBuf::from("/etc")))
        );
        assert!(r.is_empty(), "no sensitive root may be registered");
    }

    #[test]
    fn register_root_refuses_relative_path() {
        let mut r = Roots::new(home());
        assert_eq!(
            r.register_root("proj", t0()),
            Err(RootError::NotAbsolute(PathBuf::from("proj")))
        );
    }

    #[test]
    fn nested_root_collapses_into_parent() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/proj", t0()).unwrap();
        // Registering a subdir collapses into the parent; still one root.
        let got = r.register_root("/home/alice/proj/sub", t0()).unwrap();
        assert_eq!(got.path, PathBuf::from("/home/alice/proj"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn parent_root_absorbs_existing_children() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/proj/a", t0()).unwrap();
        r.register_root("/home/alice/proj/b", t0()).unwrap();
        assert_eq!(r.len(), 2);
        // Registering the parent absorbs both children.
        r.register_root("/home/alice/proj", t0()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.union()[0].path, PathBuf::from("/home/alice/proj"));
    }

    #[test]
    fn directory_root_upgrades_single_file_entry() {
        let mut r = Roots::new(home());
        let exists_none = fs_with(&[]);
        // First a loose file → single-file scope.
        r.register_for_at("/home/alice/proj/a.md", t0(), &exists_none)
            .unwrap();
        assert_eq!(r.union()[0].kind, RootKind::SingleFile);
        // Then a project root at the file's own path upgrades it to directory.
        r.register_root("/home/alice/proj/a.md", t0()).unwrap();
        assert_eq!(r.union()[0].kind, RootKind::Directory);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn owning_root_picks_most_specific_and_renews_ttl() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/outer", t0()).unwrap();
        r.register_root("/home/alice/outer/inner", t0()).unwrap();
        // The parent-absorb rule keeps only `/outer`; inner collapsed in. So the
        // owner of an inner path is `/outer`.
        let later = t0() + Duration::from_secs(60);
        let owner = r.owning_root("/home/alice/outer/inner/x.md", later).unwrap();
        assert_eq!(owner.path, PathBuf::from("/home/alice/outer"));
        assert_eq!(owner.last_used, later, "access renews the sliding TTL");
    }

    #[test]
    fn owning_root_single_file_matches_only_exact_path() {
        let mut r = Roots::new(home());
        let exists_none = fs_with(&[]);
        r.register_for_at("/home/alice/loose.md", t0(), &exists_none)
            .unwrap();
        assert!(r.owning_root("/home/alice/loose.md", t0()).is_some());
        // A sibling under the same dir is NOT covered by a single-file root.
        assert!(r.owning_root("/home/alice/other.md", t0()).is_none());
    }

    #[test]
    fn owning_root_returns_none_when_unregistered() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/proj", t0()).unwrap();
        assert!(r.owning_root("/home/alice/elsewhere/x.md", t0()).is_none());
    }

    #[test]
    fn gc_drops_only_expired_roots() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/fresh", t0()).unwrap();
        // Stale root: registered far in the past.
        let long_ago = t0() - (ROOT_TTL + Duration::from_secs(60));
        r.register_root("/home/alice/stale", long_ago).unwrap();
        assert_eq!(r.len(), 2);
        let removed = r.gc(t0());
        assert_eq!(removed, 1);
        assert_eq!(r.len(), 1);
        assert_eq!(r.union()[0].path, PathBuf::from("/home/alice/fresh"));
    }

    #[test]
    fn gc_keeps_a_root_accessed_within_ttl() {
        let mut r = Roots::new(home());
        let long_ago = t0() - (ROOT_TTL + Duration::from_secs(60));
        r.register_root("/home/alice/proj", long_ago).unwrap();
        // Access renews; now it survives GC.
        r.owning_root("/home/alice/proj/x.md", t0()).unwrap();
        assert_eq!(r.gc(t0()), 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn serialize_deserialize_roundtrips() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/proj", t0()).unwrap();
        let exists_none = fs_with(&[]);
        r.register_for_at("/home/alice/loose.md", t0(), &exists_none)
            .unwrap();
        let text = r.serialize();
        let r2 = r.deserialize(&text).unwrap();
        assert_eq!(r2.len(), 2);
        // Both kinds and TTL stamps survive (second precision).
        let mut kinds: Vec<_> = r2.union().iter().map(|x| x.kind).collect();
        kinds.sort_by_key(|k| k.as_token());
        assert_eq!(kinds, vec![RootKind::Directory, RootKind::SingleFile]);
        for root in r2.union() {
            assert_eq!(root.last_used, t0());
        }
    }

    #[test]
    fn deserialize_rejects_corrupt_lines() {
        let r = Roots::new(home());
        assert!(matches!(
            r.deserialize("garbage-no-tabs"),
            Err(RootError::Corrupt { line: 1, .. })
        ));
        assert!(matches!(
            r.deserialize("dir\tnotanumber\t/x"),
            Err(RootError::Corrupt { line: 1, .. })
        ));
        assert!(matches!(
            r.deserialize("dir\t100\t"),
            Err(RootError::Corrupt { line: 1, .. })
        ));
        // Blank lines are skipped, valid lines parse.
        assert_eq!(r.deserialize("\n\ndir\t100\t/home/alice/p\n").unwrap().len(), 1);
    }

    #[test]
    fn save_and_load_through_disk() {
        let dir = std::env::temp_dir().join(format!("md-preview-roots-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut r = reg(&dir);
        r.register_root("/home/alice/proj", t0()).unwrap();
        r.save().unwrap();
        // A fresh registry with the same injected home/state-dir loads it back.
        let loaded = reg(&dir).load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.union()[0].path, PathBuf::from("/home/alice/proj"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_yields_empty_registry() {
        let dir = std::env::temp_dir().join(format!("md-preview-roots-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let loaded = reg(&dir).load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn union_is_the_active_set_for_confinement() {
        let mut r = Roots::new(home());
        r.register_root("/home/alice/p1", t0()).unwrap();
        r.register_root("/home/alice/p2", t0()).unwrap();
        let paths: Vec<_> = r.union().iter().map(|x| x.path.clone()).collect();
        assert!(paths.contains(&PathBuf::from("/home/alice/p1")));
        assert!(paths.contains(&PathBuf::from("/home/alice/p2")));
        assert_eq!(paths.len(), 2);
    }
}
