//! `backend` — the OS-specific mechanism half of the confinement funnel.
//!
//! This module separates the **portable policy** (roots registry, denylist,
//! root-union containment, `/outside` classification, [`crate::gate::Confine`]
//! trait) from the **Unix mechanism** (the syscall-level operations that give the
//! funnel its TOCTOU-free and symlink-safe guarantees).
//!
//! ## The seam
//!
//! [`ConfineBackend`] is the internal trait that abstracts the mechanism. It has
//! exactly three operations, each corresponding to one unsafe syscall cluster in
//! the original funnel:
//!
//! | Method | Mechanism | Guarantee |
//! |--------|-----------|-----------|
//! | [`ConfineBackend::open_nofollow`] | `open(2)` + `O_NOFOLLOW` | final component is never a followed symlink |
//! | [`ConfineBackend::stat_fd`] | `fstat(2)` on the held fd | metadata is from the same descriptor we will read |
//! | [`ConfineBackend::atomic_save`] | `openat`/`O_EXCL` temp + `renameat` + `unlinkat` | writes are dirfd-relative; a swapped parent cannot redirect them |
//!
//! The policy side ([`crate::confine`]) wires these three calls in the same
//! order, with the same checks, as the original unified `confine.rs`. No
//! behaviour changes — the seam exists only to make a future `cap-std` or
//! Windows backend slot-in possible without touching the policy logic.
//!
//! ## Current state
//! Only [`UnixBackend`] exists. A macOS or Windows backend would implement
//! [`ConfineBackend`] with equivalent platform-native primitives and live in a
//! separate `cfg`-gated submodule here.
//!
//! ## Internal-only
//! This module is `pub(crate)` — it is not part of the public API. External
//! consumers see only `confine::{confine_read, confine_save, …}` unchanged.

use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io;
use std::path::Path;

/// Internal trait that abstracts the OS-specific mechanism operations.
///
/// Each method corresponds to one discrete mechanism cluster in the funnel.
/// The policy logic in [`crate::confine`] calls these methods after it has
/// already verified containment and sensitivity — the backend does not re-check
/// policy.
///
/// This trait is `pub(crate)`. External consumers cannot implement it, and the
/// only production implementor is [`UnixBackend`].
pub(crate) trait ConfineBackend {
    /// Open an existing regular file at `canonical_path` with `O_NOFOLLOW` (or
    /// an equivalent platform guarantee that the final path component is not a
    /// followed symlink). The path has already been canonicalized by the policy
    /// layer; the backend's job is to open it without following a symlink at the
    /// final step.
    ///
    /// The returned `File` is the held descriptor that callers read from.
    fn open_nofollow(&self, canonical_path: &Path) -> io::Result<File>;

    /// `fstat` the given file descriptor and return its [`Metadata`]. This must
    /// read the metadata from the **same fd** (no second path `stat`) so that
    /// the size cap and permission mode the caller sees describe the exact bytes
    /// in the held descriptor.
    fn stat_fd(&self, file: &File) -> io::Result<Metadata>;

    /// Atomically write `bytes` to `file_name` inside `canonical_dir` using a
    /// temp-file + rename strategy that is dirfd-relative on Unix. `canonical_dir`
    /// is an already-confined, canonicalized directory path; `file_name` is the
    /// bare filename with no directory separator.
    ///
    /// The implementation must:
    /// 1. Open the directory via a dirfd (so subsequent steps are relative to
    ///    the **inode**, not the path string).
    /// 2. Create a sibling temp file relative to that dirfd with `O_CREAT |
    ///    O_EXCL | O_NOFOLLOW` (or equivalent), write + sync the bytes.
    /// 3. Rename the temp to `file_name` relative to the same dirfd (so a
    ///    parent-component symlink swap between confine and the write cannot
    ///    redirect the output).
    /// 4. Unlink the temp on any failure (best-effort, relative to the dirfd).
    fn atomic_save(&self, canonical_dir: &Path, file_name: &OsStr, bytes: &[u8]) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// Unix implementation
// ---------------------------------------------------------------------------

/// The production Unix backend: `open + O_NOFOLLOW`, `fstat`, and
/// `openat`/`renameat`/`unlinkat` all relative to a held dirfd.
///
/// All `unsafe` in this crate is contained in this struct's [`ConfineBackend`]
/// implementation, documented at each call site.
pub(crate) struct UnixBackend;

impl ConfineBackend for UnixBackend {
    fn open_nofollow(&self, canonical_path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(canonical_path)
    }

    fn stat_fd(&self, file: &File) -> io::Result<Metadata> {
        // `File::metadata` issues `fstat(fd)` — not a second path stat.
        file.metadata()
    }

    fn atomic_save(&self, canonical_dir: &Path, file_name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        // Hold the confined parent as a dirfd. `O_DIRECTORY` makes the open
        // fail if it is not a directory; `O_NOFOLLOW` makes it fail if the final
        // component is a symlink. From here on every operation is relative to
        // THIS fd — an intermediate parent swapped to a symlink after this point
        // cannot be re-resolved (no second by-path open).
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(canonical_dir)?;
        let dirfd = dir.as_raw_fd();

        // Build C-string names for the `*at` syscalls.
        let temp_name = temp_sibling_name(file_name);
        let temp_cstr = path_to_cstring(&temp_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "temp file name contains an interior NUL byte",
            )
        })?;
        let target_cstr = path_to_cstring(file_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "save target name contains an interior NUL byte",
            )
        })?;

        // Create the temp via openat, relative to the held dirfd.
        //
        // SAFETY: `dirfd` is borrowed from the live, owned `dir` File for the
        // whole call — valid descriptor; `temp_cstr` is a NUL-terminated C
        // string we own that outlives the call; flags and mode are plain
        // integers passed by value. `openat` reads the path pointer only; we
        // check the returned fd before using it.
        let temp_raw = unsafe {
            libc::openat(
                dirfd,
                temp_cstr.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if temp_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // Take ownership so the fd is closed on every path (incl. early returns).
        //
        // SAFETY: `temp_raw` is a fresh, valid, owned fd returned by `openat`
        // (non-negative checked above); nothing else owns it.
        let temp_file = unsafe { std::fs::File::from_raw_fd(temp_raw) };

        // Write + fsync + commit, cleaning the temp entry on any failure.
        // The commit is renameat relative to the SAME dirfd on both sides.
        let commit = (|| -> io::Result<()> {
            // Re-borrow the owned File for buffered writes; does not duplicate
            // or close the fd.
            let mut w = &temp_file;
            w.write_all(bytes)?;
            w.sync_all()?;
            // SAFETY: both dirfds are the same live, owned `dir` descriptor
            // (valid for the call); `temp_cstr`/`target_cstr` are NUL-terminated
            // C strings we own that outlive the call. `renameat` only reads
            // through the pointers. We check the rc below.
            let rc =
                unsafe { libc::renameat(dirfd, temp_cstr.as_ptr(), dirfd, target_cstr.as_ptr()) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();

        if let Err(e) = commit {
            // Best-effort cleanup of the temp entry via unlinkat on the held
            // dirfd (so cleanup, too, cannot be redirected); ignore its error.
            //
            // SAFETY: `dirfd` is the live, owned `dir` descriptor; `temp_cstr`
            // is an owned NUL-terminated C string outliving the call; `unlinkat`
            // only reads the path. The result is intentionally ignored.
            unsafe {
                libc::unlinkat(dirfd, temp_cstr.as_ptr(), 0);
            }
            return Err(e);
        }

        // `temp_file` and `dir` drop here, closing both fds.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers shared within this module
// ---------------------------------------------------------------------------

/// Convert a path component (single file name, no separators) into a
/// NUL-terminated [`std::ffi::CString`] for the `*at` syscalls. Returns `None`
/// if the bytes contain an interior NUL (impossible for a real path component,
/// but handled rather than panicking).
fn path_to_cstring(name: &OsStr) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).ok()
}

/// Build a sibling temp-file name for an atomic save: `.<name>.<pid>.<n>.tmp`.
///
/// Hidden (leading dot) and process+counter qualified so concurrent saves in
/// the same directory don't collide. `O_EXCL` is the real guard; this just
/// keeps collisions rare.
fn temp_sibling_name(file_name: &OsStr) -> std::ffi::OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut name = std::ffi::OsString::from(".");
    name.push(file_name);
    name.push(format!(".{}.{}.tmp", std::process::id(), n));
    name
}
