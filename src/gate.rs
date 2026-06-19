//! `Confine` — the single root-union fan-out, collapsed into one trait.
//!
//! The confinement *primitive* (`confine::confine_{path,read,save,link}`) is
//! already single-sourced in [`crate::confine`]. What was duplicated across the
//! daemon was the *fan-out*: snapshot the active [`Roots`], collect an owned
//! `Vec<Root>` union, take a `&[&Root]` view, and call the primitive with the
//! registry for the denylist. That dance lived verbatim in
//! `AppState::confine_read/save`, `asset_origin::Confiner`, and `navigate_gate`.
//!
//! [`Confine`] collapses it: an implementor supplies ONE method,
//! [`Confine::confinement_snapshot`], returning a [`ConfineSnapshot`] — the owned
//! union `Vec<Root>` (already TTL-renewed / primary-root-augmented as that site
//! requires) plus the [`Roots`] registry for the denylist consult. The provided
//! [`Confine::confine_read`] / [`Confine::confine_save`] / [`Confine::confine_link`]
//! methods then take the `&[&Root]` view and call the primitive **once**,
//! identically for every site.
//!
//! ## Behavior preservation
//! This changes **no** confinement decision. Each call confines against the same
//! union the old fan-out built, consults the same denylist on the same [`Roots`],
//! and dispatches to the same primitive with the same arguments (incl.
//! [`DEFAULT_MAX_FILE_SIZE`]). The trait only moves *where* the
//! `union → Vec<Root> → &[&Root] → primitive` fan-out is written: from three
//! copies to one. Per-site quirks (TTL renew; the synthetic primary-root the
//! empty-registry asset fallback injects into the union) live in the snapshot
//! step, exactly where they did before — the asset fallback can still place a
//! *sensitive* synthetic root in the union, and the primitive's unconditional
//! `is_sensitive` check (audit MED-4) still rejects it first.

use std::path::Path;

use crate::confine::{self, ConfineError, ConfinedFile, LinkResolution};
use crate::roots::{Root, Roots};
use crate::DEFAULT_MAX_FILE_SIZE;

/// One confinement's fan-out inputs: the owned active-root union and the [`Roots`]
/// registry the primitive consults for the sensitive-path denylist.
///
/// The union is owned (`Vec<Root>`, not `Vec<&Root>`) so the producer can drop
/// the registry lock before the funnel runs — the held fd's reads and any
/// `.await` never happen under the lock. The provided [`Confine`] methods borrow
/// `union` into the `&[&Root]` view the primitive wants.
pub struct ConfineSnapshot {
    /// The active roots to fan out over (the containment set). May be empty (the
    /// primitive then denies containment while still applying the denylist), and
    /// may carry a synthetic site-supplied root (the asset origin's empty-registry
    /// primary-root fallback) — including a sensitive one, which the primitive
    /// rejects via the unconditional denylist before containment.
    pub union: Vec<Root>,
    /// The registry whose `is_sensitive` denylist the primitive consults
    /// unconditionally (audit MED-4), independent of `union`.
    pub registry: Roots,
}

/// The single confinement gate: implement [`Confine::confinement_snapshot`] to
/// supply the fan-out inputs for one access, and get the union view + primitive
/// dispatch for free.
pub trait Confine {
    /// Snapshot the active root union + registry for one confinement, applying
    /// any site-specific pre-step (TTL renew, primary-root fallback) first.
    ///
    /// This is the ONLY method a site implements; the fan-out methods below are
    /// provided. Returning an owned [`ConfineSnapshot`] lets the producer release
    /// the registry lock before the funnel runs — never held across the held-fd
    /// reads or an `.await`.
    fn confinement_snapshot(&self, requested: &Path) -> ConfineSnapshot;

    /// TOCTOU-free read through the funnel: fan out over the snapshot's union and
    /// call [`confine::confine_read`] with [`DEFAULT_MAX_FILE_SIZE`]. Returns the
    /// held fd + its fstat'd metadata (the auth floor is applied by the caller).
    fn confine_read(&self, requested: &Path) -> Result<ConfinedFile, ConfineError> {
        let snap = self.confinement_snapshot(requested);
        let union_refs: Vec<&Root> = snap.union.iter().collect();
        confine::confine_read(requested, &union_refs, &snap.registry, DEFAULT_MAX_FILE_SIZE)
    }

    /// Symlink-safe atomic save through the funnel: fan out over the snapshot's
    /// union and call [`confine::confine_save`] (dirfd + O_NOFOLLOW temp +
    /// renameat).
    fn confine_save(&self, requested: &Path, bytes: &[u8]) -> Result<(), ConfineError> {
        let snap = self.confinement_snapshot(requested);
        let union_refs: Vec<&Root> = snap.union.iter().collect();
        confine::confine_save(requested, &union_refs, &snap.registry, bytes)
    }

    /// Link classification through the funnel: fan out over the snapshot's union
    /// and call [`confine::confine_link`] (in-root → `InRoot`, escape/sensitive →
    /// `Outside`, the `/outside` 403 sentinel input).
    fn confine_link(&self, requested: &Path) -> LinkResolution {
        let snap = self.confinement_snapshot(requested);
        let union_refs: Vec<&Root> = snap.union.iter().collect();
        confine::confine_link(requested, &union_refs, &snap.registry)
    }
}

/// A plain (read-only) [`Roots`] snapshot is itself a [`Confine`] gate: its union
/// is the registry's current `union()`, and it is the denylist registry. This is
/// the *non-mutating* fan-out — no sliding-TTL renew — used by link rewriting and
/// the navigation gate, which classify against a snapshot and never renew a
/// root's TTL. Behavior-identical to the prior `roots.union()` + `confine_link`
/// hand-fan-out at those sites.
impl Confine for Roots {
    fn confinement_snapshot(&self, _requested: &Path) -> ConfineSnapshot {
        ConfineSnapshot {
            union: self.union().into_iter().cloned().collect(),
            registry: self.clone(),
        }
    }
}
