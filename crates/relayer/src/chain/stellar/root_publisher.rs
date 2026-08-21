//! Keeping a recent IBC state root on chain.
//!
//! # The problem
//!
//! `ibc-router` publishes its Merkle root as a contract event, but only when a
//! provable write happens — a packet sent, received, acknowledged. On an idle
//! link nothing writes, so no ledger carries a root.
//!
//! That matters because the light client binds a state root from the ledger it
//! is updating to. Advance the client to a recent height on a quiet link and
//! the header proves the ledger is real while carrying no root, so every packet
//! proof against that height fails with `StateRootNotBound`. The bridge is
//! live, correct, and unable to verify anything.
//!
//! ```text
//! ledger 1000   packet sent    → root published
//! ledger 1001                    (nothing happens)
//!   ...
//! ledger 5000   client updates → no root in this ledger → proofs fail
//! ```
//!
//! # The fix, and why it lives here
//!
//! `commit_root()` republishes the unchanged root, putting one in a fresh
//! ledger. It needs a signed transaction, and the relayer is the only component
//! that holds a key — the gateway has none by design, and the api only ever
//! builds unsigned transactions. So the gateway prepares and this signs.
//!
//! # Why the signer is not a privilege
//!
//! `commit_root()` takes no arguments, requires no authorisation, moves no
//! funds, and changes no state — it re-announces a value already public and
//! already on chain. Anyone may call it. The key here is a fee payer and
//! nothing more, which is what makes running this from the relayer's existing
//! keyring acceptable rather than a new trust assumption.

/// How stale a root may get before it is worth paying to republish.
///
/// Every publish costs a fee, so this trades money against how long a quiet
/// link takes to become provable again. Roughly an hour at 5-second ledgers.
pub const DEFAULT_MAX_ROOT_AGE_LEDGERS: u32 = 720;

/// What to do about the root, given how things stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootAction {
    /// A recent enough root exists; spending a fee would be waste.
    Skip,
    /// No root within the staleness bound — republish so the light client has
    /// something fresh to bind.
    Publish,
}

/// Decide whether to republish.
///
/// Split out from the transaction machinery because the decision is the part
/// worth testing: it is where fees get wasted or a link silently stops being
/// provable.
///
/// `newest_root_ledger` is the most recent ledger known to carry a router root,
/// or `None` when none was found in the window searched.
pub fn root_action(
    latest_ledger: u32,
    newest_root_ledger: Option<u32>,
    max_age_ledgers: u32,
) -> RootAction {
    match newest_root_ledger {
        // Nothing found in the window, so whatever root exists is at least that
        // old. Publishing is the only way to find out otherwise.
        None => RootAction::Publish,
        Some(seen) => {
            // A root from a ledger ahead of `latest` means our view of the
            // chain tip is stale, not that the root is. Treat it as fresh
            // rather than publishing on top of it.
            let age = latest_ledger.saturating_sub(seen);
            if age > max_age_ledgers {
                RootAction::Publish
            } else {
                RootAction::Skip
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_root_is_left_alone() {
        assert_eq!(root_action(5_000, Some(4_900), 720), RootAction::Skip);
    }

    #[test]
    fn a_stale_root_is_republished() {
        assert_eq!(root_action(5_000, Some(1_000), 720), RootAction::Publish);
    }

    /// The idle-link case this exists for: nothing has written since before the
    /// search window began.
    #[test]
    fn no_root_at_all_is_republished() {
        assert_eq!(root_action(5_000, None, 720), RootAction::Publish);
    }

    #[test]
    fn the_boundary_does_not_publish_a_ledger_early() {
        assert_eq!(root_action(1_720, Some(1_000), 720), RootAction::Skip);
        assert_eq!(root_action(1_721, Some(1_000), 720), RootAction::Publish);
    }

    /// A root newer than our view of the tip means the view is behind. Treating
    /// that as infinitely stale would publish on every tick while catching up.
    #[test]
    fn a_root_ahead_of_our_view_of_the_tip_is_not_stale() {
        assert_eq!(root_action(1_000, Some(1_050), 720), RootAction::Skip);
    }

    /// A zero bound means "always keep one in the newest ledger". Degenerate,
    /// but it must not panic or wrap.
    #[test]
    fn a_zero_bound_publishes_unless_the_root_is_in_this_very_ledger() {
        assert_eq!(root_action(1_000, Some(1_000), 0), RootAction::Skip);
        assert_eq!(root_action(1_001, Some(1_000), 0), RootAction::Publish);
    }
}
