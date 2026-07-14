//! Production [`UserResolver`] backed by the system account database via NSS (plan §4.9).
//!
//! Uses `uzers::get_user_by_name` (reentrant `getpwnam_r` under the hood) on **every** call — no
//! `UsersCache`, so a changed account identity is reflected immediately. Initial scope is local personal
//! use: `uzers` collapses "no such user" and a transient NSS error into `None`, and both fail closed
//! (the caller issues no challenge and PAM falls back to the password). This affects
//! availability/observability, not auth-success safety.
//!
//! The account record's own name (`pw_name`) is the canonical identity. It is an `OsStr`; we require
//! **strict UTF-8** (no `to_string_lossy`, whose replacement characters could alias-collide two distinct
//! names). A non-UTF-8 canonical name resolves to `None` (fail closed). Any further text-policy checks
//! (length/NFC/control/bidi/unassigned) happen when the challenge is built, so a policy-violating name
//! fails the issue and closes the connection.

use crate::session::{ResolvedIdentity, UserResolver};

/// Resolves usernames through NSS (`getpwnam_r`). Deployment assumes glibc dynamic linking so NSS
/// backends (files/systemd/sss) load; NSS/SSSD timeouts are a deployment requirement (a hung backend is
/// not interruptible by the connection's boot-time deadline).
#[derive(Debug, Default, Clone, Copy)]
pub struct UzersResolver;

impl UserResolver for UzersResolver {
    fn resolve(&self, username: &str) -> Option<ResolvedIdentity> {
        // Free function, not a cached snapshot (plan §4.9). A username containing a NUL cannot form a
        // C string and yields None here; the IPC text policy already rejects control characters upstream.
        let user = uzers::get_user_by_name(username)?;
        // pw_name is an OsStr — require exact UTF-8; a lossy conversion could merge distinct names.
        let canonical_username = user.name().to_str()?.to_string();
        Some(ResolvedIdentity {
            uid: user.uid(),
            canonical_username,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolving a name that cannot exist must be None (fail closed). This does not depend on NSS content.
    #[test]
    fn a_nonexistent_user_resolves_to_none() {
        let r = UzersResolver;
        assert_eq!(r.resolve("bifrauth-definitely-no-such-user-1a2b3c4d"), None);
        // A NUL-bearing name cannot form a C string; None (defensive — IPC policy rejects it earlier).
        assert_eq!(r.resolve("na\0me"), None);
    }

    /// If we can identify the current user via NSS, the resolved uid must match this process's uid and the
    /// canonical name must be non-empty. Skips where the environment does not expose a resolvable name.
    #[test]
    fn resolves_the_current_user_to_its_uid() {
        let Ok(name) = std::env::var("USER") else {
            eprintln!("skipping: $USER not set");
            return;
        };
        let r = UzersResolver;
        match r.resolve(&name) {
            Some(id) => {
                let self_uid = rustix::process::getuid().as_raw();
                assert_eq!(id.uid, self_uid);
                assert!(!id.canonical_username.is_empty());
            }
            None => eprintln!("skipping: '{name}' does not resolve via NSS in this environment"),
        }
    }
}
