//! bifrauthd — the root-owned verifier daemon.
//!
//! The pieces are in the library ([`bifrauthd`]): the verifier core ([`bifrauthd::Verifier`]), the
//! per-connection state machine ([`bifrauthd::session`]), the accept loop ([`bifrauthd::serve`]), and the
//! systemd socket-activation intake ([`bifrauthd::systemd`]).
//!
//! Final wiring is intentionally not enabled here yet because it depends on two decisions still open:
//! - **Transport**: the real verifier↔transport-helper socket is a separate task (ipc-design §1, "B").
//!   Until then there is no production [`bifrauth_ipc::Transport`] to inject.
//! - **UserResolver**: resolving `username → uid` needs an NSS/`getpwnam` path, i.e. a new dependency
//!   (`libc`/`nix`), which is a library-policy decision to confirm with the user before adding.
//!
//! Once both land, `main` will: acquire the validated listener via
//! [`bifrauthd::systemd::listener_from_env`], load the Ed25519 seed into a [`bifrauthd::Verifier`], build
//! the [`bifrauthd::session::Policy`] from daemon config, and call [`bifrauthd::serve::serve`].

const SOCKET_PATH: &[u8] = b"/run/bifrauthd/pam.sock";

fn main() {
    // Validate the socket-activation FD early so misconfiguration fails loudly, even before the rest of
    // the wiring exists.
    match bifrauthd::systemd::listener_from_env(SOCKET_PATH) {
        Ok(_listener) => {
            eprintln!(
                "bifrauthd: received a valid activation socket, but the transport (task B) and the \
                 username->uid resolver dependency are not yet wired; refusing to serve."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "bifrauthd: no valid socket-activation FD ({e:?}); launch this daemon via bifrauthd.socket."
            );
            std::process::exit(1);
        }
    }
}
