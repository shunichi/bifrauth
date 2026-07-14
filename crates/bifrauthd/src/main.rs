//! bifrauthd — the root-owned verifier daemon.
//!
//! The verifier state machine lives in the library ([`bifrauthd`]). The root Unix socket IPC (the daemon
//! loop, SO_PEERCRED, framing) is implemented in a later task; this binary is a placeholder for now.

fn main() {
    eprintln!(
        "bifrauthd: the verifier core is available as a library; the socket daemon is a later task."
    );
    std::process::exit(1);
}
