//! `bifrauthctl` binary entry point — a thin wrapper over [`bifrauthctl::run`].
//!
//! Enforces `euid == 0` (the registry is root-only), opens the production registry at
//! [`bifrauthd::registry::DEFAULT_BASE_DIR`], and dispatches. All command logic and error formatting
//! live in the library so they are unit-tested against an owner-injected registry.

use bifrauthd::registry::{DEFAULT_BASE_DIR, Registry};
use bifrauthd::resolver::UzersResolver;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    // Root-only: the registry lives under a root-owned tree and this tool mutates it (design §8.3/§14.1).
    if rustix::process::geteuid().as_raw() != 0 {
        eprintln!("bifrauthctl: must run as root (euid 0)");
        return ExitCode::from(1);
    }

    let reg = match Registry::open(Path::new(DEFAULT_BASE_DIR)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bifrauthctl: cannot open registry at {DEFAULT_BASE_DIR}: {e}");
            return ExitCode::from(1);
        }
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut stdout = std::io::stdout().lock();

    match bifrauthctl::run(&args, &reg, &UzersResolver, now, &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bifrauthctl: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}
