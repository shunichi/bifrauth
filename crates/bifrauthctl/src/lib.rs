//! `bifrauthctl` — the root-only admin CLI for the device registry (design §14.1, task 0009).
//!
//! Subcommands:
//! - `register --user <name> --device <hex16> --pubkey <hexSEC1> [--label <text>]`
//! - `revoke   --user <name> --device <hex16>`
//! - `list     [--user <name>]`
//!
//! A username is resolved to a uid via the same NSS path the daemon uses
//! ([`bifrauthd::resolver::UzersResolver`]), so the CLI and daemon agree on identity.
//!
//! Reflection caveat (plan D5): changes are written to the persistent registry but a **running** daemon
//! only picks them up on restart (the production reload path is a task-B dependency). `register`/`revoke`
//! therefore print a note and never claim an immediate effect.
//!
//! The command logic lives in [`run`] so it can be tested against an owner-injected registry; `main`
//! is a thin wrapper that enforces `euid == 0` and opens the real `/etc/bifrauthd`.

use bifrauthd::registry::{Registry, RegistryError, hexcodec};
use bifrauthd::session::UserResolver;
use std::io::Write;

/// A CLI failure, with the process exit code it should map to.
#[derive(Debug)]
pub enum CliError {
    /// Bad invocation (unknown subcommand, missing/duplicate flag, bad value). Exit code 2.
    Usage(String),
    /// The `--user` name did not resolve to a uid via NSS. Exit code 1.
    UnknownUser(String),
    /// A registry operation failed (includes fail-closed corrupt/unsafe entries). Exit code 1.
    Registry(RegistryError),
    /// Writing output failed. Exit code 1.
    Output(std::io::Error),
}

impl CliError {
    /// The process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            _ => 1,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "usage error: {m}\n\n{USAGE}"),
            CliError::UnknownUser(u) => write!(f, "user does not resolve to a uid: {u}"),
            CliError::Registry(e) => write!(f, "registry error: {e}"),
            CliError::Output(e) => write!(f, "output error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

const USAGE: &str = "\
bifrauthctl — bifrauth device registry admin (run as root)

USAGE:
    bifrauthctl register --user <name> --device <hex16> --pubkey <hexSEC1> [--label <text>]
    bifrauthctl revoke   --user <name> --device <hex16>
    bifrauthctl list     [--user <name>]";

/// Run one CLI invocation against `reg`, resolving usernames through `resolver`, using `now` as the
/// wall-clock epoch for created/revoked timestamps, writing human output to `out`.
pub fn run<R: UserResolver>(
    args: &[String],
    reg: &Registry,
    resolver: &R,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let (subcommand, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("no subcommand".to_string()))?;
    match subcommand.as_str() {
        "register" => run_register(rest, reg, resolver, now, out),
        "revoke" => run_revoke(rest, reg, resolver, now, out),
        "list" => run_list(rest, reg, resolver, out),
        "-h" | "--help" | "help" => {
            writeln!(out, "{USAGE}").map_err(CliError::Output)?;
            Ok(())
        }
        other => Err(CliError::Usage(format!("unknown subcommand: {other}"))),
    }
}

fn run_register<R: UserResolver>(
    args: &[String],
    reg: &Registry,
    resolver: &R,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let mut flags = Flags::parse(args)?;
    let user = flags.take_required("--user")?;
    let device_hex = flags.take_required("--device")?;
    let pubkey_hex = flags.take_required("--pubkey")?;
    let label = flags.take_optional("--label")?.unwrap_or_default();
    flags.finish()?;

    let uid = resolve_uid(resolver, &user)?;
    let device_id = hexcodec::decode16(&device_hex)
        .ok_or_else(|| CliError::Usage("--device must be 16 bytes (32 hex chars)".to_string()))?;
    let sec1 = hexcodec::decode(&pubkey_hex)
        .ok_or_else(|| CliError::Usage("--pubkey must be hex".to_string()))?;

    reg.register(uid, device_id, &sec1, &label, now)
        .map_err(CliError::Registry)?;
    writeln!(
        out,
        "registered device {} for user {user} (uid {uid})",
        hexcodec::encode(&device_id)
    )
    .map_err(CliError::Output)?;
    writeln!(out, "{RESTART_NOTE}").map_err(CliError::Output)?;
    Ok(())
}

fn run_revoke<R: UserResolver>(
    args: &[String],
    reg: &Registry,
    resolver: &R,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let mut flags = Flags::parse(args)?;
    let user = flags.take_required("--user")?;
    let device_hex = flags.take_required("--device")?;
    flags.finish()?;

    let uid = resolve_uid(resolver, &user)?;
    let device_id = hexcodec::decode16(&device_hex)
        .ok_or_else(|| CliError::Usage("--device must be 16 bytes (32 hex chars)".to_string()))?;

    reg.revoke(uid, device_id, now)
        .map_err(CliError::Registry)?;
    writeln!(
        out,
        "revoked device {} for user {user} (uid {uid})",
        hexcodec::encode(&device_id)
    )
    .map_err(CliError::Output)?;
    writeln!(out, "{RESTART_NOTE}").map_err(CliError::Output)?;
    Ok(())
}

fn run_list<R: UserResolver>(
    args: &[String],
    reg: &Registry,
    resolver: &R,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let mut flags = Flags::parse(args)?;
    let user = flags.take_optional("--user")?;
    flags.finish()?;

    let records = match &user {
        Some(name) => {
            let uid = resolve_uid(resolver, name)?;
            reg.list(uid).map_err(CliError::Registry)?
        }
        None => reg.list_all().map_err(CliError::Registry)?,
    };

    writeln!(
        out,
        "{:<10}  {:<32}  {:<18}  {:<12}  label",
        "uid", "device_id", "status", "created_at"
    )
    .map_err(CliError::Output)?;
    for r in &records {
        let status = match r.revoked_at {
            Some(t) => format!("revoked({t})"),
            None => "active".to_string(),
        };
        writeln!(
            out,
            "{:<10}  {:<32}  {:<18}  {:<12}  {}",
            r.uid,
            hexcodec::encode(&r.device_id),
            status,
            r.created_at,
            r.label
        )
        .map_err(CliError::Output)?;
    }
    Ok(())
}

fn resolve_uid<R: UserResolver>(resolver: &R, user: &str) -> Result<u32, CliError> {
    resolver
        .resolve(user)
        .map(|id| id.uid)
        .ok_or_else(|| CliError::UnknownUser(user.to_string()))
}

const RESTART_NOTE: &str = "note: a running bifrauthd does not see this change until it restarts (reload is a future feature).";

/// A tiny flag parser for `--key value` pairs. Rejects duplicates, unknown/leftover args, and a flag
/// with no value.
struct Flags {
    pairs: Vec<(String, String)>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut pairs = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let key = &args[i];
            if !key.starts_with("--") {
                return Err(CliError::Usage(format!("unexpected argument: {key}")));
            }
            let value = args
                .get(i + 1)
                .ok_or_else(|| CliError::Usage(format!("{key} requires a value")))?;
            if value.starts_with("--") {
                return Err(CliError::Usage(format!("{key} requires a value")));
            }
            pairs.push((key.clone(), value.clone()));
            i += 2;
        }
        Ok(Flags { pairs })
    }

    fn take_required(&mut self, key: &str) -> Result<String, CliError> {
        self.take_optional(key)?
            .ok_or_else(|| CliError::Usage(format!("missing required flag {key}")))
    }

    fn take_optional(&mut self, key: &str) -> Result<Option<String>, CliError> {
        let mut found: Option<String> = None;
        let mut remaining = Vec::with_capacity(self.pairs.len());
        for (k, v) in std::mem::take(&mut self.pairs) {
            if k == key {
                if found.is_some() {
                    return Err(CliError::Usage(format!("{key} given more than once")));
                }
                found = Some(v);
            } else {
                remaining.push((k, v));
            }
        }
        self.pairs = remaining;
        Ok(found)
    }

    fn finish(self) -> Result<(), CliError> {
        if let Some((k, _)) = self.pairs.first() {
            return Err(CliError::Usage(format!("unknown flag {k}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrauthd::session::{ResolvedIdentity, UserResolver};
    use std::collections::HashMap;

    struct MapResolver(HashMap<String, u32>);
    impl UserResolver for MapResolver {
        fn resolve(&self, username: &str) -> Option<ResolvedIdentity> {
            self.0.get(username).map(|&uid| ResolvedIdentity {
                uid,
                canonical_username: username.to_string(),
            })
        }
    }

    fn resolver() -> MapResolver {
        let mut m = HashMap::new();
        m.insert("alice".to_string(), 4242u32);
        MapResolver(m)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn missing_subcommand_and_unknown_flag_are_usage_errors() {
        let mut out = Vec::new();
        let base = tempbase();
        let reg = base.open();
        assert!(matches!(
            run(&[], &reg, &resolver(), 1, &mut out),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            run(
                &strs(&["list", "--bogus", "x"]),
                &reg,
                &resolver(),
                1,
                &mut out
            ),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn unknown_user_is_reported() {
        let base = tempbase();
        let reg = base.open();
        let mut out = Vec::new();
        let e = run(
            &strs(&["revoke", "--user", "nobody", "--device", &"ab".repeat(16)]),
            &reg,
            &resolver(),
            1,
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(e, CliError::UnknownUser(_)));
    }

    #[test]
    fn bad_device_hex_is_usage_error() {
        let base = tempbase();
        let reg = base.open();
        let mut out = Vec::new();
        let e = run(
            &strs(&[
                "register", "--user", "alice", "--device", "zz", "--pubkey", "04",
            ]),
            &reg,
            &resolver(),
            1,
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(e, CliError::Usage(_)));
    }

    #[test]
    fn register_revoke_list_roundtrip() {
        let base = tempbase();
        let reg = base.open();
        let dev = "a1".repeat(16);
        let key = hexcodec::encode(&sec1_key(1));

        let mut out = Vec::new();
        run(
            &strs(&[
                "register", "--user", "alice", "--device", &dev, "--pubkey", &key, "--label",
                "myphone",
            ]),
            &reg,
            &resolver(),
            1000,
            &mut out,
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("registered device"));
        assert!(s.contains("restarts"), "must warn about daemon restart");

        // list --user shows it as active.
        let mut out = Vec::new();
        run(
            &strs(&["list", "--user", "alice"]),
            &reg,
            &resolver(),
            1000,
            &mut out,
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains(&dev));
        assert!(s.contains("active"));

        // revoke, then list shows revoked(...).
        let mut out = Vec::new();
        run(
            &strs(&["revoke", "--user", "alice", "--device", &dev]),
            &reg,
            &resolver(),
            2000,
            &mut out,
        )
        .unwrap();
        let mut out = Vec::new();
        run(&strs(&["list"]), &reg, &resolver(), 2000, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("revoked(2000)"), "list output was: {s}");
    }

    // ---- test helpers: an owner-injected temp registry ----

    fn sec1_key(seed: u8) -> Vec<u8> {
        mock_iphone::MockIphone::new([0x11; 16], &[seed; 32], [0u8; 32], [0x22; 16])
            .unwrap()
            .device_public_key_sec1()
            .to_vec()
    }

    struct TempBase {
        path: std::path::PathBuf,
    }
    impl TempBase {
        fn open(&self) -> Registry {
            Registry::open_with_owner(
                &self.path,
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
            )
            .unwrap()
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn tempbase() -> TempBase {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU32, Ordering};
        static C: AtomicU32 = AtomicU32::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("bifrauthctl-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempBase { path }
    }
}
