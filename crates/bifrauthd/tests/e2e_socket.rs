//! End-to-end authentication over the real root socket, with the device registry as the source of truth
//! (design §23-9,10; task 0009 D7).
//!
//! Wires the production accept loop [`bifrauthd::serve::serve`] on a real `UnixListener`, injects a
//! [`bifrauth_ipc::Transport`] backed by [`mock_iphone::MockIphone`] (the stand-in responder), and drives
//! a client through `AuthRequest → ConfirmationCode → DisplayAck → Outcome`. The verifier's device set is
//! loaded from an on-disk [`bifrauthd::registry::Registry`], so this exercises the full 0009 path:
//!
//! - a registered device completes the round trip with `Success`;
//! - after `revoke` + an atomic snapshot reload, the same device is `Denied`.
//!
//! The finer "a response whose challenge was issued while the device was still active must be denied once
//! the registry is swapped to a revoked snapshot" case is proven deterministically at the verifier level
//! in `lib.rs::tests::pending_response_crossing_a_revoke_boundary_is_denied` (it needs to interleave
//! issue/replace/verify precisely, which the synchronous socket flow cannot express).

use bifrauth_ipc::wire::{AuthRequest, ConfirmationCode, DisplayAck, Outcome, OutcomeCode};
use bifrauth_ipc::{Clock, Deadline, Transport, TransportError, frame};
use bifrauthd::Verifier;
use bifrauthd::registry::Registry;
use bifrauthd::serve::{Shared, serve};
use bifrauthd::session::{Policy, ResolvedIdentity, UserResolver};
use mock_iphone::MockIphone;
use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VERIFIER_SEED: [u8; 32] = [0x03; 32];
const DEVICE_SEED: [u8; 32] = [0x55; 32];
const IPHONE_DEV: [u8; 16] = [0x66; 16];
const LINUX_DEV: [u8; 16] = [0x44; 16];
const UID: u32 = 4242;
const SERVICE: &str = "bifrauth-login";

// A fixed clock so the pending challenge never expires mid-test regardless of real elapsed time.
#[derive(Clone, Copy)]
struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_boottime_ns(&self) -> u64 {
        self.0
    }
}

// The transport port backed by the software mock iPhone (the responder).
struct IphoneTransport {
    ph: MockIphone,
}
impl Transport for IphoneTransport {
    fn dispatch(&self, envelope: &[u8], _deadline: Deadline) -> Result<Vec<u8>, TransportError> {
        self.ph
            .process(envelope)
            .map_err(|_| TransportError::Failed)
    }
}

struct MapResolver(HashMap<String, u32>);
impl UserResolver for MapResolver {
    fn resolve(&self, username: &str) -> Option<ResolvedIdentity> {
        self.0.get(username).map(|&uid| ResolvedIdentity {
            uid,
            canonical_username: username.to_string(),
        })
    }
}

fn verifier_pk() -> [u8; 32] {
    bifrauth_crypto::ed25519::public_key(&bifrauth_crypto::ed25519::signing_key(&VERIFIER_SEED))
}

fn iphone() -> MockIphone {
    MockIphone::new(IPHONE_DEV, &DEVICE_SEED, verifier_pk(), LINUX_DEV).unwrap()
}

fn policy() -> Policy {
    Policy {
        linux_device_id: LINUX_DEV,
        linux_device_name: "workstation".into(),
        ttl_seconds: 30,
        allowed_pam_services: vec![SERVICE.to_string()],
    }
}

fn resolver() -> MapResolver {
    let mut m = HashMap::new();
    m.insert("alice".to_string(), UID);
    MapResolver(m)
}

// ---- a temp registry the test user owns ----

struct TempBase {
    path: PathBuf,
}
impl TempBase {
    fn new() -> Self {
        static C: AtomicU32 = AtomicU32::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("bifrauth-e2e-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&path);
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempBase { path }
    }
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

fn timeouts_supported() -> bool {
    match UnixStream::pair() {
        Ok((a, _)) => a.set_read_timeout(Some(Duration::from_millis(50))).is_ok(),
        Err(_) => false,
    }
}

fn temp_sock(name: &str) -> PathBuf {
    let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    Path::new(&dir).join(name)
}

fn auth_request(user: &str) -> Vec<u8> {
    AuthRequest {
        username: user.into(),
        pam_service: SERVICE.into(),
        pam_tty: None,
        pam_rhost: None,
    }
    .encode()
    .unwrap()
}

/// Drive one full client flow over the socket; returns the Outcome code or Err on any I/O failure.
fn client_flow(path: &Path, user: &str) -> Result<OutcomeCode, ()> {
    let clock = bifrauth_ipc::BoottimeClock;
    let dl = Deadline::after_secs(&clock, 15);
    let mut s = UnixStream::connect(path).map_err(|_| ())?;
    frame::write_message(&mut s, &auth_request(user), dl, &clock).map_err(|_| ())?;
    let cc = frame::read_message(&mut s, dl, &clock).map_err(|_| ())?;
    let cc = ConfirmationCode::decode(&cc).map_err(|_| ())?;
    let ack = DisplayAck {
        request_id: cc.request_id,
        conversation_succeeded: true,
    }
    .encode()
    .unwrap();
    frame::write_message(&mut s, &ack, dl, &clock).map_err(|_| ())?;
    let out = frame::read_message(&mut s, dl, &clock).map_err(|_| ())?;
    Outcome::decode(&out).map(|o| o.result).map_err(|_| ())
}

#[test]
fn registered_device_succeeds_then_revoked_device_is_denied_over_the_socket() {
    if !timeouts_supported() {
        eprintln!("skipping: this environment does not permit socket timeouts");
        return;
    }

    // Registry is the source of truth: register the device, load it into the verifier.
    let base = TempBase::new();
    let reg = base.open();
    let sec1 = iphone().device_public_key_sec1();
    reg.register(UID, IPHONE_DEV, &sec1, "phone", 1000).unwrap();

    let mut verifier = Verifier::new(VERIFIER_SEED, FixedClock(1_000_000_000));
    verifier.replace_devices(reg.load_all().unwrap()).unwrap();

    let shared = Arc::new(Shared {
        verifier: Mutex::new(verifier),
        clock: FixedClock(1_000_000_000),
        transport: IphoneTransport { ph: iphone() },
        policy: policy(),
        resolver: resolver(),
        authorize: |_uid: u32| true, // production uses |uid| uid == 0; the test runs unprivileged
    });

    let path = temp_sock("bifrauthd-e2e-registry.sock");
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => Arc::new(l),
        Err(_) => {
            eprintln!("skipping: binding a unix socket is not permitted in this environment");
            return;
        }
    };
    {
        let l = Arc::clone(&listener);
        let sh = Arc::clone(&shared);
        std::thread::spawn(move || serve(l, sh, 2));
    }

    // (1) The registered device authenticates end-to-end.
    assert_eq!(client_flow(&path, "alice"), Ok(OutcomeCode::Success));

    // (2) Revoke it in the registry, then atomically reload the snapshot into the running verifier.
    reg.revoke(UID, IPHONE_DEV, 2000).unwrap();
    shared
        .verifier
        .lock()
        .unwrap()
        .replace_devices(reg.load_all().unwrap())
        .unwrap();

    // The same device is now denied (RevokedDevice -> Denied), proving revocation reaches verification.
    assert_eq!(client_flow(&path, "alice"), Ok(OutcomeCode::Denied));

    let _ = std::fs::remove_file(&path);
}
