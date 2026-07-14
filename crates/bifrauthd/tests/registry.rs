//! On-disk device registry: safety, concurrency, and schema tests (task 0009).
//!
//! These drive the public [`bifrauthd::registry::Registry`] against a temp directory the test user owns,
//! using the owner-injection constructor so the symlink/mode/traversal checks still run unprivileged.

use bifrauthd::registry::{DeviceRecord, Registry, RegistryError};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// A valid P-256 SEC1 public key for a given seed, via the mock device (dev-dependency).
fn sec1_key(seed: u8) -> Vec<u8> {
    mock_iphone::MockIphone::new([0x11; 16], &[seed; 32], [0u8; 32], [0x22; 16])
        .unwrap()
        .device_public_key_sec1()
        .to_vec()
}

fn me() -> (u32, u32) {
    (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
}

/// A temp base directory owned by the test user, removed on drop.
struct TempBase {
    path: PathBuf,
}

impl TempBase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("bifrauth-reg-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempBase { path }
    }

    fn open(&self) -> Registry {
        let (uid, gid) = me();
        Registry::open_with_owner(&self.path, uid, gid).unwrap()
    }

    fn devices_dir(&self, uid: u32) -> PathBuf {
        self.path
            .join("users")
            .join(uid.to_string())
            .join("devices")
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

const UID: u32 = 4242;
const DEV_A: [u8; 16] = [0xA1; 16];
const DEV_B: [u8; 16] = [0xB2; 16];

fn dev_filename(id: &[u8; 16]) -> String {
    let mut s = String::new();
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    format!("{s}.cbor")
}

#[test]
fn register_list_roundtrip_and_load_snapshot() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "phone", 1000)
        .unwrap();

    let list = reg.list(UID).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].device_id, DEV_A);
    assert_eq!(list[0].label, "phone");
    assert_eq!(list[0].created_at, 1000);
    assert!(!list[0].is_revoked());

    // load_all returns a snapshot that installs without error.
    let mut v = bifrauthd::Verifier::new([0x03; 32], bifrauthd::BoottimeClock);
    v.replace_devices(reg.load_all().unwrap()).unwrap();
}

#[test]
fn register_duplicate_is_rejected_without_changing_bytes() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "first", 1000)
        .unwrap();
    let before = std::fs::read(base.devices_dir(UID).join(dev_filename(&DEV_A))).unwrap();

    // A second register (even active-or-revoked) is refused; original bytes are untouched.
    let err = reg
        .register(UID, DEV_A, &sec1_key(2), "second", 2000)
        .unwrap_err();
    assert!(matches!(err, RegistryError::AlreadyRegistered));
    let after = std::fs::read(base.devices_dir(UID).join(dev_filename(&DEV_A))).unwrap();
    assert_eq!(before, after, "duplicate register must not overwrite");
}

#[test]
fn revoke_is_one_way_and_preserves_bytes_on_repeat() {
    let base = TempBase::new();
    let reg = base.open();
    // Revoke before register -> NotRegistered.
    assert!(matches!(
        reg.revoke(UID, DEV_A, 500).unwrap_err(),
        RegistryError::NotRegistered
    ));

    reg.register(UID, DEV_A, &sec1_key(1), "phone", 1000)
        .unwrap();
    reg.revoke(UID, DEV_A, 2000).unwrap();
    let rec = &reg.list(UID).unwrap()[0];
    assert_eq!(rec.revoked_at, Some(2000));

    // Second revoke is AlreadyRevoked and leaves the bytes unchanged.
    let before = std::fs::read(base.devices_dir(UID).join(dev_filename(&DEV_A))).unwrap();
    assert!(matches!(
        reg.revoke(UID, DEV_A, 3000).unwrap_err(),
        RegistryError::AlreadyRevoked
    ));
    let after = std::fs::read(base.devices_dir(UID).join(dev_filename(&DEV_A))).unwrap();
    assert_eq!(before, after);

    // A revoked registration still blocks re-registration (design §14.2).
    assert!(matches!(
        reg.register(UID, DEV_A, &sec1_key(9), "new", 4000)
            .unwrap_err(),
        RegistryError::AlreadyRegistered
    ));
}

#[test]
fn concurrent_register_same_device_has_exactly_one_winner() {
    let base = TempBase::new();
    let path = base.path.clone();
    let (uid, gid) = me();

    let mut handles = Vec::new();
    for seed in 0u8..8 {
        let p = path.clone();
        handles.push(std::thread::spawn(move || {
            let reg = Registry::open_with_owner(&p, uid, gid).unwrap();
            reg.register(UID, DEV_A, &sec1_key(seed.max(1)), "x", 1000)
                .is_ok()
        }));
    }
    let winners = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(
        winners, 1,
        "renameat2(RENAME_NOREPLACE) admits exactly one register"
    );

    // The stored file is a single valid record.
    let reg = base.open();
    assert_eq!(reg.list(UID).unwrap().len(), 1);
}

#[test]
fn concurrent_register_distinct_devices_all_persist() {
    let base = TempBase::new();
    let path = base.path.clone();
    let (uid, gid) = me();

    let mut handles = Vec::new();
    for seed in 1u8..=16 {
        let p = path.clone();
        handles.push(std::thread::spawn(move || {
            let reg = Registry::open_with_owner(&p, uid, gid).unwrap();
            let mut id = [0u8; 16];
            id[0] = seed;
            reg.register(UID, id, &sec1_key(seed), "x", 1000).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let reg = base.open();
    assert_eq!(reg.list(UID).unwrap().len(), 16);
    // load_all sees a consistent snapshot with all 16 devices.
    let snapshot = reg.load_all().unwrap();
    let mut v = bifrauthd::Verifier::new([0x03; 32], bifrauthd::BoottimeClock);
    v.replace_devices(snapshot).unwrap();
}

#[test]
fn intermediate_directory_symlink_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();

    // Replace users/<uid>/devices with a symlink to an attacker-controlled dir.
    let devices = base.devices_dir(UID);
    let evil = base.path.join("evil");
    std::fs::create_dir(&evil).unwrap();
    std::fs::remove_dir_all(&devices).unwrap();
    symlink(&evil, &devices).unwrap();

    let err = reg.list(UID).unwrap_err();
    assert!(
        matches!(err, RegistryError::Unsafe { .. }),
        "symlinked component must fail closed, got {err:?}"
    );
}

#[test]
fn device_file_symlink_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();

    let file = base.devices_dir(UID).join(dev_filename(&DEV_A));
    let target = base.path.join("secret");
    std::fs::write(&target, b"whatever").unwrap();
    std::fs::remove_file(&file).unwrap();
    symlink(&target, &file).unwrap();

    let err = reg.list(UID).unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn non_regular_device_entry_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
    // Put a *directory* where a device file's canonical name is expected.
    let dir = base.devices_dir(UID).join(dev_filename(&DEV_B));
    std::fs::create_dir(&dir).unwrap();

    let err = reg.list(UID).unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn unexpected_entry_in_devices_dir_fails_closed() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
    // A stray file (e.g. a leftover temp or garbage) is not silently skipped.
    std::fs::write(base.devices_dir(UID).join("garbage.txt"), b"junk").unwrap();

    let err = reg.list(UID).unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn hardlinked_device_file_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
    let a = base.devices_dir(UID).join(dev_filename(&DEV_A));
    let b = base.devices_dir(UID).join(dev_filename(&DEV_B));
    std::fs::hard_link(&a, &b).unwrap(); // both now have nlink == 2

    let err = reg.list(UID).unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn corrupt_and_mismatched_records_fail_closed() {
    // Garbage CBOR under a canonical name.
    let base = TempBase::new();
    let reg = base.open();
    let dev_dir = base.devices_dir(UID);
    std::fs::create_dir_all(&dev_dir).unwrap();
    std::fs::write(dev_dir.join(dev_filename(&DEV_A)), b"\xff\xff\xff\xff").unwrap();
    assert!(matches!(
        reg.list(UID).unwrap_err(),
        RegistryError::Corrupt { .. }
    ));
}

#[test]
fn oversize_record_file_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    let dev_dir = base.devices_dir(UID);
    std::fs::create_dir_all(&dev_dir).unwrap();
    std::fs::write(dev_dir.join(dev_filename(&DEV_A)), vec![0u8; 5000]).unwrap();
    assert!(matches!(
        reg.list(UID).unwrap_err(),
        RegistryError::Corrupt { .. }
    ));
}

#[test]
fn non_canonical_uid_directory_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
    // Create a bogus, non-canonical uid directory (leading zero).
    std::fs::create_dir_all(base.path.join("users").join("007").join("devices")).unwrap();
    assert!(matches!(
        reg.list_all().unwrap_err(),
        RegistryError::Unsafe { .. }
    ));
}

#[test]
fn lock_file_symlink_is_rejected() {
    let base = TempBase::new();
    // Pre-plant .registry.lock as a symlink before any operation.
    let target = base.path.join("lock-target");
    std::fs::write(&target, b"x").unwrap();
    symlink(&target, base.path.join(".registry.lock")).unwrap();

    let reg = base.open();
    let err = reg
        .register(UID, DEV_A, &sec1_key(1), "x", 1000)
        .unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn group_writable_lock_file_is_rejected() {
    let base = TempBase::new();
    // First op creates the lock 0600.
    let reg = base.open();
    reg.register(UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
    // Loosen the lock to be group-writable; the next op must fail closed.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        base.path.join(".registry.lock"),
        std::fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    let err = reg.list(UID).unwrap_err();
    assert!(matches!(err, RegistryError::Unsafe { .. }), "got {err:?}");
}

#[test]
fn label_validation() {
    let base = TempBase::new();
    let reg = base.open();
    // Empty label is allowed (means "no label").
    reg.register(UID, DEV_A, &sec1_key(1), "", 1000).unwrap();
    assert_eq!(reg.list(UID).unwrap()[0].label, "");
    // Control characters are rejected (no terminal escapes / newlines in list output).
    assert!(matches!(
        reg.register(UID, DEV_B, &sec1_key(2), "bad\nname", 1000)
            .unwrap_err(),
        RegistryError::InvalidLabel
    ));
    // Overlong label is rejected.
    let long = "x".repeat(200);
    assert!(matches!(
        reg.register(UID, DEV_B, &sec1_key(2), &long, 1000)
            .unwrap_err(),
        RegistryError::InvalidLabel
    ));
}

#[test]
fn invalid_public_key_is_rejected() {
    let base = TempBase::new();
    let reg = base.open();
    assert!(matches!(
        reg.register(UID, DEV_A, &[0u8; 5], "x", 1000).unwrap_err(),
        RegistryError::InvalidPublicKey
    ));
}

// A helper reused by a couple of tests: read a record straight back for assertions.
#[allow(dead_code)]
fn read_record(base: &Path, uid: u32, id: &[u8; 16]) -> DeviceRecord {
    let reg = Registry::open_with_owner(base, me().0, me().1).unwrap();
    reg.list(uid)
        .unwrap()
        .into_iter()
        .find(|r| &r.device_id == id)
        .unwrap()
}
