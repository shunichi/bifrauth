//! Persistent, root-owned device registry (design §8.3, task 0009).
//!
//! Stores each registered iPhone device as one canonical-CBOR file under a base directory (default
//! `/etc/bifrauthd`):
//!
//! ```text
//! <base>/users/<uid>/devices/<device_id_hex>.cbor
//! ```
//!
//! Format: the whole project uses one canonical acceptance representation, deterministic CBOR
//! ([`bifrauth_proto::cbor`]); the registry reuses it rather than introducing JSON (cbor-profile §8 —
//! registration info uses the same representation; this supersedes the `.json` sketch in design §8.3).
//!
//! Safety model (implementation-plan §4.7, mirrored here). Every path component is traversed from a
//! trusted base dirfd with `openat(O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` and `fstat`-verified (a real
//! directory, owned by the expected uid/gid, no group/world write), so an attacker cannot swap an
//! intermediate component for a symlink. Device files are opened `O_NOFOLLOW` and verified as regular,
//! single-link (`nlink == 1`, no surprise hardlink), owner/mode-checked, and size-capped before reading.
//! Writes are staged to a CSPRNG-named temp in the same directory (`O_EXCL`), `fsync`ed, then published:
//! **register** uses `renameat2(RENAME_NOREPLACE)` so an existing (active *or* revoked) registration is
//! never overwritten (`EEXIST` → [`RegistryError::AlreadyRegistered`], design §14.2); the directory is
//! `fsync`ed after. A corrupt/unreadable registry is **fail closed** (never silently regenerated).
//!
//! Concurrency (task 0009 D3-a). All operations run under a single registry-wide advisory lock,
//! `<base>/.registry.lock` (`flock`): mutations take it exclusively, reads (`list*`/`load_all`) take it
//! shared. Holding it shared for the entire enumeration guarantees a **point-in-time** snapshot — a
//! writer for any uid is blocked while a snapshot is built, so a partial/mixed view is impossible.
//! `flock` is per open-file-description, so independently opened lock fds (even in one process) still
//! exclude one another. The lock file is reserved: it is created safely, verified, and never
//! renamed/unlinked, and enumeration skips exactly this one name.
//!
//! Running-daemon reflection is out of scope here (the production daemon is not yet wired, task B): the
//! daemon loads a [`DeviceSnapshot`] at startup. `bifrauthctl` must therefore tell the operator that a
//! change is not reflected until the daemon restarts (plan D5).

use crate::{DeviceSnapshot, SnapshotError};
use bifrauth_crypto as crypto;
use bifrauth_proto::cbor::{self, Value};
use bifrauth_proto::text;
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, flock, fstat, mkdirat,
    openat, renameat_with, unlinkat,
};
use rustix::io::Errno;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

/// The default registry base directory (design §8.3).
pub const DEFAULT_BASE_DIR: &str = "/etc/bifrauthd";

/// The registry record schema version (CBOR map key 0).
const RECORD_VERSION: u64 = 1;
/// Directory / file / lock modes we create and require (no group/world write; plan D2).
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o640;
const LOCK_MODE: u32 = 0o600;
/// The reserved registry-wide lock filename (never enumerated as a device).
const LOCK_NAME: &str = ".registry.lock";
/// Prefix for in-progress temp files (dot-prefixed so a canonical `<hex>.cbor` never collides).
const TEMP_PREFIX: &str = ".tmp-";
/// `(uid_t)-1` is reserved and rejected (matches the challenge `target_uid` range, cbor-profile §4).
const UID_MAX: u32 = u32::MAX - 1;
/// Device id length in bytes (cbor-profile §8: exact 16 B).
const DEVICE_ID_LEN: usize = 16;
/// Upper bound on a stored SEC1 public key (uncompressed P-256 is 65 B).
const SEC1_MAX_BYTES: usize = 65;
/// Upper bound on a device label (bytes).
const LABEL_MAX_BYTES: usize = 128;
/// Upper bound on a whole record file (checked before reading).
const MAX_RECORD_FILE: u64 = 4096;

/// Layer-A CBOR limits for a registry record (small, single top-level map).
fn record_limits() -> cbor::Limits {
    cbor::Limits {
        max_total: MAX_RECORD_FILE as usize,
        max_depth: 1,
        max_bytes: SEC1_MAX_BYTES,
        max_text: LABEL_MAX_BYTES,
        max_map_entries: 8,
    }
}

/// A device registration as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub uid: u32,
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The device's P-256 SEC1 public key.
    pub sec1: Vec<u8>,
    /// Human-readable label; empty string means "no label" (the single canonical representation).
    pub label: String,
    /// Wall-clock epoch seconds at registration.
    pub created_at: u64,
    /// `Some(epoch_secs)` iff revoked (tombstone). A revoked record is never revived.
    pub revoked_at: Option<u64>,
}

impl DeviceRecord {
    /// Whether this registration has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Why a registry operation failed.
#[derive(Debug)]
pub enum RegistryError {
    /// A registration already exists for this (uid, device_id) — active or revoked (design §14.2).
    AlreadyRegistered,
    /// The device is already revoked (revocation is one-way).
    AlreadyRevoked,
    /// No registration exists for this (uid, device_id).
    NotRegistered,
    /// The supplied bytes are not a valid P-256 SEC1 public key.
    InvalidPublicKey,
    /// The supplied label violates the length/text policy.
    InvalidLabel,
    /// On-disk data is corrupt or violates the schema (fail closed). Carries a path hint and reason.
    Corrupt { path: String, reason: String },
    /// A path-safety invariant was violated (symlink, wrong owner/mode, unexpected hardlink, non-regular,
    /// unknown directory entry). Fail closed. Carries a path hint and reason.
    Unsafe { path: String, reason: String },
    /// The change was published (the rename succeeded) but the subsequent directory `fsync` failed, so its
    /// durability across a crash is uncertain. The operation itself took effect — a caller should verify
    /// with `list` rather than retry (a retry hits AlreadyRegistered/AlreadyRevoked anyway).
    DurabilityUncertain {
        path: String,
        source: std::io::Error,
    },
    /// The OS randomness source failed while generating a temp name.
    Rng,
    /// An unexpected I/O error. Carries a path hint.
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::AlreadyRegistered => write!(f, "device already registered"),
            RegistryError::AlreadyRevoked => write!(f, "device already revoked"),
            RegistryError::NotRegistered => write!(f, "device not registered"),
            RegistryError::InvalidPublicKey => write!(f, "invalid P-256 SEC1 public key"),
            RegistryError::InvalidLabel => write!(f, "invalid label"),
            RegistryError::Corrupt { path, reason } => {
                write!(f, "corrupt registry entry {path}: {reason}")
            }
            RegistryError::Unsafe { path, reason } => {
                write!(f, "unsafe registry path {path}: {reason}")
            }
            RegistryError::DurabilityUncertain { path, source } => write!(
                f,
                "change applied but durability uncertain (fsync {path} failed: {source}); verify with `list`"
            ),
            RegistryError::Rng => write!(f, "randomness source failed"),
            RegistryError::Io { path, source } => write!(f, "I/O error on {path}: {source}"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegistryError::Io { source, .. } => Some(source),
            RegistryError::DurabilityUncertain { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_err(path: &str, e: Errno) -> RegistryError {
    RegistryError::Io {
        path: path.to_string(),
        source: std::io::Error::from_raw_os_error(e.raw_os_error()),
    }
}

/// The persistent device registry, bound to a verified base directory fd.
pub struct Registry {
    base: OwnedFd,
    /// The uid/gid every registry file/dir must be owned by (production: root = 0/0).
    owner_uid: u32,
    owner_gid: u32,
    /// A stable label for the base directory used in error messages.
    base_label: String,
}

impl Registry {
    /// Open (creating if absent) the production registry rooted at `base_path`, requiring root ownership
    /// (uid == 0 && gid == 0). Ownership is fixed here, not caller-supplied, so a production caller cannot
    /// weaken the owner check.
    pub fn open(base_path: &Path) -> Result<Self, RegistryError> {
        Self::open_inner(base_path, 0, 0)
    }

    /// Open a registry requiring an arbitrary owner uid/gid — a **testing-only** escape hatch so
    /// unprivileged tests can exercise the symlink/mode/traversal checks against a temp directory they own.
    /// Compiled only under `cfg(test)` or the `testing` feature, so it is absent from the production API
    /// surface. Production must use [`Registry::open`].
    #[cfg(any(test, feature = "testing"))]
    pub fn open_with_owner(
        base_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, RegistryError> {
        Self::open_inner(base_path, owner_uid, owner_gid)
    }

    fn open_inner(base_path: &Path, owner_uid: u32, owner_gid: u32) -> Result<Self, RegistryError> {
        let base_label = base_path.display().to_string();
        let base = open_or_create_base(base_path, &base_label)?;
        verify_dir(base.as_fd(), owner_uid, owner_gid, DIR_MODE, &base_label)?;
        Ok(Registry {
            base,
            owner_uid,
            owner_gid,
            base_label,
        })
    }

    /// Register a device (design §8.3). Fails [`RegistryError::AlreadyRegistered`] if a registration for
    /// this (uid, device_id) already exists (active or revoked); the publish is atomic and non-clobbering.
    pub fn register(
        &self,
        uid: u32,
        device_id: [u8; DEVICE_ID_LEN],
        p256_sec1: &[u8],
        label: &str,
        now: u64,
    ) -> Result<(), RegistryError> {
        crypto::p256_ecdsa::validate_public_key(p256_sec1)
            .map_err(|_| RegistryError::InvalidPublicKey)?;
        if p256_sec1.len() > SEC1_MAX_BYTES {
            return Err(RegistryError::InvalidPublicKey);
        }
        validate_uid(uid).map_err(|r| self.corrupt_here(&r))?;
        validate_label(label)?;

        let _lock = self.lock(FlockOperation::LockExclusive)?;
        let devices = self.devices_dir_for_write(uid)?;
        let record = DeviceRecord {
            uid,
            device_id,
            sec1: p256_sec1.to_vec(),
            label: label.to_string(),
            created_at: now,
            revoked_at: None,
        };
        let bytes = encode_record(&record);
        let final_name = device_filename(&device_id);
        publish(
            devices.as_fd(),
            &final_name,
            &bytes,
            RenameFlags::NOREPLACE,
            &self.base_label,
        )
    }

    /// Revoke a device (tombstone). Fails [`RegistryError::NotRegistered`] if absent and
    /// [`RegistryError::AlreadyRevoked`] if already revoked (bytes then left unchanged).
    pub fn revoke(
        &self,
        uid: u32,
        device_id: [u8; DEVICE_ID_LEN],
        now: u64,
    ) -> Result<(), RegistryError> {
        let _lock = self.lock(FlockOperation::LockExclusive)?;
        let devices = match self.devices_dir_for_read(uid)? {
            Some(d) => d,
            None => return Err(RegistryError::NotRegistered),
        };
        let final_name = device_filename(&device_id);
        let bytes = match self.read_device_file(devices.as_fd(), &final_name) {
            Ok(b) => b,
            Err(RegistryError::NotRegistered) => return Err(RegistryError::NotRegistered),
            Err(e) => return Err(e),
        };
        let mut record = decode_record(&bytes, uid, device_id, &final_name)?;
        if record.is_revoked() {
            return Err(RegistryError::AlreadyRevoked);
        }
        record.revoked_at = Some(now);
        let new_bytes = encode_record(&record);
        // Replace in place (allowed: the same device under the exclusive lock is serialized).
        publish(
            devices.as_fd(),
            &final_name,
            &new_bytes,
            RenameFlags::empty(),
            &self.base_label,
        )
    }

    /// List one user's registrations (shared lock). Fails closed on any corrupt/unsafe entry.
    pub fn list(&self, uid: u32) -> Result<Vec<DeviceRecord>, RegistryError> {
        let _lock = self.lock(FlockOperation::LockShared)?;
        let Some(users) = self.open_dir_read(self.base.as_fd(), "users", "users")? else {
            return Ok(Vec::new());
        };
        self.read_one_user(users.as_fd(), uid, &uid.to_string())
    }

    /// List every registration across all users (shared lock). Fails closed on any corrupt/unsafe entry.
    pub fn list_all(&self) -> Result<Vec<DeviceRecord>, RegistryError> {
        let _lock = self.lock(FlockOperation::LockShared)?;
        self.enumerate_all()
    }

    /// Build a validated point-in-time [`DeviceSnapshot`] for the verifier (shared lock, so no writer can
    /// interleave). Fails closed on any corrupt/unsafe entry rather than dropping it.
    pub fn load_all(&self) -> Result<DeviceSnapshot, RegistryError> {
        let _lock = self.lock(FlockOperation::LockShared)?;
        let records = self.enumerate_all()?;
        let mut builder = DeviceSnapshot::builder();
        for r in &records {
            builder
                .add(r.uid, r.device_id, &r.sec1, r.is_revoked())
                .map_err(|e| RegistryError::Corrupt {
                    path: device_filename(&r.device_id),
                    reason: match e {
                        SnapshotError::InvalidPublicKey => "invalid public key".to_string(),
                        SnapshotError::Duplicate => "duplicate (uid, device_id)".to_string(),
                    },
                })?;
        }
        Ok(builder.build())
    }

    // ---- internal helpers (all assume the caller holds the appropriate lock) ----

    fn corrupt_here(&self, reason: &str) -> RegistryError {
        RegistryError::Corrupt {
            path: self.base_label.clone(),
            reason: reason.to_string(),
        }
    }

    /// Acquire the registry-wide advisory lock, verifying (and safely first-creating) the lock file.
    fn lock(&self, op: FlockOperation) -> Result<LockGuard, RegistryError> {
        let path = format!("{}/{LOCK_NAME}", self.base_label);
        // Try to create it exclusively first so we can tell "we created it" (needs fsync) from "it
        // existed"; a concurrent first-time creator loses the race with EEXIST and opens the existing one.
        let (fd, created) = match openat(
            self.base.as_fd(),
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(LOCK_MODE),
        ) {
            Ok(fd) => (fd, true),
            Err(Errno::EXIST) => {
                let fd = openat(
                    self.base.as_fd(),
                    LOCK_NAME,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| lock_open_err(&path, e))?;
                (fd, false)
            }
            Err(Errno::LOOP) => {
                return Err(RegistryError::Unsafe {
                    path,
                    reason: "lock file is a symlink".to_string(),
                });
            }
            Err(e) => return Err(io_err(&path, e)),
        };
        // Only an inode we just created is normalized (fchmod to the exact mode, then made durable) — and
        // that happens *before* verification. A pre-existing inode is never chmod'd before it is trusted:
        // it must already be exactly the expected owner/mode/nlink or verification fails closed.
        if created {
            rustix::fs::fchmod(fd.as_fd(), Mode::from_raw_mode(LOCK_MODE))
                .map_err(|e| io_err(&path, e))?;
        }
        verify_regular(fd.as_fd(), self.owner_uid, self.owner_gid, LOCK_MODE, &path)?;
        if created {
            rustix::fs::fsync(fd.as_fd()).map_err(|e| io_err(&path, e))?;
            rustix::fs::fsync(self.base.as_fd()).map_err(|e| io_err(&self.base_label, e))?;
        }
        flock(fd.as_fd(), op).map_err(|e| io_err(&path, e))?;
        Ok(LockGuard { fd })
    }

    /// Traverse base -> users -> <uid> -> devices, creating each directory if absent.
    fn devices_dir_for_write(&self, uid: u32) -> Result<OwnedFd, RegistryError> {
        let users = self.open_or_create_dir(self.base.as_fd(), "users", &self.base_label)?;
        let uid_name = uid.to_string();
        let user_dir = self.open_or_create_dir(users.as_fd(), &uid_name, &uid_name)?;
        self.open_or_create_dir(user_dir.as_fd(), "devices", "devices")
    }

    /// Traverse base -> users -> <uid> -> devices for reading; returns None if any component is absent.
    fn devices_dir_for_read(&self, uid: u32) -> Result<Option<OwnedFd>, RegistryError> {
        let Some(users) = self.open_dir_read(self.base.as_fd(), "users", "users")? else {
            return Ok(None);
        };
        let uid_name = uid.to_string();
        let Some(user_dir) = self.open_dir_read(users.as_fd(), &uid_name, &uid_name)? else {
            return Ok(None);
        };
        self.open_dir_read(user_dir.as_fd(), "devices", "devices")
    }

    fn open_or_create_dir(
        &self,
        parent: BorrowedFd<'_>,
        name: &str,
        label: &str,
    ) -> Result<OwnedFd, RegistryError> {
        match openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                verify_dir(fd.as_fd(), self.owner_uid, self.owner_gid, DIR_MODE, label)?;
                Ok(fd)
            }
            Err(Errno::NOENT) => {
                // Distinguish "we created it" (mkdirat Ok) from "it appeared meanwhile" (EEXIST): only an
                // inode we created is fchmod'd, and only before verification. A raced-in inode is verified
                // as-is and fails closed if it is not exactly the expected directory.
                let created = match mkdirat(parent, name, Mode::from_raw_mode(DIR_MODE)) {
                    Ok(()) => true,
                    Err(Errno::EXIST) => false,
                    Err(e) => return Err(io_err(label, e)),
                };
                // Reopen with O_NOFOLLOW: if a symlink was raced into place, this fails ELOOP/ENOTDIR.
                let fd = openat(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| dir_open_err(label, e))?;
                if created {
                    rustix::fs::fchmod(fd.as_fd(), Mode::from_raw_mode(DIR_MODE))
                        .map_err(|e| io_err(label, e))?;
                }
                verify_dir(fd.as_fd(), self.owner_uid, self.owner_gid, DIR_MODE, label)?;
                Ok(fd)
            }
            Err(e) => Err(dir_open_err(label, e)),
        }
    }

    fn open_dir_read(
        &self,
        parent: BorrowedFd<'_>,
        name: &str,
        label: &str,
    ) -> Result<Option<OwnedFd>, RegistryError> {
        match openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                verify_dir(fd.as_fd(), self.owner_uid, self.owner_gid, DIR_MODE, label)?;
                Ok(Some(fd))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(dir_open_err(label, e)),
        }
    }

    /// Open and read one device file with full safety checks. Maps ENOENT to `NotRegistered`.
    fn read_device_file(
        &self,
        devices: BorrowedFd<'_>,
        name: &str,
    ) -> Result<Vec<u8>, RegistryError> {
        let fd = match openat(
            devices,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Err(RegistryError::NotRegistered),
            Err(Errno::LOOP) => {
                return Err(RegistryError::Unsafe {
                    path: name.to_string(),
                    reason: "device file is a symlink".to_string(),
                });
            }
            Err(e) => return Err(io_err(name, e)),
        };
        // Regular file, expected owner, exact 0640, single link (no surprise hardlink).
        verify_regular(fd.as_fd(), self.owner_uid, self.owner_gid, FILE_MODE, name)?;
        let st = fstat(fd.as_fd()).map_err(|e| io_err(name, e))?;
        if st.st_size < 0 || st.st_size as u64 > MAX_RECORD_FILE {
            return Err(RegistryError::Corrupt {
                path: name.to_string(),
                reason: "device file exceeds the size cap".to_string(),
            });
        }
        let expected = st.st_size as u64;
        let mut buf = Vec::with_capacity(expected as usize);
        // Cap the read defensively; then require the byte count to equal the fstat size, so a concurrent
        // non-cooperative writer's truncation/growth (outside our lock) fails closed rather than decoding
        // a torn record.
        std::fs::File::from(fd)
            .take(MAX_RECORD_FILE)
            .read_to_end(&mut buf)
            .map_err(|source| RegistryError::Io {
                path: name.to_string(),
                source,
            })?;
        if buf.len() as u64 != expected {
            return Err(RegistryError::Corrupt {
                path: name.to_string(),
                reason: "device file size changed during read".to_string(),
            });
        }
        Ok(buf)
    }

    fn enumerate_all(&self) -> Result<Vec<DeviceRecord>, RegistryError> {
        // The base directory is intentionally *not* enumerated: it may hold reserved siblings now
        // (`.registry.lock`) and in future (`verifier_key`, plan D6), so only the `users/` subtree is
        // swept. Every `users/` entry must be a canonical uid directory or the whole read fails closed.
        let Some(users) = self.open_dir_read(self.base.as_fd(), "users", "users")? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for name in dir_entries(users.as_fd(), "users")? {
            let uid = parse_uid_dirname(&name).ok_or_else(|| RegistryError::Unsafe {
                path: format!("users/{}", name.to_string_lossy()),
                reason: "non-canonical uid directory name".to_string(),
            })?;
            out.extend(self.read_one_user(users.as_fd(), uid, name_str(&name)?)?);
        }
        Ok(out)
    }

    /// Read one `users/<uid>/devices/` subtree, rejecting anything unexpected. The `users/<uid>` directory
    /// must contain **only** a `devices` entry (any sibling — a stray file, a `.registry.lock`, another
    /// directory — fails closed). A missing `devices` (an empty user directory) yields no records.
    fn read_one_user(
        &self,
        users: BorrowedFd<'_>,
        uid: u32,
        uid_name: &str,
    ) -> Result<Vec<DeviceRecord>, RegistryError> {
        let uid_label = format!("users/{uid_name}");
        let Some(user_dir) = self.open_dir_read(users, uid_name, &uid_label)? else {
            return Ok(Vec::new());
        };
        for name in dir_entries(user_dir.as_fd(), &uid_label)? {
            if name.to_bytes() != b"devices" {
                return Err(RegistryError::Unsafe {
                    path: format!("{uid_label}/{}", name.to_string_lossy()),
                    reason: "unexpected entry beside devices".to_string(),
                });
            }
        }
        let devices_label = format!("{uid_label}/devices");
        let Some(devices) = self.open_dir_read(user_dir.as_fd(), "devices", &devices_label)? else {
            return Ok(Vec::new());
        };
        self.read_devices_dir(devices.as_fd(), uid, &devices_label)
    }

    /// Read and validate every device file in one user's `devices/` directory.
    fn read_devices_dir(
        &self,
        devices: BorrowedFd<'_>,
        uid: u32,
        label: &str,
    ) -> Result<Vec<DeviceRecord>, RegistryError> {
        let mut out = Vec::new();
        for name in dir_entries(devices, label)? {
            let name_s = name_str(&name)?;
            let device_id = parse_device_filename(name_s).ok_or_else(|| RegistryError::Unsafe {
                path: format!("{label}/{name_s}"),
                reason: "unexpected entry in devices directory".to_string(),
            })?;
            let bytes = self.read_device_file(devices, name_s)?;
            let record = decode_record(&bytes, uid, device_id, name_s)?;
            out.push(record);
        }
        Ok(out)
    }
}

/// Open the (possibly not-yet-existing) base directory, creating it 0700 if absent.
fn open_or_create_base(path: &Path, label: &str) -> Result<OwnedFd, RegistryError> {
    match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(fd),
        Err(Errno::NOENT) => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(DIR_MODE)
                .create(path)
                .map_err(|source| RegistryError::Io {
                    path: label.to_string(),
                    source,
                })?;
            rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| dir_open_err(label, e))
        }
        Err(Errno::LOOP) => Err(RegistryError::Unsafe {
            path: label.to_string(),
            reason: "base directory is a symlink".to_string(),
        }),
        Err(e) => Err(io_err(label, e)),
    }
}

/// Publish `bytes` to `final_name` in `dir` via a temp file: create O_EXCL, write, fchmod, fsync, then
/// rename (with `rename_flags`; `RENAME_NOREPLACE` for a non-clobbering register), then fsync the dir.
/// The temp is unlinked on any failure. `EEXIST` from a `RENAME_NOREPLACE` becomes `AlreadyRegistered`.
fn publish(
    dir: BorrowedFd<'_>,
    final_name: &str,
    bytes: &[u8],
    rename_flags: RenameFlags,
    base_label: &str,
) -> Result<(), RegistryError> {
    let rand = crypto::csprng::random_bytes::<16>().map_err(|_| RegistryError::Rng)?;
    let tmp_name = format!("{TEMP_PREFIX}{}", hex(&rand));
    let fd = openat(
        dir,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
    )
    .map_err(|e| io_err(&tmp_name, e))?;
    let mut guard = TempGuard {
        dir,
        name: tmp_name.clone(),
        armed: true,
    };
    let write_result = (|| {
        let mut f = std::fs::File::from(fd);
        f.write_all(bytes)?;
        rustix::fs::fchmod(f.as_fd(), Mode::from_raw_mode(FILE_MODE))
            .map_err(std::io::Error::from)?;
        f.sync_all()?; // fsync the file contents + metadata before publishing
        Ok::<(), std::io::Error>(())
    })();
    if let Err(source) = write_result {
        return Err(RegistryError::Io {
            path: tmp_name,
            source,
        });
    }
    match renameat_with(dir, tmp_name.as_str(), dir, final_name, rename_flags) {
        Ok(()) => {
            // The rename published the record (and, for a replace, removed the temp); disarm so the guard
            // does not unlink the now-published name.
            guard.disarm();
            // The directory fsync makes the rename durable. If it fails the change is already applied, so
            // report DurabilityUncertain (not a plain error) — a retry would hit AlreadyRegistered/Revoked.
            rustix::fs::fsync(dir).map_err(|e| RegistryError::DurabilityUncertain {
                path: base_label.to_string(),
                source: std::io::Error::from_raw_os_error(e.raw_os_error()),
            })?;
            Ok(())
        }
        Err(Errno::EXIST) => Err(RegistryError::AlreadyRegistered),
        Err(e) => Err(io_err(final_name, e)),
    }
}

/// An `Unsafe` error for `label` with `reason`.
fn unsafe_err(label: &str, reason: &str) -> RegistryError {
    RegistryError::Unsafe {
        path: label.to_string(),
        reason: reason.to_string(),
    }
}

/// Verify owner uid/gid and an **exact** permission/special-bit mode. The mode is compared strictly
/// (not just "no group/world write") so a loosened `0755`/`0644`/`0644`-lock, an unexpected setuid/setgid/
/// sticky bit, or a group/world-readable relaxation all fail closed (plan D2: dir 0700 / file 0640 /
/// lock 0600 are fixed).
fn verify_owner_mode(
    st: &rustix::fs::Stat,
    owner_uid: u32,
    owner_gid: u32,
    expected_mode: u32,
    label: &str,
) -> Result<(), RegistryError> {
    if st.st_uid != owner_uid || st.st_gid != owner_gid {
        return Err(unsafe_err(label, "unexpected owner"));
    }
    if Mode::from_raw_mode(st.st_mode).bits() != expected_mode {
        return Err(unsafe_err(label, "unexpected permission bits"));
    }
    Ok(())
}

fn verify_dir(
    fd: BorrowedFd<'_>,
    owner_uid: u32,
    owner_gid: u32,
    expected_mode: u32,
    label: &str,
) -> Result<(), RegistryError> {
    let st = fstat(fd).map_err(|e| io_err(label, e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(unsafe_err(label, "not a directory"));
    }
    verify_owner_mode(&st, owner_uid, owner_gid, expected_mode, label)
}

/// fstat-verify a regular file fd: regular, expected owner, exact mode, exactly one link.
fn verify_regular(
    fd: BorrowedFd<'_>,
    owner_uid: u32,
    owner_gid: u32,
    expected_mode: u32,
    label: &str,
) -> Result<(), RegistryError> {
    let st = fstat(fd).map_err(|e| io_err(label, e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(unsafe_err(label, "not a regular file"));
    }
    verify_owner_mode(&st, owner_uid, owner_gid, expected_mode, label)?;
    if st.st_nlink != 1 {
        return Err(unsafe_err(label, "unexpected hard links"));
    }
    Ok(())
}

/// Collect a directory's entry names (excluding only `.` and `..`). The reserved lock file lives at the
/// base directory, which is never enumerated, so any `.registry.lock` (or other unexpected name) appearing
/// inside `users/`/`devices/` is returned to the caller and rejected there — nothing is silently skipped.
fn dir_entries(dirfd: BorrowedFd<'_>, label: &str) -> Result<Vec<CString>, RegistryError> {
    let dir = Dir::read_from(dirfd).map_err(|e| io_err(label, e))?;
    let mut names = Vec::new();
    for entry in dir {
        let entry = entry.map_err(|e| io_err(label, e))?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn name_str(name: &CStr) -> Result<&str, RegistryError> {
    name.to_str().map_err(|_| RegistryError::Unsafe {
        path: name.to_string_lossy().into_owned(),
        reason: "non-UTF-8 entry name".to_string(),
    })
}

/// An RAII guard that unlinks an in-progress temp file unless disarmed (publish succeeded).
struct TempGuard<'a> {
    dir: BorrowedFd<'a>,
    name: String,
    armed: bool,
}

impl TempGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.dir, self.name.as_str(), AtFlags::empty());
        }
    }
}

/// An RAII guard that releases the registry-wide advisory lock on drop.
struct LockGuard {
    fd: OwnedFd,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Best-effort explicit unlock; the lock is also released when the fd closes right after.
        let _ = flock(self.fd.as_fd(), FlockOperation::Unlock);
    }
}

// ---- record (de)serialization: canonical CBOR ----

fn encode_record(r: &DeviceRecord) -> Vec<u8> {
    let mut entries = vec![
        (0u64, Value::Uint(RECORD_VERSION)),
        (1, Value::Uint(u64::from(r.uid))),
        (2, Value::Bytes(r.device_id.to_vec())),
        (3, Value::Bytes(r.sec1.clone())),
        (4, Value::Text(r.label.clone())),
        (5, Value::Uint(r.created_at)),
    ];
    if let Some(t) = r.revoked_at {
        entries.push((6, Value::Uint(t)));
    }
    cbor::encode(&Value::Map(entries))
}

fn decode_record(
    bytes: &[u8],
    expect_uid: u32,
    expect_device_id: [u8; DEVICE_ID_LEN],
    path: &str,
) -> Result<DeviceRecord, RegistryError> {
    let corrupt = |reason: &str| RegistryError::Corrupt {
        path: path.to_string(),
        reason: reason.to_string(),
    };
    let value =
        cbor::scan_structure(bytes, record_limits()).map_err(|_| corrupt("invalid CBOR"))?;
    let Value::Map(entries) = value else {
        return Err(corrupt("record is not a map"));
    };
    let mut version = None;
    let mut uid = None;
    let mut device_id = None;
    let mut sec1 = None;
    let mut label = None;
    let mut created_at = None;
    let mut revoked_at = None;
    // Keys are canonical (ascending, unique) by construction of scan_structure; reject any unknown key.
    for (k, v) in &entries {
        match k {
            0 => version = Some(as_uint(v).ok_or_else(|| corrupt("bad version"))?),
            1 => uid = Some(as_uint(v).ok_or_else(|| corrupt("bad uid"))?),
            2 => device_id = Some(as_bytes(v).ok_or_else(|| corrupt("bad device_id"))?),
            3 => sec1 = Some(as_bytes(v).ok_or_else(|| corrupt("bad sec1"))?),
            4 => label = Some(as_text(v).ok_or_else(|| corrupt("bad label"))?),
            5 => created_at = Some(as_uint(v).ok_or_else(|| corrupt("bad created_at"))?),
            6 => revoked_at = Some(as_uint(v).ok_or_else(|| corrupt("bad revoked_at"))?),
            _ => return Err(corrupt("unknown key")),
        }
    }
    if version != Some(RECORD_VERSION) {
        return Err(corrupt("unsupported version"));
    }
    let uid = uid.ok_or_else(|| corrupt("missing uid"))?;
    let uid = u32::try_from(uid).map_err(|_| corrupt("uid out of range"))?;
    if uid > UID_MAX {
        return Err(corrupt("uid out of range"));
    }
    if uid != expect_uid {
        return Err(corrupt("uid does not match its directory"));
    }
    let device_id = device_id.ok_or_else(|| corrupt("missing device_id"))?;
    let device_id: [u8; DEVICE_ID_LEN] = device_id
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("device_id length"))?;
    if device_id != expect_device_id {
        return Err(corrupt("device_id does not match its filename"));
    }
    let sec1 = sec1.ok_or_else(|| corrupt("missing sec1"))?;
    if sec1.len() > SEC1_MAX_BYTES {
        return Err(corrupt("sec1 too long"));
    }
    crypto::p256_ecdsa::validate_public_key(&sec1).map_err(|_| corrupt("sec1 not a P-256 key"))?;
    let label = label.ok_or_else(|| corrupt("missing label"))?;
    // Enforce the full text policy on the stored label too, so a tampered on-disk record with control /
    // bidi / non-NFC bytes fails closed instead of reaching `list` output.
    text::check(&label, 0, LABEL_MAX_BYTES, false)
        .map_err(|_| corrupt("label violates text policy"))?;
    let created_at = created_at.ok_or_else(|| corrupt("missing created_at"))?;
    Ok(DeviceRecord {
        uid,
        device_id,
        sec1,
        label,
        created_at,
        revoked_at,
    })
}

fn as_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Uint(n) => Some(*n),
        _ => None,
    }
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

// ---- validation + filename helpers ----

fn validate_uid(uid: u32) -> Result<(), String> {
    if uid > UID_MAX {
        return Err("uid is (uid_t)-1".to_string());
    }
    Ok(())
}

/// Validate a label under the shared text policy (NUL/C0/C1 control, bidi controls, Unicode 16.0
/// unassigned, and non-NFC are all rejected), length 0..=128 (empty = "no label"). Using the same
/// `bifrauth_proto::text` policy as the wire messages keeps `list` output free of terminal escapes,
/// line breaks, and bidi/spoofing tricks.
fn validate_label(label: &str) -> Result<(), RegistryError> {
    text::check(label, 0, LABEL_MAX_BYTES, false).map_err(|_| RegistryError::InvalidLabel)
}

/// The canonical device filename for a device id: 32 lowercase hex chars + ".cbor".
fn device_filename(device_id: &[u8; DEVICE_ID_LEN]) -> String {
    format!("{}.cbor", hex(device_id))
}

/// Parse a canonical device filename back to its device id, or None if non-canonical.
fn parse_device_filename(name: &str) -> Option<[u8; DEVICE_ID_LEN]> {
    let stem = name.strip_suffix(".cbor")?;
    parse_hex16(stem)
}

/// Parse a canonical decimal uid directory name (no leading zeros, in range).
fn parse_uid_dirname(name: &CStr) -> Option<u32> {
    let s = name.to_str().ok()?;
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let uid: u32 = s.parse().ok()?;
    if uid > UID_MAX {
        return None;
    }
    Some(uid)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Parse exactly 32 lowercase hex characters into 16 bytes. Rejects uppercase (non-canonical).
fn parse_hex16(s: &str) -> Option<[u8; DEVICE_ID_LEN]> {
    if s.len() != DEVICE_ID_LEN * 2 {
        return None;
    }
    let mut out = [0u8; DEVICE_ID_LEN];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// A single lowercase-hex nibble (uppercase rejected to keep filenames canonical).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Public hex helpers for CLI input parsing (device id / SEC1 key), so the CLI shares one hex codec.
pub mod hexcodec {
    /// Encode bytes as lowercase hex.
    pub fn encode(bytes: &[u8]) -> String {
        super::hex(bytes)
    }

    /// Decode a lowercase-or-uppercase hex string into bytes (CLI input tolerance). Returns None on any
    /// non-hex character or odd length.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for chunk in bytes.chunks_exact(2) {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }

    /// Decode a hex string into exactly 16 bytes (a device id).
    pub fn decode16(s: &str) -> Option<[u8; 16]> {
        let v = decode(s)?;
        v.as_slice().try_into().ok()
    }

    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

fn lock_open_err(path: &str, e: Errno) -> RegistryError {
    if e == Errno::LOOP {
        RegistryError::Unsafe {
            path: path.to_string(),
            reason: "lock file is a symlink".to_string(),
        }
    } else {
        io_err(path, e)
    }
}

fn dir_open_err(label: &str, e: Errno) -> RegistryError {
    // O_NOFOLLOW|O_DIRECTORY on a symlink yields ELOOP or (when the un-followed link is not a directory)
    // ENOTDIR; either way a directory component was replaced by something else -> fail closed.
    if e == Errno::LOOP || e == Errno::NOTDIR {
        RegistryError::Unsafe {
            path: label.to_string(),
            reason: "directory component is a symlink or non-directory".to_string(),
        }
    } else {
        io_err(label, e)
    }
}

#[cfg(test)]
mod tests {
    //! On-disk safety, concurrency, and schema tests. They run unprivileged against a temp directory the
    //! test user owns, via the cfg(test)-only `open_with_owner`, so the symlink/mode/traversal checks are
    //! still exercised (ownership is the only environment-dependent check).
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::PathBuf;
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

    struct TempBase {
        path: PathBuf,
    }

    impl TempBase {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bifrauth-reg-test-{}-{}",
                std::process::id(),
                n
            ));
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

    const T_UID: u32 = 4242;
    const DEV_A: [u8; 16] = [0xA1; 16];
    const DEV_B: [u8; 16] = [0xB2; 16];

    #[test]
    fn register_list_roundtrip_and_load_snapshot() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "phone", 1000)
            .unwrap();

        let list = reg.list(T_UID).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].device_id, DEV_A);
        assert_eq!(list[0].label, "phone");
        assert_eq!(list[0].created_at, 1000);
        assert!(!list[0].is_revoked());

        let mut v = crate::Verifier::new([0x03; 32], crate::BoottimeClock);
        v.replace_devices(reg.load_all().unwrap()).unwrap();
    }

    #[test]
    fn register_duplicate_is_rejected_without_changing_bytes() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "first", 1000)
            .unwrap();
        let before = std::fs::read(base.devices_dir(T_UID).join(device_filename(&DEV_A))).unwrap();

        let err = reg
            .register(T_UID, DEV_A, &sec1_key(2), "second", 2000)
            .unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered));
        let after = std::fs::read(base.devices_dir(T_UID).join(device_filename(&DEV_A))).unwrap();
        assert_eq!(before, after, "duplicate register must not overwrite");
    }

    #[test]
    fn revoke_is_one_way_and_preserves_bytes_on_repeat() {
        let base = TempBase::new();
        let reg = base.open();
        assert!(matches!(
            reg.revoke(T_UID, DEV_A, 500).unwrap_err(),
            RegistryError::NotRegistered
        ));

        reg.register(T_UID, DEV_A, &sec1_key(1), "phone", 1000)
            .unwrap();
        reg.revoke(T_UID, DEV_A, 2000).unwrap();
        assert_eq!(reg.list(T_UID).unwrap()[0].revoked_at, Some(2000));

        let before = std::fs::read(base.devices_dir(T_UID).join(device_filename(&DEV_A))).unwrap();
        assert!(matches!(
            reg.revoke(T_UID, DEV_A, 3000).unwrap_err(),
            RegistryError::AlreadyRevoked
        ));
        let after = std::fs::read(base.devices_dir(T_UID).join(device_filename(&DEV_A))).unwrap();
        assert_eq!(before, after);

        assert!(matches!(
            reg.register(T_UID, DEV_A, &sec1_key(9), "new", 4000)
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
                reg.register(T_UID, DEV_A, &sec1_key(seed.max(1)), "x", 1000)
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
            "renameat2(RENAME_NOREPLACE) + flock admit exactly one register (OFD mutual exclusion)"
        );
        assert_eq!(base.open().list(T_UID).unwrap().len(), 1);
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
                reg.register(T_UID, id, &sec1_key(seed), "x", 1000).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let reg = base.open();
        assert_eq!(reg.list(T_UID).unwrap().len(), 16);
        let mut v = crate::Verifier::new([0x03; 32], crate::BoottimeClock);
        v.replace_devices(reg.load_all().unwrap()).unwrap();
    }

    #[test]
    fn intermediate_directory_symlink_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();

        let devices = base.devices_dir(T_UID);
        let evil = base.path.join("evil");
        std::fs::create_dir(&evil).unwrap();
        std::fs::remove_dir_all(&devices).unwrap();
        symlink(&evil, &devices).unwrap();

        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn device_file_symlink_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();

        let file = base.devices_dir(T_UID).join(device_filename(&DEV_A));
        let target = base.path.join("secret");
        std::fs::write(&target, b"whatever").unwrap();
        std::fs::remove_file(&file).unwrap();
        symlink(&target, &file).unwrap();

        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn non_regular_device_entry_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::create_dir(base.devices_dir(T_UID).join(device_filename(&DEV_B))).unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn unexpected_entry_in_devices_dir_fails_closed() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::write(base.devices_dir(T_UID).join("garbage.txt"), b"junk").unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn reserved_lock_name_inside_devices_dir_is_not_silently_skipped() {
        // A file literally named .registry.lock inside a devices dir must fail closed (it is only reserved
        // at the base directory, which is never enumerated).
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::write(base.devices_dir(T_UID).join(LOCK_NAME), b"x").unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn unexpected_sibling_beside_devices_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        // A stray file next to `devices` inside users/<uid> must fail closed.
        std::fs::write(
            base.path.join("users").join(T_UID.to_string()).join("note"),
            b"x",
        )
        .unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn hardlinked_device_file_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        let a = base.devices_dir(T_UID).join(device_filename(&DEV_A));
        let b = base.devices_dir(T_UID).join(device_filename(&DEV_B));
        std::fs::hard_link(&a, &b).unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    // Write a device file at the canonical name with the exact expected modes (dir 0700 / file 0640) so
    // reads reach the decode/size checks rather than tripping the strict mode check first.
    fn write_device_file(dir: &std::path::Path, id: &[u8; 16], bytes: &[u8]) {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(dir)
            .unwrap();
        let p = dir.join(device_filename(id));
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    #[test]
    fn corrupt_and_oversize_records_fail_closed() {
        let base = TempBase::new();
        let reg = base.open();
        let dev_dir = base.devices_dir(T_UID);
        write_device_file(&dev_dir, &DEV_A, b"\xff\xff\xff\xff");
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Corrupt { .. }
        ));
        write_device_file(&dev_dir, &DEV_A, &vec![0u8; 5000]);
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Corrupt { .. }
        ));
    }

    #[test]
    fn non_canonical_uid_directory_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::create_dir_all(base.path.join("users").join("007").join("devices")).unwrap();
        assert!(matches!(
            reg.list_all().unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn lock_file_symlink_is_rejected() {
        let base = TempBase::new();
        let target = base.path.join("lock-target");
        std::fs::write(&target, b"x").unwrap();
        symlink(&target, base.path.join(LOCK_NAME)).unwrap();
        let reg = base.open();
        assert!(matches!(
            reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000)
                .unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn group_writable_lock_file_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::set_permissions(
            base.path.join(LOCK_NAME),
            std::fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn group_readable_device_file_is_rejected() {
        // Strict mode: a device file loosened to 0644 (group/world readable) must fail closed, not just
        // group/world *writable* (the record could contain no secret, but the fixed-mode invariant guards
        // against tampering more broadly).
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::set_permissions(
            base.devices_dir(T_UID).join(device_filename(&DEV_A)),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn loosened_directory_mode_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        reg.register(T_UID, DEV_A, &sec1_key(1), "x", 1000).unwrap();
        std::fs::set_permissions(
            base.devices_dir(T_UID),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Unsafe { .. }
        ));
    }

    #[test]
    fn label_text_policy_on_register() {
        let base = TempBase::new();
        let reg = base.open();
        // Empty label is allowed (means "no label").
        reg.register(T_UID, DEV_A, &sec1_key(1), "", 1000).unwrap();
        assert_eq!(reg.list(T_UID).unwrap()[0].label, "");
        // Control chars, bidi override, and overlong labels are rejected.
        for bad in ["bad\nname", "a\u{202e}b", &"x".repeat(200)] {
            assert!(
                matches!(
                    reg.register(T_UID, DEV_B, &sec1_key(2), bad, 1000)
                        .unwrap_err(),
                    RegistryError::InvalidLabel
                ),
                "label {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn tampered_label_on_disk_fails_closed() {
        // A hand-written record carrying a bidi/control label must be rejected by load/list so it never
        // reaches terminal output.
        let base = TempBase::new();
        let reg = base.open();
        let dev_dir = base.devices_dir(T_UID);
        // Build a record whose label contains an RLO override (a valid CBOR record, invalid text policy).
        let rec = DeviceRecord {
            uid: T_UID,
            device_id: DEV_A,
            sec1: sec1_key(1),
            label: "a\u{202e}b".to_string(),
            created_at: 1000,
            revoked_at: None,
        };
        write_device_file(&dev_dir, &DEV_A, &encode_record(&rec));
        assert!(matches!(
            reg.list(T_UID).unwrap_err(),
            RegistryError::Corrupt { .. }
        ));
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let base = TempBase::new();
        let reg = base.open();
        assert!(matches!(
            reg.register(T_UID, DEV_A, &[0u8; 5], "x", 1000)
                .unwrap_err(),
            RegistryError::InvalidPublicKey
        ));
    }
}
