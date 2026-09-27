//! Root-only, plaintext-on-disk SQLite vault. This is NOT encryption at rest.
//!
//! `Store::open` protects files for the current effective UID (root in production).
//! Ancestors must be owned by root or that UID and not writable by other users;
//! root-owned sticky directories such as `/tmp` are allowed. The state directory
//! must be mode 0700 and database/sidecars mode 0600. Existing permissions are
//! never repaired. SQLite uses rollback journals, not WAL. Callers sharing the
//! effective UID are trusted; this cannot protect against root or that UID.
//!
//! The owner UID passed to methods is a namespace, NOT an authenticated identity.
//! Authentication, authorization, and client-to-owner mapping belong to the daemon.

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// Maximum canonical key length in ASCII bytes, including the first dot.
pub const MAX_KEY_LEN: usize = 128;
/// Maximum secret size; empty values and arbitrary bytes are supported.
pub const MAX_SECRET_LEN: usize = 64 * 1024;
/// The database filename within the protected state directory.
pub const DATABASE_NAME: &str = "vault.sqlite3";
const APPLICATION_ID: i64 = 0x414b5654;
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "CREATE TABLE entries (
    owner_uid INTEGER NOT NULL CHECK(typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    key TEXT NOT NULL CHECK(typeof(key) = 'text' AND length(CAST(key AS BLOB)) BETWEEN 3 AND 128),
    version INTEGER NOT NULL CHECK(typeof(version) = 'integer' AND version BETWEEN 1 AND 9223372036854775807),
    deleted INTEGER NOT NULL CHECK(typeof(deleted) = 'integer' AND deleted IN (0, 1)),
    value BLOB,
    PRIMARY KEY (owner_uid, key),
    CHECK((deleted = 1 AND value IS NULL) OR (deleted = 0 AND typeof(value) = 'blob' AND length(value) <= 65536))
) WITHOUT ROWID";

pub type Result<T> = std::result::Result<T, Error>;

/// Errors never contain secret values. SQL/I/O failures are kept as sources.
#[derive(Debug)]
pub enum Error {
    InvalidKey,
    SecretTooLarge,
    InvalidVersion,
    AlreadyExists,
    NotFound,
    Tombstoned,
    VersionConflict { expected: u64, actual: u64 },
    VersionExhausted,
    UnsafePath(String),
    MalformedState(String),
    Io(io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(
                f,
                "invalid application.label key (maximum {MAX_KEY_LEN} ASCII bytes)"
            ),
            Self::SecretTooLarge => write!(f, "secret exceeds {MAX_SECRET_LEN} bytes"),
            Self::InvalidVersion => f.write_str("version must be between 1 and i64::MAX"),
            Self::AlreadyExists => {
                f.write_str("key has already been created (possibly tombstoned)")
            }
            Self::NotFound => f.write_str("key does not exist"),
            Self::Tombstoned => f.write_str("key has been deleted"),
            Self::VersionConflict { expected, actual } => {
                write!(f, "version conflict: expected {expected}, found {actual}")
            }
            Self::VersionExhausted => f.write_str("version counter exhausted"),
            Self::UnsafePath(reason) => write!(f, "unsafe vault path: {reason}"),
            Self::MalformedState(reason) => write!(f, "malformed vault state: {reason}"),
            Self::Io(error) => write!(f, "vault I/O error: {error}"),
            Self::Sqlite(error) => write!(f, "vault SQLite error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Owned secret bytes, zeroized on drop. Debug output is always redacted.
/// SQLite's internal buffers, OS page cache, and caller-owned inputs are not wiped.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[derive(Debug)]
pub struct Record {
    pub version: u64,
    pub secret: Secret,
}

/// Non-secret metadata. Tombstones remain visible to administrative callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub owner_uid: u32,
    pub key: String,
    pub version: u64,
    pub deleted: bool,
}

/// Validate, without normalization, a case-sensitive `application.label` key.
/// Application and each dot-separated label component must be nonempty and
/// contain only ASCII letters, digits, `_`, or `-`. The first dot separates the
/// application; further dots belong to the label. Whitespace/Unicode are rejected.
pub fn validate_key(key: &str) -> Result<()> {
    if key.len() > MAX_KEY_LEN
        || !key.contains('.')
        || key.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// A connection to a protected vault. Open one connection per concurrent worker.
/// Mutations use IMMEDIATE transactions and wait up to five seconds for locks.
pub struct Store {
    connection: Connection,
    // Keep the descriptor alive for the /proc/self/fd SQLite path and sidecars.
    directory: File,
}

impl Store {
    /// Open or create the last directory component and initialize the database.
    /// All ancestors must already exist. Symlinks and `..` components are refused.
    /// Uses Linux `/proc/self/fd` to anchor SQLite paths to the validated directory.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let directory = open_directory(state_dir.as_ref())?;
        let database = open_database_file(&directory)?;
        validate_sidecars(&directory)?;
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory.as_raw_fd(),
            DATABASE_NAME
        ));
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        // Check before changing journal modes: a WAL database is not our format.
        let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(Error::MalformedState(
                "only DELETE rollback journaling is supported".into(),
            ));
        }
        connection.execute_batch(
            "PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;",
        )?;
        initialize(&mut connection)?;
        let reopened = open_existing(&directory, OsStr::new(DATABASE_NAME))?;
        let original_stat = stat(&database)?;
        let reopened_stat = stat(&reopened)?;
        if original_stat.st_dev != reopened_stat.st_dev
            || original_stat.st_ino != reopened_stat.st_ino
        {
            return Err(Error::UnsafePath("database changed while opening".into()));
        }
        validate_file(&reopened, "database")?;
        validate_sidecars(&directory)?;
        Ok(Self {
            connection,
            directory,
        })
    }

    /// Insert only if this owner/key has never existed, including as a tombstone.
    /// Values are borrowed; callers are responsible for wiping their own buffers.
    pub fn create(&mut self, owner_uid: u32, key: &str, value: &[u8]) -> Result<Metadata> {
        validate_key(key)?;
        validate_value(value)?;
        self.check_files()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "INSERT INTO entries (owner_uid, key, version, deleted, value) VALUES (?1, ?2, 1, 0, ?3) ON CONFLICT(owner_uid, key) DO NOTHING",
            params![owner_uid, key, value],
        )?;
        if changed != 1 {
            return Err(Error::AlreadyExists);
        }
        tx.commit()?;
        Ok(Metadata {
            owner_uid,
            key: key.into(),
            version: 1,
            deleted: false,
        })
    }

    /// Read an active value; deleted keys return `Tombstoned`, unknown keys `NotFound`.
    pub fn read(&self, owner_uid: u32, key: &str) -> Result<Record> {
        validate_key(key)?;
        self.check_files()?;
        let result = self
            .connection
            .query_row(
                "SELECT version, deleted, value FROM entries WHERE owner_uid = ?1 AND key = ?2",
                params![owner_uid, key],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?.map(Zeroizing::new),
                    ))
                },
            )
            .optional()?;
        match result {
            None => Err(Error::NotFound),
            Some((_, true, _)) => Err(Error::Tombstoned),
            Some((version, false, Some(value))) => Ok(Record {
                version,
                secret: Secret(value),
            }),
            _ => Err(Error::MalformedState("active entry has no value".into())),
        }
    }

    /// Atomically replace an active value only at the expected version.
    pub fn replace(
        &mut self,
        owner_uid: u32,
        key: &str,
        expected_version: u64,
        value: &[u8],
    ) -> Result<Metadata> {
        validate_key(key)?;
        validate_value(value)?;
        if expected_version == 0 || expected_version > i64::MAX as u64 {
            return Err(Error::InvalidVersion);
        }
        self.check_files()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (version, deleted) = lookup_version(&tx, owner_uid, key)?;
        if deleted {
            return Err(Error::Tombstoned);
        }
        if version != expected_version {
            return Err(Error::VersionConflict {
                expected: expected_version,
                actual: version,
            });
        }
        let next = increment_version(version)?;
        tx.execute("UPDATE entries SET value = ?3, version = ?4 WHERE owner_uid = ?1 AND key = ?2 AND version = ?5",
            params![owner_uid, key, value, next, version])?;
        tx.commit()?;
        Ok(Metadata {
            owner_uid,
            key: key.into(),
            version: next,
            deleted: false,
        })
    }

    /// Administrative delete: retain the key forever as a versioned tombstone.
    /// Already-deleted keys return `Tombstoned`. No authorization is done here.
    /// This is logical deletion, not a guarantee of forensic erasure or backup removal.
    pub fn delete(&mut self, owner_uid: u32, key: &str) -> Result<Metadata> {
        validate_key(key)?;
        self.check_files()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (version, deleted) = lookup_version(&tx, owner_uid, key)?;
        if deleted {
            return Err(Error::Tombstoned);
        }
        let next = increment_version(version)?;
        tx.execute("UPDATE entries SET value = NULL, deleted = 1, version = ?3 WHERE owner_uid = ?1 AND key = ?2",
            params![owner_uid, key, next])?;
        tx.commit()?;
        Ok(Metadata {
            owner_uid,
            key: key.into(),
            version: next,
            deleted: true,
        })
    }

    /// Fetch one key's metadata, including a tombstone, without selecting its value.
    pub fn metadata(&self, owner_uid: u32, key: &str) -> Result<Metadata> {
        validate_key(key)?;
        self.check_files()?;
        let (version, deleted) = lookup_version(&self.connection, owner_uid, key)?;
        Ok(Metadata {
            owner_uid,
            key: key.into(),
            version,
            deleted,
        })
    }

    /// List this owner's metadata, including tombstones, ordered by case-sensitive key.
    pub fn list_metadata(&self, owner_uid: u32) -> Result<Vec<Metadata>> {
        self.check_files()?;
        let mut statement = self.connection.prepare(
            "SELECT key, version, deleted FROM entries WHERE owner_uid = ?1 ORDER BY key",
        )?;
        let rows = statement.query_map([owner_uid], |row| {
            Ok(Metadata {
                owner_uid,
                key: row.get(0)?,
                version: row.get(1)?,
                deleted: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn check_files(&self) -> Result<()> {
        validate_directory(&self.directory, true)?;
        let file = open_existing(&self.directory, OsStr::new(DATABASE_NAME))?;
        validate_file(&file, "database")?;
        validate_sidecars(&self.directory)
    }
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_SECRET_LEN {
        Err(Error::SecretTooLarge)
    } else {
        Ok(())
    }
}

fn increment_version(version: u64) -> Result<u64> {
    if version >= i64::MAX as u64 {
        Err(Error::VersionExhausted)
    } else {
        Ok(version + 1)
    }
}

fn lookup_version(connection: &Connection, owner_uid: u32, key: &str) -> Result<(u64, bool)> {
    connection
        .query_row(
            "SELECT version, deleted FROM entries WHERE owner_uid = ?1 AND key = ?2",
            params![owner_uid, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)
}

fn initialize(connection: &mut Connection) -> Result<()> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema: Vec<(String, String, String)> = {
        let mut statement = tx.prepare("SELECT type, name, coalesce(sql, '') FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name")?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if version == 0 && application == 0 && schema.is_empty() {
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    } else if version != SCHEMA_VERSION
        || application != APPLICATION_ID
        || schema != vec![("table".into(), "entries".into(), SCHEMA.into())]
    {
        return Err(Error::MalformedState(
            "unrecognized schema or format version".into(),
        ));
    }
    // quick_check includes CHECK constraints, storage types, and page consistency.
    let integrity: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::MalformedState(
            "SQLite integrity check failed".into(),
        ));
    }
    {
        let mut statement = tx.prepare("SELECT key FROM entries")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            if validate_key(&key).is_err() {
                return Err(Error::MalformedState("invalid stored key".into()));
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn c_name(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error::UnsafePath("NUL in path".into()))
}

fn stat(file: &File) -> Result<libc::stat> {
    let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: result is writable and fd remains live throughout fstat.
    if unsafe { libc::fstat(file.as_raw_fd(), result.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: a successful fstat initialized the structure.
    Ok(unsafe { result.assume_init() })
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn validate_directory(file: &File, final_component: bool) -> Result<()> {
    let info = stat(file)?;
    let mode = info.st_mode & 0o7777;
    if info.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(Error::UnsafePath("not a directory".into()));
    }
    if final_component {
        if info.st_uid != effective_uid() || mode != 0o700 {
            return Err(Error::UnsafePath(
                "state directory must belong to effective UID with mode 0700".into(),
            ));
        }
    } else {
        if info.st_uid != 0 && info.st_uid != effective_uid() {
            return Err(Error::UnsafePath(
                "ancestor belongs to an untrusted UID".into(),
            ));
        }
        // Sticky root-owned parents prevent untrusted users renaming our child.
        if mode & 0o022 != 0 && !(info.st_uid == 0 && mode & libc::S_ISVTX != 0) {
            return Err(Error::UnsafePath(
                "ancestor is writable by other users".into(),
            ));
        }
    }
    Ok(())
}

fn validate_file(file: &File, label: &str) -> Result<()> {
    let info = stat(file)?;
    if info.st_mode & libc::S_IFMT != libc::S_IFREG
        || info.st_uid != effective_uid()
        || info.st_mode & 0o7777 != 0o600
        || info.st_nlink != 1
    {
        return Err(Error::UnsafePath(format!(
            "{label} must be a regular, singly-linked effective-UID-owned file with mode 0600"
        )));
    }
    Ok(())
}

fn open_at(parent: &File, name: &OsStr, flags: i32, mode: libc::mode_t) -> Result<File> {
    let name = c_name(name)?;
    // SAFETY: the C string and parent fd are live; mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new, uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> Result<File> {
    if path.as_os_str().is_empty() {
        return Err(Error::UnsafePath("empty state directory path".into()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut names = Vec::new();
    for component in absolute.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::RootDir | Component::CurDir => {}
            _ => return Err(Error::UnsafePath("parent traversal is forbidden".into())),
        }
    }
    if names.is_empty() {
        return Err(Error::UnsafePath(
            "root cannot be the state directory".into(),
        ));
    }
    let mut directory = File::open("/")?;
    validate_directory(&directory, false)?;
    for (index, name) in names.iter().enumerate() {
        let last = index + 1 == names.len();
        let opened = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
        let child = match opened {
            Err(Error::Io(error)) if last && error.kind() == io::ErrorKind::NotFound => {
                let name_c = c_name(name)?;
                // SAFETY: both the descriptor and C string are valid.
                if unsafe { libc::mkdirat(directory.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error.into());
                    }
                }
                open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
            }
            other => other?,
        };
        validate_directory(&child, last)?;
        directory = child;
    }
    Ok(directory)
}

fn open_existing(directory: &File, name: &OsStr) -> Result<File> {
    // NONBLOCK avoids blocking on malicious FIFOs before fstat rejects them.
    open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
}

fn open_database_file(directory: &File) -> Result<File> {
    let name = OsStr::new(DATABASE_NAME);
    let file = match open_at(
        directory,
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_existing(directory, name)?
        }
        other => other?,
    };
    validate_file(&file, "database")?;
    Ok(file)
}

fn validate_sidecars(directory: &File) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        match open_existing(directory, OsStr::new(&format!("{DATABASE_NAME}{suffix}"))) {
            Ok(file) => {
                if let Err(error) = validate_file(&file, "SQLite sidecar") {
                    // Another connection may unlink its completed rollback journal
                    // between our open and fstat. An unlinked descriptor is harmless.
                    if suffix == "-journal" && stat(&file)?.st_nlink == 0 {
                        continue;
                    }
                    return Err(error);
                }
                if suffix != "-journal" {
                    return Err(Error::MalformedState("unexpected WAL/SHM sidecar".into()));
                }
            }
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        (temp, path)
    }

    #[test]
    fn key_validation_is_canonical_and_bounded() {
        for key in ["app.label", "App.Label", "a.b.c", "my-app.my_label", "_.-"] {
            validate_key(key).unwrap();
        }
        for key in [
            "",
            "app",
            ".label",
            "app.",
            "app..label",
            "app.label.",
            "app.hello world",
            "app.\n",
            "app.\0",
            "app.é",
            "app./x",
            "app.\\x",
            "app.\u{7f}",
        ] {
            assert!(
                matches!(validate_key(key), Err(Error::InvalidKey)),
                "{key:?}"
            );
        }
        validate_key(&format!("a.{}", "b".repeat(MAX_KEY_LEN - 2))).unwrap();
        assert!(matches!(
            validate_key(&format!("a.{}", "b".repeat(MAX_KEY_LEN - 1))),
            Err(Error::InvalidKey)
        ));
    }

    #[test]
    fn byte_values_duplicates_namespaces_and_redaction() {
        let (_temp, path) = fixture();
        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.create(10, "app.empty", b"").unwrap().version, 1);
        assert_eq!(store.read(10, "app.empty").unwrap().secret.as_bytes(), b"");
        let bytes = b"secret-marker\0\n\xff\r";
        store.create(10, "app.binary", bytes).unwrap();
        let record = store.read(10, "app.binary").unwrap();
        assert_eq!(record.secret.as_bytes(), bytes);
        assert!(!format!("{record:?}").contains("secret-marker"));
        assert!(matches!(
            store.create(10, "app.binary", b"new"),
            Err(Error::AlreadyExists)
        ));
        store.create(11, "app.binary", b"other owner").unwrap();
        store.create(10, "App.binary", b"different case").unwrap();
        assert_eq!(
            store.read(10, "app.binary").unwrap().secret.as_bytes(),
            bytes
        );
        assert_eq!(
            store.read(11, "app.binary").unwrap().secret.as_bytes(),
            b"other owner"
        );
        assert!(matches!(store.read(12, "app.binary"), Err(Error::NotFound)));
        assert_eq!(store.list_metadata(10).unwrap().len(), 3);
        assert_eq!(store.list_metadata(12).unwrap(), vec![]);
    }

    #[test]
    fn input_limits_do_not_mutate_state() {
        let (_temp, path) = fixture();
        let mut store = Store::open(&path).unwrap();
        let max = vec![0x42; MAX_SECRET_LEN];
        store.create(0, "app.key", &max).unwrap();
        assert_eq!(store.read(0, "app.key").unwrap().secret.as_bytes(), max);
        let over = vec![0; MAX_SECRET_LEN + 1];
        assert!(matches!(
            store.create(0, "app.other", &over),
            Err(Error::SecretTooLarge)
        ));
        assert!(matches!(
            store.replace(0, "app.key", 1, &over),
            Err(Error::SecretTooLarge)
        ));
        assert!(matches!(
            store.create(0, "bad key", b""),
            Err(Error::InvalidKey)
        ));
        assert!(matches!(store.read(0, "bad key"), Err(Error::InvalidKey)));
        assert!(matches!(store.delete(0, "bad key"), Err(Error::InvalidKey)));
        assert!(matches!(
            store.metadata(0, "bad key"),
            Err(Error::InvalidKey)
        ));
        for version in [0, i64::MAX as u64 + 1, u64::MAX] {
            assert!(matches!(
                store.replace(0, "app.key", version, b""),
                Err(Error::InvalidVersion)
            ));
        }
        assert_eq!(store.metadata(0, "app.key").unwrap().version, 1);
        assert!(matches!(
            store.metadata(0, "app.other"),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn cas_tombstones_and_reopen_persist() {
        let (_temp, path) = fixture();
        {
            let mut store = Store::open(&path).unwrap();
            assert!(matches!(
                store.replace(8, "app.key", 1, b"x"),
                Err(Error::NotFound)
            ));
            assert!(matches!(store.delete(8, "app.key"), Err(Error::NotFound)));
            store.create(8, "app.key", b"v1").unwrap();
            assert_eq!(store.replace(8, "app.key", 1, b"v2").unwrap().version, 2);
            assert!(matches!(
                store.replace(8, "app.key", 1, b"wrong"),
                Err(Error::VersionConflict {
                    expected: 1,
                    actual: 2
                })
            ));
        }
        {
            let mut store = Store::open(&path).unwrap();
            let record = store.read(8, "app.key").unwrap();
            assert_eq!(record.version, 2);
            assert_eq!(record.secret.as_bytes(), b"v2");
            assert_eq!(
                store.delete(8, "app.key").unwrap(),
                Metadata {
                    owner_uid: 8,
                    key: "app.key".into(),
                    version: 3,
                    deleted: true,
                }
            );
            assert!(matches!(store.read(8, "app.key"), Err(Error::Tombstoned)));
            assert!(matches!(
                store.replace(8, "app.key", 3, b"wrong"),
                Err(Error::Tombstoned)
            ));
            assert!(matches!(store.delete(8, "app.key"), Err(Error::Tombstoned)));
        }
        let mut store = Store::open(&path).unwrap();
        assert!(matches!(
            store.create(8, "app.key", b"recreated"),
            Err(Error::AlreadyExists)
        ));
        assert!(store.metadata(8, "app.key").unwrap().deleted);
        assert_eq!(store.list_metadata(8).unwrap()[0].version, 3);
        let value: Option<Vec<u8>> = store
            .connection
            .query_row("SELECT value FROM entries", [], |row| row.get(0))
            .unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn concurrent_open_create_and_replace_have_one_winner() {
        let (_temp, path) = fixture();
        let count = 8;
        let barrier = Arc::new(Barrier::new(count));
        let handles: Vec<_> = (0..count)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    let mut store = Store::open(&path).unwrap();
                    store.create(4, "app.key", b"initial")
                })
            })
            .collect();
        let mut winners = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(_) => winners += 1,
                Err(Error::AlreadyExists) => {}
                other => panic!("unexpected create result: {other:?}"),
            }
        }
        assert_eq!(winners, 1);
        let barrier = Arc::new(Barrier::new(count));
        let handles: Vec<_> = (0..count)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                thread::spawn(move || {
                    let mut store = Store::open(&path).unwrap();
                    barrier.wait();
                    store.replace(4, "app.key", 1, &[i as u8])
                })
            })
            .collect();
        let mut winners = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(metadata) => {
                    assert_eq!(metadata.version, 2);
                    winners += 1;
                }
                Err(Error::VersionConflict {
                    expected: 1,
                    actual: 2,
                }) => {}
                other => panic!("unexpected replace result: {other:?}"),
            }
        }
        assert_eq!(winners, 1);
        assert_eq!(
            Store::open(path)
                .unwrap()
                .read(4, "app.key")
                .unwrap()
                .version,
            2
        );
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn secure_permissions_are_created_and_insecure_ones_never_repaired() {
        let (_temp, path) = fixture();
        drop(Store::open(&path).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let db = path.join(DATABASE_NAME);
        assert_eq!(
            fs::metadata(&db).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        set_mode(&db, 0o640);
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        assert_eq!(
            fs::metadata(&db).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        set_mode(&db, 0o600);
        set_mode(&path, 0o750);
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o750
        );
    }

    #[test]
    fn rejects_writable_ancestors_and_traversal() {
        let (temp, path) = fixture();
        // Unlike root-owned /tmp, this parent is not sticky.
        set_mode(temp.path(), 0o777);
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        assert!(!path.exists());
        set_mode(temp.path(), 0o700);
        assert!(matches!(
            Store::open(temp.path().join("x/../state")),
            Err(Error::UnsafePath(_))
        ));
        assert!(matches!(Store::open(""), Err(Error::UnsafePath(_))));
        assert!(matches!(Store::open("/"), Err(Error::UnsafePath(_))));
    }

    #[test]
    fn rejects_symlinks_at_every_path_level() {
        let (temp, path) = fixture();
        let actual = temp.path().join("actual");
        fs::create_dir(&actual).unwrap();
        set_mode(&actual, 0o700);
        symlink(&actual, &path).unwrap();
        assert!(Store::open(&path).is_err());
        assert!(Store::open(path.join("child")).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        set_mode(&path, 0o700);
        let target = actual.join("untouched");
        fs::write(&target, b"do not modify").unwrap();
        set_mode(&target, 0o600);
        symlink(&target, path.join(DATABASE_NAME)).unwrap();
        assert!(Store::open(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do not modify");
        fs::remove_file(path.join(DATABASE_NAME)).unwrap();
        for suffix in ["-journal", "-wal", "-shm"] {
            let sidecar = path.join(format!("{DATABASE_NAME}{suffix}"));
            symlink(&target, &sidecar).unwrap();
            assert!(Store::open(&path).is_err());
            assert_eq!(fs::read(&target).unwrap(), b"do not modify");
            fs::remove_file(sidecar).unwrap();
        }
    }

    #[test]
    fn rejects_hardlinks_and_nonregular_files() {
        let (temp, path) = fixture();
        drop(Store::open(&path).unwrap());
        let db = path.join(DATABASE_NAME);
        let link = temp.path().join("hardlink");
        fs::hard_link(&db, &link).unwrap();
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        fs::remove_file(&link).unwrap();
        fs::remove_file(&db).unwrap();
        fs::create_dir(&db).unwrap();
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        fs::remove_dir(&db).unwrap();
        let name = c_name(db.as_os_str()).unwrap();
        // SAFETY: valid NUL-terminated filename in our isolated test directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
    }

    #[test]
    fn rejects_insecure_sidecars_and_wal_state() {
        let (_temp, path) = fixture();
        drop(Store::open(&path).unwrap());
        let journal = path.join(format!("{DATABASE_NAME}-journal"));
        fs::write(&journal, []).unwrap();
        set_mode(&journal, 0o644);
        assert!(matches!(Store::open(&path), Err(Error::UnsafePath(_))));
        assert_eq!(
            fs::metadata(&journal).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        fs::remove_file(journal).unwrap();
        for suffix in ["-wal", "-shm"] {
            let sidecar = path.join(format!("{DATABASE_NAME}{suffix}"));
            drop(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&sidecar)
                    .unwrap(),
            );
            assert!(matches!(Store::open(&path), Err(Error::MalformedState(_))));
            fs::remove_file(sidecar).unwrap();
        }
        let connection = Connection::open(path.join(DATABASE_NAME)).unwrap();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        drop(connection);
        assert!(matches!(Store::open(&path), Err(Error::MalformedState(_))));
    }

    #[test]
    fn rejects_malformed_database_schema_and_rows() {
        let (_temp, path) = fixture();
        drop(Store::open(&path).unwrap());
        let db = path.join(DATABASE_NAME);
        fs::write(&db, b"not a sqlite database").unwrap();
        assert!(Store::open(&path).is_err());
        fs::remove_file(&db).unwrap();
        drop(Store::open(&path).unwrap());
        {
            let connection = Connection::open(&db).unwrap();
            connection
                .execute_batch("CREATE TABLE unexpected (x TEXT)")
                .unwrap();
        }
        assert!(matches!(Store::open(&path), Err(Error::MalformedState(_))));
        fs::remove_file(&db).unwrap();
        drop(Store::open(&path).unwrap());
        {
            let connection = Connection::open(&db).unwrap();
            connection
                .execute("INSERT INTO entries VALUES (1, 'bad key', 1, 0, X'00')", [])
                .unwrap();
        }
        assert!(matches!(Store::open(&path), Err(Error::MalformedState(_))));
        fs::remove_file(&db).unwrap();
        drop(Store::open(&path).unwrap());
        {
            let connection = Connection::open(&db).unwrap();
            connection.execute_batch("PRAGMA ignore_check_constraints = ON; INSERT INTO entries VALUES (1, 'app.key', -1, 0, X'00')").unwrap();
        }
        assert!(matches!(Store::open(&path), Err(Error::MalformedState(_))));
    }

    #[test]
    fn versions_never_wrap() {
        let (_temp, path) = fixture();
        let mut store = Store::open(&path).unwrap();
        store.create(u32::MAX, "app.key", b"retained").unwrap();
        store
            .connection
            .execute("UPDATE entries SET version = ?1", [i64::MAX])
            .unwrap();
        assert!(matches!(
            store.replace(u32::MAX, "app.key", i64::MAX as u64, b"wrong"),
            Err(Error::VersionExhausted)
        ));
        assert!(matches!(
            store.delete(u32::MAX, "app.key"),
            Err(Error::VersionExhausted)
        ));
        assert_eq!(
            store.read(u32::MAX, "app.key").unwrap().secret.as_bytes(),
            b"retained"
        );
    }
}
