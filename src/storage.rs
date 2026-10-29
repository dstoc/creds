use crate::{
    envelope::{Envelope, EnvelopeError, MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES},
    protocol::validate_name,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// List valid secret filenames without opening envelopes or following symlinks.
pub fn list_names(storage_dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(storage_dir)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(name) = filename
            .to_str()
            .and_then(|filename| filename.strip_suffix(".json"))
        else {
            continue;
        };
        if validate_name(name).is_ok()
            && entry
                .file_type()
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("cannot inspect {}: {error}", entry.path().display()),
                    )
                })?
                .is_file()
        {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

#[derive(Debug)]
pub enum StoreError {
    Busy(String),
    RevisionOverflow,
    Io(io::Error),
    IoAt {
        action: String,
        path: PathBuf,
        source: io::Error,
    },
    Envelope(EnvelopeError),
    PublishedButDurabilityUncertain(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(name) => {
                write!(formatter, "secret {name:?} is busy with another encryption")
            }
            Self::RevisionOverflow => {
                formatter.write_str("secret revision is at the maximum value")
            }
            Self::Io(error) => write!(formatter, "storage I/O failed: {error}"),
            Self::IoAt {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::Envelope(error) => write!(formatter, "invalid secret envelope: {error}"),
            Self::PublishedButDurabilityUncertain(error) => write!(
                formatter,
                "secret replacement was published, but directory sync failed; crash durability is uncertain: {error}"
            ),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error)
            | Self::PublishedButDurabilityUncertain(error)
            | Self::IoAt { source: error, .. } => Some(error),
            Self::Envelope(error) => Some(error),
            Self::Busy(_) | Self::RevisionOverflow => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<EnvelopeError> for StoreError {
    fn from(error: EnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

/// Read at most 64 KiB plus one sentinel byte so oversized input is rejected.
pub fn read_plaintext<R: Read>(reader: R) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_PLAINTEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(StoreError::Envelope(EnvelopeError::from_message(
            "plaintext exceeds the 64 KiB limit",
        )));
    }
    Ok(Zeroizing::new(bytes))
}

/// Read a named plaintext source without modifying it.
pub fn read_plaintext_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    read_plaintext(File::open(path)?)
}

fn acquire_name_lock(storage_dir: &Path, name: &str) -> Result<File, StoreError> {
    validate_name(name)
        .map_err(|error| StoreError::Envelope(EnvelopeError::from_message(error.to_string())))?;
    if !storage_dir.is_dir() {
        return Err(StoreError::IoAt {
            action: "access storage directory".to_owned(),
            path: storage_dir.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::NotFound,
                "storage directory is not available",
            ),
        });
    }
    let lock_path = storage_dir.join(format!("{name}.lock"));
    let lock = open_lock_file(&lock_path).map_err(|source| StoreError::IoAt {
        action: format!("open lock file for secret {name:?}"),
        path: lock_path.clone(),
        source,
    })?;
    match lock.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(StoreError::Busy(name.to_owned()));
        }
        Err(source) => {
            return Err(StoreError::IoAt {
                action: format!("lock secret {name:?}"),
                path: lock_path,
                source,
            });
        }
    }

    Ok(lock)
}

/// Remove one envelope while holding its stable per-name lock.
pub fn remove_secret(storage_dir: &Path, name: &str) -> Result<(), StoreError> {
    let lock = acquire_name_lock(storage_dir, name)?;
    let result = fs::remove_file(storage_dir.join(format!("{name}.json"))).map_err(StoreError::Io);
    let _ = lock.unlock();
    result
}

/// Hold the stable per-name sidecar lock from revision selection through publication.
pub struct SecretWriter {
    storage_dir: PathBuf,
    name: String,
    revision: u32,
    _lock: File,
}

impl SecretWriter {
    pub fn begin(storage_dir: &Path, name: &str) -> Result<Self, StoreError> {
        let lock = acquire_name_lock(storage_dir, name)?;

        let current_path = storage_dir.join(format!("{name}.json"));
        let revision = if current_path.exists() {
            let existing = read_envelope(&current_path, name).map_err(|error| match error {
                StoreError::Io(source) => StoreError::IoAt {
                    action: format!("read existing envelope for secret {name:?}"),
                    path: current_path.clone(),
                    source,
                },
                error => error,
            })?;
            existing
                .revision()
                .checked_add(1)
                .ok_or(StoreError::RevisionOverflow)?
        } else {
            1
        };
        Ok(Self {
            storage_dir: storage_dir.to_path_buf(),
            name: name.to_owned(),
            revision,
            _lock: lock,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// Publish a fully encrypted replacement while this value still owns the lock.
    pub fn publish(self, plaintext: &[u8], key: &[u8; 32]) -> Result<(), StoreError> {
        self.publish_with_cancel(plaintext, key, || false)
    }

    /// Publish unless cancellation arrives before the atomic rename commit point.
    pub fn publish_with_cancel<F>(
        self,
        plaintext: &[u8],
        key: &[u8; 32],
        is_cancelled: F,
    ) -> Result<(), StoreError>
    where
        F: FnOnce() -> bool,
    {
        let envelope = Envelope::encrypt(&self.name, self.revision, plaintext, key)?;
        let bytes = envelope.to_json()?;
        publish_envelope_with_cancel(&self.storage_dir, &self.name, &bytes, is_cancelled)
    }
}

impl Drop for SecretWriter {
    fn drop(&mut self) {
        // Release the sidecar lock as soon as the writer leaves scope. The OS
        // still releases it if the process exits before this runs.
        let _ = self._lock.unlock();
    }
}

/// A bounded, validated in-memory snapshot. Later replacements do not change it.
pub struct SecretSnapshot {
    envelope: Envelope,
}

impl SecretSnapshot {
    pub fn read(storage_dir: &Path, name: &str) -> Result<Self, StoreError> {
        validate_name(name).map_err(|error| {
            StoreError::Envelope(EnvelopeError::from_message(error.to_string()))
        })?;
        let path = storage_dir.join(format!("{name}.json"));
        Ok(Self {
            envelope: read_envelope(&path, name)?,
        })
    }

    pub fn name(&self) -> &str {
        self.envelope.name()
    }

    pub fn revision(&self) -> u32 {
        self.envelope.revision()
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        Ok(self.envelope.decrypt(key)?)
    }
}

fn read_envelope(path: &Path, expected_name: &str) -> Result<Envelope, StoreError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let envelope = Envelope::parse(&bytes)?;
    if envelope.name() != expected_name {
        return Err(StoreError::Envelope(EnvelopeError::from_message(
            "envelope name does not match the requested logical name",
        )));
    }
    Ok(envelope)
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

struct TempCiphertext {
    path: PathBuf,
    published: bool,
}

impl Drop for TempCiphertext {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp_file(storage_dir: &Path, name: &str) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|error| {
            io::Error::other(format!("temporary filename randomness failed: {error}"))
        })?;
        let path = storage_dir.join(format!(".{name}.{}.tmp", URL_SAFE_NO_PAD.encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique ciphertext staging file",
    ))
}

fn publish_envelope_with_cancel<F>(
    storage_dir: &Path,
    name: &str,
    bytes: &[u8],
    is_cancelled: F,
) -> Result<(), StoreError>
where
    F: FnOnce() -> bool,
{
    publish_envelope_with(
        storage_dir,
        name,
        bytes,
        is_cancelled,
        |file, contents| file.write_all(contents),
        sync_directory,
    )
}

fn publish_envelope_with<W, S>(
    storage_dir: &Path,
    name: &str,
    bytes: &[u8],
    is_cancelled: impl FnOnce() -> bool,
    write_staging: W,
    sync_dir: S,
) -> Result<(), StoreError>
where
    W: FnOnce(&mut File, &[u8]) -> io::Result<()>,
    S: FnOnce(&Path) -> io::Result<()>,
{
    let target = storage_dir.join(format!("{name}.json"));
    let (temp_path, mut temp_file) = create_temp_file(storage_dir, name)?;
    let mut temp_guard = TempCiphertext {
        path: temp_path,
        published: false,
    };
    let staging_result = write_staging(&mut temp_file, bytes)
        .and_then(|()| temp_file.flush())
        .and_then(|()| temp_file.sync_all());
    drop(temp_file);
    staging_result?;
    if is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "encryption was cancelled before publication",
        )
        .into());
    }
    fs::rename(&temp_guard.path, &target)?;
    temp_guard.published = true;
    sync_dir(storage_dir).map_err(StoreError::PublishedButDurabilityUncertain)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Create plaintext output exclusively. Remove a partial file if any write or sync fails.
pub fn write_plaintext_exclusive(path: &Path, plaintext: &[u8]) -> Result<(), StoreError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(StoreError::Envelope(EnvelopeError::from_message(
            "plaintext exceeds the 64 KiB limit",
        )));
    }
    write_exclusive_with(path, |file| file.write_all(plaintext))
}

fn write_exclusive_with<F>(path: &Path, write: F) -> Result<(), StoreError>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = write(&mut file).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("creds-store-{}-{tick}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn first_write_replacement_and_literal_revision_suffix() {
        let dir = TestDir::new();
        let key = [0x31; 32];
        let first = SecretWriter::begin(dir.path(), "secret-x").unwrap();
        assert_eq!(first.revision(), 1);
        first.publish(b"one", &key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path().join("secret-x.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(dir.path().join("secret-x.lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let second = SecretWriter::begin(dir.path(), "secret-x").unwrap();
        assert_eq!(second.revision(), 2);
        second.publish(b"two", &key).unwrap();
        let literal = SecretWriter::begin(dir.path(), "secret-x-r2").unwrap();
        assert_eq!(literal.revision(), 1);
        literal.publish(b"literal", &key).unwrap();
        assert_eq!(
            SecretSnapshot::read(dir.path(), "secret-x")
                .unwrap()
                .revision(),
            2
        );
        assert_eq!(
            SecretSnapshot::read(dir.path(), "secret-x-r2")
                .unwrap()
                .revision(),
            1
        );
        assert!(dir.path().join("secret-x.lock").exists());
        assert!(dir.path().join("secret-x-r2.lock").exists());
        fs::remove_file(dir.path().join("secret-x.json")).unwrap();
        assert_eq!(
            SecretWriter::begin(dir.path(), "secret-x")
                .unwrap()
                .revision(),
            1
        );
    }

    #[test]
    fn same_name_is_busy_and_different_names_are_independent() {
        let dir = TestDir::new();
        let first = SecretWriter::begin(dir.path(), "one").unwrap();
        assert!(matches!(
            SecretWriter::begin(dir.path(), "one"),
            Err(StoreError::Busy(_))
        ));
        assert!(SecretWriter::begin(dir.path(), "two").is_ok());
        drop(first);
        if let Err(error) = SecretWriter::begin(dir.path(), "one") {
            panic!("same-name lock was not released when the writer dropped: {error:?}");
        }
    }

    #[test]
    fn process_exit_releases_the_operating_system_lock() {
        let dir = TestDir::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::tests::exit_while_holding_lock",
                "--ignored",
            ])
            .env("CREDS_TEST_LOCK_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(SecretWriter::begin(dir.path(), "crash").is_ok());
    }

    #[test]
    #[ignore = "child process fixture for process_exit_releases_the_operating_system_lock"]
    fn exit_while_holding_lock() {
        let dir = PathBuf::from(std::env::var_os("CREDS_TEST_LOCK_DIR").unwrap());
        let writer = SecretWriter::begin(&dir, "crash").unwrap();
        std::mem::forget(writer);
        std::process::exit(0);
    }

    #[test]
    fn snapshot_keeps_old_envelope_during_replacement() {
        let dir = TestDir::new();
        let key = [0x42; 32];
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"old", &key)
            .unwrap();
        let snapshot = SecretSnapshot::read(dir.path(), "secret").unwrap();
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"new", &key)
            .unwrap();
        assert_eq!(snapshot.revision(), 1);
        assert_eq!(snapshot.decrypt(&key).unwrap().as_slice(), b"old");
        let current = SecretSnapshot::read(dir.path(), "secret").unwrap();
        assert_eq!(current.revision(), 2);
        assert_eq!(current.decrypt(&key).unwrap().as_slice(), b"new");
    }

    #[test]
    fn malformed_existing_file_and_revision_overflow_fail_closed() {
        let dir = TestDir::new();
        let key = [0x11; 32];
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"old", &key)
            .unwrap();
        let path = dir.path().join("secret.json");
        fs::write(&path, br#"{"version":1,"name":"secret","revision":4294967295,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}"#).unwrap();
        assert!(matches!(
            SecretWriter::begin(dir.path(), "secret"),
            Err(StoreError::RevisionOverflow)
        ));
        fs::write(&path, b"not json").unwrap();
        assert!(SecretWriter::begin(dir.path(), "secret").is_err());
        assert!(SecretSnapshot::read(dir.path(), "other").is_err());
    }

    #[test]
    fn handled_staging_failure_preserves_old_bytes_and_cleans_temp() {
        let dir = TestDir::new();
        let key = [0x22; 32];
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"old", &key)
            .unwrap();
        let path = dir.path().join("secret.json");
        let old = fs::read(&path).unwrap();
        let envelope = Envelope::encrypt("secret", 2, b"new", &key).unwrap();
        let result = publish_envelope_with(
            dir.path(),
            "secret",
            &envelope.to_json().unwrap(),
            || false,
            |file, bytes| {
                file.write_all(&bytes[..bytes.len() / 2])?;
                Err(io::Error::other("injected staging failure"))
            },
            sync_directory,
        );
        assert!(matches!(result, Err(StoreError::Io(_))));
        assert_eq!(fs::read(path).unwrap(), old);
        let entries = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 2, "only envelope and stable lock remain");
    }

    #[test]
    fn cancellation_before_rename_preserves_old_envelope_and_cleans_temp() {
        let dir = TestDir::new();
        let key = [0x24; 32];
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"old", &key)
            .unwrap();
        let path = dir.path().join("secret.json");
        let old = fs::read(&path).unwrap();
        let result = SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish_with_cancel(b"new", &key, || true);
        assert!(matches!(
            result,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert_eq!(fs::read(&path).unwrap(), old);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        assert!(SecretWriter::begin(dir.path(), "secret").is_ok());
    }

    #[test]
    fn post_rename_directory_sync_error_reports_published_state() {
        let dir = TestDir::new();
        let key = [0x23; 32];
        SecretWriter::begin(dir.path(), "secret")
            .unwrap()
            .publish(b"old", &key)
            .unwrap();
        let envelope = Envelope::encrypt("secret", 2, b"new", &key).unwrap();
        let result = publish_envelope_with(
            dir.path(),
            "secret",
            &envelope.to_json().unwrap(),
            || false,
            |file, bytes| file.write_all(bytes),
            |_| Err(io::Error::other("injected directory sync failure")),
        );
        assert!(matches!(
            result,
            Err(StoreError::PublishedButDurabilityUncertain(_))
        ));
        let current = SecretSnapshot::read(dir.path(), "secret").unwrap();
        assert_eq!(current.revision(), 2);
        assert_eq!(current.decrypt(&key).unwrap().as_slice(), b"new");
    }

    #[test]
    fn plaintext_output_is_exclusive_private_and_removed_after_partial_failure() {
        let dir = TestDir::new();
        let path = dir.path().join("plaintext");
        write_plaintext_exclusive(&path, b"plain").unwrap();
        assert!(write_plaintext_exclusive(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"plain");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let partial = dir.path().join("partial");
        let result = write_exclusive_with(&partial, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        });
        assert!(result.is_err());
        assert!(!partial.exists());
    }

    #[test]
    fn bounded_reader_rejects_extra_input() {
        assert_eq!(read_plaintext(&b""[..]).unwrap().as_slice(), b"");
        assert!(read_plaintext(&vec![0; MAX_PLAINTEXT_BYTES + 1][..]).is_err());
    }

    #[test]
    fn named_input_is_bounded_and_unchanged() {
        let dir = TestDir::new();
        let path = dir.path().join("source.bin");
        let original = vec![0, 255, 7, 0, 12];
        fs::write(&path, &original).unwrap();
        assert_eq!(read_plaintext_file(&path).unwrap().as_slice(), original);
        assert_eq!(fs::read(path).unwrap(), original);
    }
}
