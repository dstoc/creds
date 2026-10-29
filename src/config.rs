use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use creds_qr_rendering::Mode as QrMode;
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Host, Url};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigValues {
    pub app_url: String,
    pub hostname: String,
    pub storage_dir: PathBuf,
    pub public_key: String,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qr_mode: Option<String>,
}

#[derive(Debug)]
pub struct ValidatedConfig {
    pub config_path: PathBuf,
    pub app_url: String,
    pub app_origin: String,
    pub rp_id: String,
    pub hostname: String,
    pub storage_dir: PathBuf,
    pub listen_addr: SocketAddr,
    pub qr_mode: QrMode,
    pub public_key: VerifyingKey,
    pub public_key_fingerprint: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn default_listen_addr() -> String {
    "0.0.0.0:0".to_owned()
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| invalid("HOME must be set to an absolute path").into())
}

fn xdg_dir(name: &str, fallback: PathBuf) -> Result<PathBuf> {
    match std::env::var_os(name) {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(invalid(format!("{name} must be an absolute path")).into());
            }
            Ok(path)
        }
        None => Ok(fallback),
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let fallback = home_dir()?.join(".config");
    Ok(xdg_dir("XDG_CONFIG_HOME", fallback)?.join("creds/config.toml"))
}

fn default_storage_path() -> Result<PathBuf> {
    let fallback = home_dir()?.join(".local/share");
    Ok(xdg_dir("XDG_DATA_HOME", fallback)?.join("creds/secrets"))
}

pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.is_absolute() {
        return Err(invalid("configuration path did not resolve to an absolute path").into());
    }
    Ok(normalized)
}

fn config_dir(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid("configuration path must have a parent directory").into())
}

fn resolve_storage(path: &Path, config_path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(invalid("storage_dir must not be empty").into());
    }
    if path.to_string_lossy().contains('\0') {
        return Err(invalid("storage_dir contains a NUL byte").into());
    }
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir(config_path)?.join(path)
    };
    let resolved = absolute_path(&resolved)?;
    if resolved == Path::new("/") {
        return Err(invalid("storage_dir must not be the filesystem root").into());
    }
    Ok(resolved)
}

fn validate_storage_path(path: &Path) -> std::result::Result<(), String> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::metadata(candidate) {
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            Ok(_) => {
                return Err(format!(
                    "{} exists and is not a directory",
                    candidate.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = candidate.parent();
            }
            Err(error) => {
                return Err(format!("cannot inspect {}: {error}", candidate.display()));
            }
        }
    }
    Ok(())
}

fn validate_hostname_label(hostname: &str) -> Result<()> {
    let valid = !hostname.is_empty()
        && hostname.len() <= 63
        && hostname.is_ascii()
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && hostname
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && hostname
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        return Err(invalid("hostname must be one valid DNS label (1–63 ASCII letters, digits, or hyphens; no leading or trailing hyphen)").into());
    }
    Ok(())
}

fn validate_app_url(value: &str) -> Result<(Url, String, String)> {
    let url = Url::parse(value).map_err(|error| invalid(format!("invalid app_url: {error}")))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "app_url must use HTTPS and must not contain credentials, a query, or a fragment",
        )
        .into());
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err(invalid("app_url must use a DNS hostname, not an IP address").into());
    };
    if host.is_empty() || host.ends_with('.') || url.port() == Some(0) {
        return Err(invalid("app_url must use a non-root DNS hostname and a nonzero port").into());
    }
    let rp_id = host.to_owned();
    let origin = url.origin().ascii_serialization();
    Ok((url, origin, rp_id))
}

fn decode_public_key(value: &str) -> Result<(VerifyingKey, String)> {
    let der = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| invalid(format!("public_key is not unpadded base64url: {error}")))?;
    if der.is_empty() || der.len() > 4096 || URL_SAFE_NO_PAD.encode(&der) != value {
        return Err(invalid(
            "public_key must be canonical unpadded base64url DER of at most 4096 bytes",
        )
        .into());
    }
    let key = VerifyingKey::from_public_key_der(&der).map_err(|error| {
        invalid(format!(
            "public_key is not a valid ES256 P-256 SPKI key: {error}"
        ))
    })?;
    let fingerprint = Sha256::digest(&der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((key, format!("SHA-256:{fingerprint}")))
}

fn validate_values(
    config_path: &Path,
    values: ConfigValues,
    require_storage_directory: bool,
) -> Result<ValidatedConfig> {
    validate_hostname_label(&values.hostname)?;
    let (app_url, app_origin, rp_id) = validate_app_url(&values.app_url)?;
    let storage_dir = resolve_storage(&values.storage_dir, config_path)?;
    let listen_addr = values
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| invalid(format!("invalid listen_addr: {error}")))?;
    let qr_mode = values
        .qr_mode
        .as_deref()
        .unwrap_or("half")
        .parse::<QrMode>()
        .map_err(|error| invalid(error.to_string()))?;
    let (public_key, public_key_fingerprint) = decode_public_key(&values.public_key)?;
    if require_storage_directory {
        validate_storage_directory(&storage_dir)?;
    }
    Ok(ValidatedConfig {
        config_path: config_path.to_path_buf(),
        app_url: app_url.to_string(),
        app_origin,
        rp_id,
        hostname: values.hostname,
        storage_dir,
        listen_addr,
        qr_mode,
        public_key,
        public_key_fingerprint,
    })
}

fn validate_storage_directory(storage_dir: &Path) -> Result<()> {
    let metadata = fs::metadata(storage_dir).map_err(|error| {
        invalid(format!(
            "storage directory {} is not available: {error}",
            storage_dir.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "storage path {} is not a directory",
            storage_dir.display()
        ))
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(invalid(format!(
                "storage directory {} must be owner-only (mode 0700)",
                storage_dir.display()
            ))
            .into());
        }
    }
    Ok(())
}

fn read_values(path: &Path) -> Result<(PathBuf, ConfigValues)> {
    let path = absolute_path(path)?;
    let mut contents = Vec::new();
    let config_file = File::open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if config_file.metadata()?.permissions().mode() & 0o7777 != 0o600 {
            return Err(invalid("configuration file must be owner-only (mode 0600)").into());
        }
    }
    config_file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err(invalid("configuration file exceeds 16 KiB").into());
    }
    let text = std::str::from_utf8(&contents)
        .map_err(|error| invalid(format!("configuration file is not UTF-8: {error}")))?;
    let values: ConfigValues = toml::from_str(text)
        .map_err(|error| invalid(format!("invalid configuration TOML: {error}")))?;
    Ok((path, values))
}

pub fn load(path: &Path) -> Result<ValidatedConfig> {
    let (path, values) = read_values(path)?;
    validate_values(&path, values, true)
}

pub fn load_storage_dir(path: &Path) -> Result<PathBuf> {
    let (path, values) = read_values(path)?;
    let storage_dir = resolve_storage(&values.storage_dir, &path)?;
    validate_storage_directory(&storage_dir)?;
    Ok(storage_dir)
}

pub fn check(path: &Path, details: bool) -> Result<()> {
    let validated = load(path)?;
    println!("Local setup is valid.");
    if details {
        println!("Configuration: {}", validated.config_path.display());
        println!("Storage: {}", validated.storage_dir.display());
        println!("App origin: {}", validated.app_origin);
        println!("RP ID: {}", validated.rp_id);
        println!("Machine label: {}", validated.hostname);
        println!("UDP listener: {}", validated.listen_addr);
        println!("QR rendering: {}", validated.qr_mode);
        println!(
            "Pinned public-key fingerprint: {}",
            validated.public_key_fingerprint
        );
        println!(
            "This local check does not prove passkey possession, network reachability, or secret decryptability."
        );
    }
    Ok(())
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(value) => eprint!("{label} [{value}]: "),
        None => eprint!("{label}: "),
    }
    io::stderr().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input ended").into());
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(default.unwrap_or_default().to_owned());
    }
    Ok(input.to_owned())
}

fn prompt_validated(
    label: &str,
    default: Option<&str>,
    validate: impl Fn(&str) -> std::result::Result<(), String>,
) -> Result<String> {
    loop {
        let value = prompt(label, default)?;
        let result = if value.is_empty() {
            Err("a value is required".to_owned())
        } else {
            validate(&value)
        };
        match result {
            Ok(()) => return Ok(value),
            Err(error) => eprintln!("Invalid {label}: {error}. Try again."),
        }
    }
}

fn confirm(label: &str) -> Result<bool> {
    eprint!("{label} [y/N]: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input ended").into());
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(unix)]
fn create_private_dirs(path: &Path, secure_existing_final: bool) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let absolute = path.is_absolute();
    let mut current = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::Normal(part) => current.push(part),
        }
        if !current.exists() {
            match fs::DirBuilder::new().mode(0o700).create(&current) {
                Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
    if !fs::metadata(path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "setup directory path is not a directory",
        ));
    }
    if secure_existing_final {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    create_private_dirs(path, true)
}

#[cfg(unix)]
fn create_private_parent(path: &Path) -> io::Result<()> {
    create_private_dirs(path, false)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(not(unix))]
fn create_private_parent(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

fn temp_config_path(path: &Path, attempt: u32) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut name: OsString = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".{}.{}.{}.tmp",
        std::process::id(),
        timestamp,
        attempt
    ));
    path.with_file_name(name)
}

#[cfg(unix)]
fn create_owner_only_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_owner_only_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn write_config(path: &Path, values: &ConfigValues, replace: bool) -> Result<()> {
    let parent = config_dir(path)?;
    create_private_parent(parent)?;
    let toml = toml::to_string_pretty(values)?;
    for attempt in 0..16 {
        let temporary = temp_config_path(path, attempt);
        match create_owner_only_file(&temporary) {
            Ok(mut file) => {
                let result = (|| -> io::Result<()> {
                    file.write_all(toml.as_bytes())?;
                    file.sync_all()
                })();
                drop(file);
                if let Err(error) = result {
                    let _ = fs::remove_file(&temporary);
                    return Err(error.into());
                }
                let publication = if replace {
                    fs::rename(&temporary, path)
                } else {
                    fs::hard_link(&temporary, path)
                };
                if let Err(error) = publication {
                    let _ = fs::remove_file(&temporary);
                    return Err(error.into());
                }
                // A failed directory sync happens after the destination was
                // published. Report that state so callers do not assume the
                // configuration stayed unchanged.
                if !replace {
                    fs::remove_file(&temporary).map_err(|error| {
                        io::Error::other(format!(
                            "Configuration at {} was written, but temporary file {} could not be removed; the configuration file now exists: {error}",
                            path.display(),
                            temporary.display()
                        ))
                    })?;
                }
                File::open(parent).and_then(|directory| directory.sync_all()).map_err(|error| {
                    io::Error::other(format!(
                        "Configuration at {} was written, but directory sync failed; the replacement may already have occurred: {error}",
                        path.display()
                    ))
                })?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(invalid("could not create a unique temporary configuration file").into())
}

fn configured_qr_mode(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let document = toml::from_str::<toml::Value>(&contents).ok()?;
    let mode = document.get("qr_mode")?.as_str()?;
    mode.parse::<QrMode>().ok().map(|mode| mode.to_string())
}

pub fn setup(path: &Path) -> Result<()> {
    let path = absolute_path(path)?;
    let replace = path.exists();
    let prior_qr_mode = if replace {
        configured_qr_mode(&path)
    } else {
        None
    };
    if replace
        && !confirm(&format!(
            "Configuration {} exists. Replace it?",
            path.display()
        ))?
    {
        return Err(invalid("Setup cancelled; existing configuration was not changed").into());
    }

    let default_storage = default_storage_path()?;
    let mut values = ConfigValues {
        app_url: prompt_validated("Trusted app HTTPS URL", None, |value| {
            validate_app_url(value)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })?,
        hostname: prompt_validated("Machine DNS label", Some("workstation"), |value| {
            validate_hostname_label(value).map_err(|error| error.to_string())
        })?,
        storage_dir: PathBuf::from(prompt_validated(
            "Secret storage directory",
            default_storage.to_str(),
            |value| {
                let path =
                    resolve_storage(Path::new(value), &path).map_err(|error| error.to_string())?;
                validate_storage_path(&path)
            },
        )?),
        public_key: prompt_validated("Passkey public key", None, |value| {
            decode_public_key(value)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })?,
        listen_addr: prompt_validated("UDP listener address", Some("0.0.0.0:0"), |value| {
            value
                .parse::<SocketAddr>()
                .map(|_| ())
                .map_err(|error| error.to_string())
        })?,
        qr_mode: prior_qr_mode,
    };
    let validated = validate_values(&path, values.clone(), false)?;
    values.storage_dir = validated.storage_dir.clone();
    eprintln!("\nReview setup");
    eprintln!("App origin: {}", validated.app_origin);
    eprintln!("RP ID: {}", validated.rp_id);
    eprintln!("Machine label: {}", validated.hostname);
    eprintln!("Storage: {}", validated.storage_dir.display());
    eprintln!("UDP listener: {}", validated.listen_addr);
    eprintln!(
        "Pinned key fingerprint: {}",
        validated.public_key_fingerprint
    );
    if !confirm("Trust this pinned passkey key and save?")? {
        return Err(invalid("Setup cancelled; configuration was not written").into());
    }

    create_private_dir(&validated.storage_dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "Cannot create storage directory {}: {error}",
                validated.storage_dir.display()
            ),
        )
    })?;
    write_config(&path, &values, replace)?;
    println!("Setup saved to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
    use std::collections::HashSet;

    fn valid_values(storage_dir: PathBuf) -> ConfigValues {
        let signing_key = SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let public_key = signing_key.verifying_key().to_public_key_der().unwrap();
        ConfigValues {
            app_url: "https://keys.example/path".into(),
            hostname: "workstation".into(),
            storage_dir,
            public_key: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
            listen_addr: "0.0.0.0:0".into(),
            qr_mode: None,
        }
    }

    #[test]
    fn rejects_urls_with_credentials_query_fragment_and_ip_hosts() {
        for value in [
            "https://user@keys.example/",
            "https://keys.example/?token=x",
            "https://keys.example/#fragment",
            "https://keys.example.:443/",
            "https://keys.example:0/",
            "https://127.0.0.1/",
            "http://keys.example/",
        ] {
            assert!(validate_app_url(value).is_err(), "accepted {value}");
        }
        let (_, origin, rp_id) = validate_app_url("https://keys.example:443/deploy/").unwrap();
        assert_eq!(origin, "https://keys.example");
        assert_eq!(rp_id, "keys.example");
    }

    #[test]
    fn rejects_invalid_hostname_listener_and_non_p256_keys() {
        for hostname in ["", "-workstation", "workstation-", "a.b", "bad label"] {
            assert!(
                validate_hostname_label(hostname).is_err(),
                "accepted {hostname}"
            );
        }
        let path = PathBuf::from("/tmp/creds-config-test/config.toml");
        let mut values = valid_values(PathBuf::from("secrets"));
        values.listen_addr = "localhost:0".into();
        assert!(validate_values(&path, values.clone(), false).is_err());

        values.listen_addr = "0.0.0.0:0".into();
        values.public_key = URL_SAFE_NO_PAD.encode(b"not a public key");
        assert!(validate_values(&path, values, false).is_err());
        assert!(decode_public_key(&URL_SAFE_NO_PAD.encode([1_u8; 32])).is_err());
    }

    #[test]
    fn resolves_relative_storage_against_config_directory() {
        let path = PathBuf::from("/home/test/.config/creds/config.toml");
        let validated =
            validate_values(&path, valid_values(PathBuf::from("../secrets")), false).unwrap();
        assert_eq!(
            validated.storage_dir,
            PathBuf::from("/home/test/.config/secrets")
        );
        assert!(resolve_storage(Path::new("/"), &path).is_err());
        assert!(resolve_storage(Path::new("\0"), &path).is_err());
        assert_eq!(
            absolute_path(Path::new("/../../tmp/creds")).unwrap(),
            PathBuf::from("/tmp/creds")
        );
    }

    #[test]
    fn toml_rejects_duplicate_unknown_and_invalid_fields() {
        let encoded_key = valid_values(PathBuf::from("/tmp/secrets")).public_key;
        let duplicate = format!(
            "app_url='https://keys.example/'\napp_url='https://other.example/'\nhostname='pc'\nstorage_dir='/tmp/secrets'\npublic_key='{encoded_key}'"
        );
        assert!(toml::from_str::<ConfigValues>(&duplicate).is_err());
        let unknown = format!(
            "app_url='https://keys.example/'\nhostname='pc'\nstorage_dir='/tmp/secrets'\npublic_key='{encoded_key}'\nextra=true"
        );
        assert!(toml::from_str::<ConfigValues>(&unknown).is_err());
        let invalid = "app_url=[]\nhostname='pc'\nstorage_dir='/tmp/secrets'\npublic_key='x'";
        assert!(toml::from_str::<ConfigValues>(invalid).is_err());
    }

    #[test]
    fn qr_mode_is_optional_validated_and_retained_by_config_serialization() {
        let encoded_key = valid_values(PathBuf::from("/tmp/secrets")).public_key;
        let base = format!(
            "app_url='https://keys.example/'\nhostname='pc'\nstorage_dir='/tmp/secrets'\npublic_key='{encoded_key}'"
        );
        let missing: ConfigValues = toml::from_str(&base).unwrap();
        assert_eq!(missing.qr_mode, None);
        let validated = validate_values(Path::new("/tmp/config.toml"), missing, false).unwrap();
        assert_eq!(validated.qr_mode, QrMode::Half);

        let configured: ConfigValues =
            toml::from_str(&format!("{base}\nqr_mode='sextant'")).unwrap();
        assert_eq!(configured.qr_mode.as_deref(), Some("sextant"));
        let serialized = toml::to_string(&configured).unwrap();
        assert!(serialized.contains("qr_mode = \"sextant\""));

        let error = validate_values(
            Path::new("/tmp/config.toml"),
            ConfigValues {
                qr_mode: Some("pixels".into()),
                ..valid_values(PathBuf::from("/tmp/secrets"))
            },
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid qr_mode \"pixels\""), "{error}");
        assert!(error.contains("braille, sextant, half, kitty"), "{error}");

        let default_serialized =
            toml::to_string(&valid_values(PathBuf::from("/tmp/secrets"))).unwrap();
        assert!(!default_serialized.contains("qr_mode"));
    }

    #[test]
    fn setup_update_preserves_a_valid_configured_qr_mode() {
        let root = std::env::temp_dir().join(format!(
            "creds-config-qr-mode-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        fs::write(&path, "qr_mode = \"braille\"\n").unwrap();
        assert_eq!(configured_qr_mode(&path).as_deref(), Some("braille"));
        fs::write(&path, "qr_mode = \"pixels\"\n").unwrap();
        assert_eq!(configured_qr_mode(&path), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_write_is_private_and_check_is_read_only() {
        let root = std::env::temp_dir().join(format!(
            "creds-config-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("config.toml");
        let storage_dir = root.join("secrets");
        create_private_dir(&storage_dir).unwrap();
        let values = valid_values(PathBuf::from("secrets"));
        write_config(&config_path, &values, false).unwrap();

        let validated = load(&config_path).unwrap();
        assert_eq!(validated.storage_dir, storage_dir);
        assert_eq!(validated.app_origin, "https://keys.example");
        assert_eq!(validated.rp_id, "keys.example");
        assert_eq!(validated.listen_addr, "0.0.0.0:0".parse().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&config_path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
            assert_eq!(
                fs::metadata(storage_dir).unwrap().permissions().mode() & 0o7777,
                0o700
            );
        }

        let config_bytes = fs::read(&config_path).unwrap();
        let config_modified = fs::metadata(&config_path).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<HashSet<_>>();
        check(&config_path, false).unwrap();
        assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
        assert_eq!(
            fs::metadata(&config_path).unwrap().modified().unwrap(),
            config_modified
        );
        let entries_after = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<HashSet<_>>();
        assert_eq!(entries_after, entries_before);
        fs::remove_dir_all(root).unwrap();
    }
}
