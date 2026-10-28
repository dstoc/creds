use creds::{
    config,
    handoff::{self, Operation},
    protocol::validate_name,
    storage::{self, SecretSnapshot, SecretWriter, StoreError},
};
mod cli;

use clap::{CommandFactory, Parser, error::ErrorKind};
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), CliError> {
    validate_config_arguments();
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) if error.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            cli::Cli::command()
                .error(ErrorKind::MissingSubcommand, "a command is required")
                .exit();
        }
        Err(error) => error.exit(),
    };
    let explicit_config_path = cli.config;

    match cli.command {
        cli::Commands::Setup => {
            let path = config_path(explicit_config_path.as_deref())?;
            config::setup(&path).map_err(|error| setup_error(&path, error))?;
        }
        cli::Commands::Check { details } => {
            let path = config_path(explicit_config_path.as_deref())?;
            config::check(&path, details).map_err(|error| config_error(&path, error))?;
        }
        cli::Commands::List => {
            let path = config_path(explicit_config_path.as_deref())?;
            let validated = config::load(&path).map_err(|error| config_error(&path, error))?;
            let names = storage::list_names(&validated.storage_dir).map_err(|error| {
                CliError::with_source(
                    format!("Cannot list secrets in {}", validated.storage_dir.display()),
                    error,
                )
            })?;
            let mut stdout = io::stdout().lock();
            for name in names {
                writeln!(stdout, "{name}").map_err(|error| {
                    CliError::with_source("Cannot write secret names to stdout", error)
                })?;
            }
            stdout.flush().map_err(|error| {
                CliError::with_source("Cannot write secret names to stdout", error)
            })?;
        }
        cli::Commands::Encrypt { name, input } => {
            let path = config_path(explicit_config_path.as_deref())?;
            encrypt(&path, &name, &input).await?;
        }
        cli::Commands::Decrypt { name, output } => {
            let path = config_path(explicit_config_path.as_deref())?;
            decrypt(&path, &name, &output).await?;
        }
    }
    Ok(())
}

fn validate_config_arguments() {
    let mut arguments = std::env::args_os().skip(1);
    let mut config_seen = false;

    while let Some(argument) = arguments.next() {
        if argument == "--" {
            break;
        } else if argument == "--config" {
            if config_seen {
                config_argument_error(
                    ErrorKind::ArgumentConflict,
                    "--config may be used only once",
                );
            }
            config_seen = true;

            let Some(path) = arguments.next() else {
                config_argument_error(
                    ErrorKind::MissingRequiredArgument,
                    "--config requires a path",
                );
            };
            if path.as_os_str().is_empty() || path.to_string_lossy().starts_with('-') {
                config_argument_error(
                    ErrorKind::MissingRequiredArgument,
                    "--config requires a path",
                );
            }
        } else if let Some(path) = argument.to_string_lossy().strip_prefix("--config=") {
            if config_seen {
                config_argument_error(
                    ErrorKind::ArgumentConflict,
                    "--config may be used only once",
                );
            }
            config_seen = true;
            if path.is_empty() {
                config_argument_error(
                    ErrorKind::ValueValidation,
                    "--config requires one non-empty path",
                );
            }
        }
    }
}

fn config_argument_error(kind: ErrorKind, message: &str) -> ! {
    cli::Cli::command().error(kind, message).exit()
}

fn config_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    match explicit {
        Some(path) => Ok(path.to_path_buf()),
        None => config::default_config_path().map_err(|error| {
            CliError::with_boxed_source("Cannot determine the default configuration path", error)
        }),
    }
}

async fn encrypt(config_path: &Path, name: &str, input_path: &Path) -> Result<(), CliError> {
    validate_name(name).map_err(|error| CliError::with_source("Invalid secret name", error))?;
    let plaintext = if input_path == Path::new("-") {
        storage::read_plaintext(io::stdin().lock()).map_err(|error| match error {
            StoreError::Envelope(error) => {
                CliError::with_source("Cannot read plaintext from stdin", error)
            }
            StoreError::Io(error) => {
                CliError::with_source("Cannot read plaintext from stdin", error)
            }
            other => CliError::with_source("Cannot read plaintext from stdin", other),
        })?
    } else {
        storage::read_plaintext_file(input_path).map_err(|error| match error {
            StoreError::Io(error) => file_error("read input file", input_path, error),
            StoreError::Envelope(error) => CliError::with_source(
                format!("Cannot read plaintext input at {}", input_path.display()),
                error,
            ),
            other => CliError::with_source(
                format!("Cannot read plaintext input at {}", input_path.display()),
                other,
            ),
        })?
    };
    let validated = config::load(config_path).map_err(|error| config_error(config_path, error))?;
    let writer = SecretWriter::begin(&validated.storage_dir, name)
        .map_err(|error| secret_store_error(name, &validated.storage_dir, "prepare", error))?;
    let revision = writer.revision();
    let cancellation = start_cancellation_listener();
    let key = handoff::receive_key(
        &validated,
        name,
        revision,
        Operation::Encrypt,
        cancellation.clone(),
    )
    .await
    .map_err(|error| approval_error(name, error))?;
    ensure_not_cancelled(&cancellation).map_err(|error| {
        CliError::with_source(
            format!("Encryption of secret {name:?} was cancelled"),
            error,
        )
    })?;
    writer
        .publish_with_cancel(&plaintext, &key, || *cancellation.borrow())
        .map_err(|error| secret_store_error(name, &validated.storage_dir, "write", error))?;
    eprintln!("Encrypted {name:?} at revision {revision}.");
    Ok(())
}

async fn decrypt(config_path: &Path, name: &str, output_path: &Path) -> Result<(), CliError> {
    validate_name(name).map_err(|error| CliError::with_source("Invalid secret name", error))?;
    let validated = config::load(config_path).map_err(|error| config_error(config_path, error))?;
    let snapshot = SecretSnapshot::read(&validated.storage_dir, name)
        .map_err(|error| secret_store_error(name, &validated.storage_dir, "read", error))?;
    let revision = snapshot.revision();
    if output_path != Path::new("-") {
        match std::fs::symlink_metadata(output_path) {
            Ok(_) => {
                return Err(file_error(
                    "write output file",
                    output_path,
                    io::Error::from(io::ErrorKind::AlreadyExists),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(file_error("write output file", output_path, error)),
        }
    }
    let cancellation = start_cancellation_listener();
    let key = handoff::receive_key(
        &validated,
        name,
        revision,
        Operation::Decrypt,
        cancellation.clone(),
    )
    .await
    .map_err(|error| approval_error(name, error))?;
    ensure_not_cancelled(&cancellation).map_err(|error| {
        CliError::with_source(
            format!("Decryption of secret {name:?} was cancelled"),
            error,
        )
    })?;
    let plaintext = snapshot
        .decrypt(&key)
        .map_err(|error| secret_store_error(name, &validated.storage_dir, "decrypt", error))?;
    if output_path == Path::new("-") {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&plaintext)
            .and_then(|()| stdout.flush())
            .map_err(|error| {
                CliError::with_source("Cannot write decrypted plaintext to stdout", error)
            })?;
    } else {
        storage::write_plaintext_exclusive(output_path, &plaintext).map_err(
            |error| match error {
                StoreError::Io(error) => file_error("write output file", output_path, error),
                other => CliError::with_source(
                    format!("Cannot write output file at {}", output_path.display()),
                    other,
                ),
            },
        )?;
    }
    eprintln!("Decrypted {name:?} at revision {revision}.");
    Ok(())
}

#[derive(Debug)]
struct CliError {
    message: String,
    source: Option<Box<dyn Error>>,
}

impl CliError {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    fn with_source(message: impl Into<String>, source: impl Error + 'static) -> Self {
        Self::with_boxed_source(message, Box::new(source))
    }

    fn with_boxed_source(message: impl Into<String>, source: Box<dyn Error>) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
}

fn config_error(path: &Path, error: Box<dyn Error>) -> CliError {
    let path = path.display();
    match error_kind(&*error) {
        Some(io::ErrorKind::NotFound) => CliError::message(format!(
            "Configuration not found at {path}. Run creds setup."
        )),
        Some(io::ErrorKind::PermissionDenied) => CliError::with_boxed_source(
            format!("Cannot read configuration at {path}; check file permissions"),
            error,
        ),
        Some(io::ErrorKind::InvalidData) => {
            CliError::with_boxed_source(format!("Invalid configuration at {path}"), error)
        }
        _ => CliError::with_boxed_source(format!("Cannot read configuration at {path}"), error),
    }
}

fn setup_error(path: &Path, error: Box<dyn Error>) -> CliError {
    let display_path = path.display();
    if error.to_string().starts_with("Configuration at ") {
        return CliError::message(error.to_string());
    }
    if error.to_string().starts_with("Setup cancelled;") {
        return CliError::message(error.to_string());
    }
    match error_kind(&*error) {
        Some(io::ErrorKind::UnexpectedEof) => {
            CliError::message("Setup cancelled because input ended")
        }
        Some(io::ErrorKind::AlreadyExists) => {
            CliError::message(format!("Cannot write {display_path}: file already exists"))
        }
        Some(io::ErrorKind::PermissionDenied) => CliError::with_boxed_source(
            format!("Cannot set up configuration at {display_path}; check directory permissions"),
            error,
        ),
        _ => CliError::with_boxed_source(
            format!("Setup failed for configuration at {display_path}"),
            error,
        ),
    }
}

fn file_error(action: &str, path: &Path, error: impl Error + 'static) -> CliError {
    let path = path.display();
    match error_kind(&error) {
        Some(io::ErrorKind::AlreadyExists) if action == "write output file" => CliError::message(
            format!("Cannot write {path}: file already exists. Choose a different output path."),
        ),
        Some(io::ErrorKind::PermissionDenied) => CliError::with_source(
            format!("Cannot {action} at {path}; check file and directory permissions"),
            error,
        ),
        Some(io::ErrorKind::NotFound) if action == "read input file" => CliError::with_source(
            format!("Cannot read input file at {path}; check that the file exists"),
            error,
        ),
        Some(io::ErrorKind::NotFound) if action.starts_with("read existing envelope") => {
            CliError::with_source(
                format!("Cannot {action} at {path}; check that the file exists"),
                error,
            )
        }
        _ => CliError::with_source(format!("Cannot {action} at {path}"), error),
    }
}

fn secret_store_error(name: &str, storage_dir: &Path, action: &str, error: StoreError) -> CliError {
    let path = storage_dir.join(format!("{name}.json"));
    match error {
        StoreError::Busy(_) => CliError::message(format!(
            "Secret {name:?} is busy with another encryption (lock: {}). Wait for it to finish.",
            storage_dir.join(format!("{name}.lock")).display()
        )),
        StoreError::RevisionOverflow => CliError::message(format!(
            "Cannot update secret {name:?} at {}: revision limit reached. Use a new secret name.",
            path.display()
        )),
        StoreError::PublishedButDurabilityUncertain(error) => CliError::with_source(
            format!(
                "Secret replacement at {} may already have occurred, but directory sync failed; durability is uncertain",
                path.display()
            ),
            error,
        ),
        StoreError::Io(error) if action == "read" && error.kind() == io::ErrorKind::NotFound => {
            CliError::message(format!(
                "Secret {name:?} not found at {}. Encrypt it first.",
                path.display()
            ))
        }
        StoreError::IoAt {
            action,
            path,
            source,
        } => file_error(&action, &path, source),
        StoreError::Io(error) => {
            if action == "prepare" {
                file_error(
                    &format!("prepare secret {name:?} in storage directory"),
                    storage_dir,
                    error,
                )
            } else {
                file_error(&format!("{action} secret {name:?}"), &path, error)
            }
        }
        StoreError::Envelope(error) => CliError::with_source(
            format!("Cannot {action} secret {name:?} at {}", path.display()),
            error,
        ),
    }
}

fn approval_error(name: &str, error: Box<dyn Error + Send + Sync>) -> CliError {
    match error.downcast::<io::Error>() {
        Ok(error) if error.kind() == io::ErrorKind::Interrupted => {
            CliError::message(format!("Approval for secret {name:?} was cancelled"))
        }
        Ok(error) if error.kind() == io::ErrorKind::TimedOut => {
            CliError::message(format!("Approval for secret {name:?} expired"))
        }
        Ok(error) => CliError::with_source(format!("Approval failed for secret {name:?}"), error),
        Err(error) => {
            CliError::with_boxed_source(format!("Approval failed for secret {name:?}"), error)
        }
    }
}

fn error_kind(error: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            return Some(io_error.kind());
        }
        current = error.source();
    }
    None
}

fn start_cancellation_listener() -> watch::Receiver<bool> {
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            sender.send_replace(true);
        }
    });
    receiver
}

fn ensure_not_cancelled(cancellation: &watch::Receiver<bool>) -> Result<(), io::Error> {
    if *cancellation.borrow() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "operation was cancelled",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::{approval_error, secret_store_error};
    use creds::storage::StoreError;
    use std::{io, path::Path};

    #[test]
    fn timeout_diagnostic_names_the_operation_and_keeps_the_reason() {
        let error = io::Error::new(
            io::ErrorKind::TimedOut,
            "approval expired after two minutes",
        );
        let diagnostic = approval_error("synthetic-secret", Box::new(error));
        assert_eq!(
            diagnostic.to_string(),
            "Approval for secret \"synthetic-secret\" expired"
        );
    }

    #[test]
    fn cancellation_diagnostic_names_the_secret_without_wrapping_details() {
        let error = io::Error::new(io::ErrorKind::Interrupted, "operation cancelled");
        let diagnostic = approval_error("synthetic-secret", Box::new(error));
        assert_eq!(
            diagnostic.to_string(),
            "Approval for secret \"synthetic-secret\" was cancelled"
        );
    }

    #[test]
    fn durability_error_says_the_secret_replacement_may_already_have_occurred() {
        let error = StoreError::PublishedButDurabilityUncertain(io::Error::other(
            "synthetic directory sync failure",
        ));
        let diagnostic = secret_store_error(
            "synthetic-secret",
            Path::new("/synthetic/secrets"),
            "write",
            error,
        );
        let text = diagnostic.to_string();
        assert!(text.contains("/synthetic/secrets/synthetic-secret.json"));
        assert!(text.contains("may already have occurred"));
        assert!(text.contains("directory sync failed"));
        assert!(!text.contains("Custom {"));
    }

    #[test]
    fn revision_limit_diagnostic_names_the_secret_path_and_remedy() {
        let diagnostic = secret_store_error(
            "synthetic-secret",
            Path::new("/synthetic/secrets"),
            "prepare",
            StoreError::RevisionOverflow,
        );
        let text = diagnostic.to_string();
        assert!(text.contains("/synthetic/secrets/synthetic-secret.json"));
        assert!(text.contains("revision limit reached"));
        assert!(text.contains("Use a new secret name"));
    }

    #[test]
    fn transport_error_keeps_a_plain_cause_and_secret_context() {
        let error = io::Error::other("synthetic transport connection failed");
        let diagnostic = approval_error("synthetic-secret", Box::new(error));
        assert_eq!(
            diagnostic.to_string(),
            "Approval failed for secret \"synthetic-secret\": synthetic transport connection failed"
        );
        assert!(!diagnostic.to_string().contains("Custom {"));
    }
}
