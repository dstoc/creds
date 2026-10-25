use creds::{
    config,
    handoff::{self, Operation},
    protocol::validate_name,
    storage::{self, SecretSnapshot, SecretWriter},
};
mod cli;

use clap::{CommandFactory, Parser, error::ErrorKind};
use std::{
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
            let path = config_path(explicit_config_path)?;
            config::setup(&path)?;
        }
        cli::Commands::Check => {
            let path = config_path(explicit_config_path)?;
            config::check(&path)?;
        }
        cli::Commands::Encrypt { name, input } => {
            let path = config_path(explicit_config_path)?;
            encrypt(&path, &name, &input).await?;
        }
        cli::Commands::Decrypt { name, output } => {
            let path = config_path(explicit_config_path)?;
            decrypt(&path, &name, &output).await?;
        }
    }
    Ok(())
}

fn validate_config_arguments() {
    let mut arguments = std::env::args_os().skip(1);
    let mut config_seen = false;

    while let Some(argument) = arguments.next() {
        if argument == "--config" {
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

fn config_path(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn Error>> {
    match explicit {
        Some(path) => Ok(path),
        None => Ok(config::default_config_path()?),
    }
}

async fn encrypt(config_path: &Path, name: &str, input_path: &Path) -> Result<(), Box<dyn Error>> {
    validate_name(name)?;
    let plaintext = if input_path == Path::new("-") {
        storage::read_plaintext(io::stdin().lock())?
    } else {
        storage::read_plaintext_file(input_path)?
    };
    let validated = config::load(config_path)?;
    let writer = SecretWriter::begin(&validated.storage_dir, name)?;
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
    .map_err(|error| io::Error::other(error.to_string()))?;
    ensure_not_cancelled(&cancellation)?;
    writer.publish_with_cancel(&plaintext, &key, || *cancellation.borrow())?;
    eprintln!("Encrypted {name:?} at revision {revision}.");
    Ok(())
}

async fn decrypt(config_path: &Path, name: &str, output_path: &Path) -> Result<(), Box<dyn Error>> {
    validate_name(name)?;
    let validated = config::load(config_path)?;
    let snapshot = SecretSnapshot::read(&validated.storage_dir, name)?;
    let revision = snapshot.revision();
    let cancellation = start_cancellation_listener();
    let key = handoff::receive_key(
        &validated,
        name,
        revision,
        Operation::Decrypt,
        cancellation.clone(),
    )
    .await
    .map_err(|error| io::Error::other(error.to_string()))?;
    ensure_not_cancelled(&cancellation)?;
    let plaintext = snapshot.decrypt(&key)?;
    if output_path == Path::new("-") {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&plaintext)?;
        stdout.flush()?;
    } else {
        storage::write_plaintext_exclusive(output_path, &plaintext)?;
    }
    eprintln!("Decrypted {name:?} revision {revision}.");
    Ok(())
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
