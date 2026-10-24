mod probe;

use creds::{
    config,
    handoff::{self, Operation},
    protocol::validate_name,
    storage::{self, SecretSnapshot, SecretWriter},
};
use std::{
    error::Error,
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tokio::sync::watch;

type ParsedArgs = (String, Vec<OsString>, Option<PathBuf>);

fn usage() -> &'static str {
    "usage: creds [--config PATH] <setup|check|probe-server|encrypt NAME INPUT|decrypt NAME OUTPUT>"
}

fn parse_args() -> Result<ParsedArgs, Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1).peekable();
    let mut command_args = Vec::new();
    let mut config_path = None;
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            if config_path.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--config may be used only once",
                )
                .into());
            }
            let Some(path) = arguments.next() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--config requires a path",
                )
                .into());
            };
            if path.to_string_lossy().starts_with('-') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--config requires a path",
                )
                .into());
            }
            config_path = Some(PathBuf::from(path));
        } else if let Some(path) = argument.to_string_lossy().strip_prefix("--config=") {
            if config_path.is_some() || path.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--config requires one non-empty path",
                )
                .into());
            }
            config_path = Some(PathBuf::from(path));
        } else {
            command_args.push(argument);
        }
    }
    let Some(command) = command_args.first().and_then(|value| value.to_str()) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()).into());
    };
    Ok((
        command.to_owned(),
        command_args.into_iter().skip(1).collect(),
        config_path,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (command, extra, explicit_config_path) = parse_args()?;
    match command.as_str() {
        "probe-server" => {
            require_no_extra(&extra)?;
            probe::serve().await?;
        }
        "setup" => {
            require_no_extra(&extra)?;
            let path = match explicit_config_path {
                Some(path) => path,
                None => config::default_config_path()?,
            };
            config::setup(&path)?;
        }
        "check" => {
            require_no_extra(&extra)?;
            let path = match explicit_config_path {
                Some(path) => path,
                None => config::default_config_path()?,
            };
            config::check(&path)?;
        }
        "encrypt" => {
            let (name, input) = parse_operation_args(&extra)?;
            let path = config_path(explicit_config_path)?;
            encrypt(&path, name, input).await?;
        }
        "decrypt" => {
            let (name, output) = parse_operation_args(&extra)?;
            let path = config_path(explicit_config_path)?;
            decrypt(&path, name, output).await?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()).into()),
    }
    Ok(())
}

fn require_no_extra(extra: &[OsString]) -> Result<(), io::Error> {
    if extra.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, usage()))
    }
}

fn parse_operation_args(extra: &[OsString]) -> Result<(&str, &Path), io::Error> {
    if extra.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()));
    }
    let name = extra[0]
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "secret name must be UTF-8"))?;
    Ok((name, Path::new(&extra[1])))
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
