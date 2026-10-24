mod probe;

use creds::config;
use std::{error::Error, ffi::OsString, io, path::PathBuf};

type ParsedArgs = (String, Vec<OsString>, Option<PathBuf>);

fn usage() -> &'static str {
    "usage: creds [--config PATH] <setup|check|probe-server>"
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
    if !extra.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()).into());
    }
    match command.as_str() {
        "probe-server" => probe::serve().await?,
        "setup" => {
            let path = match explicit_config_path {
                Some(path) => path,
                None => config::default_config_path()?,
            };
            config::setup(&path)?;
        }
        "check" => {
            let path = match explicit_config_path {
                Some(path) => path,
                None => config::default_config_path()?,
            };
            config::check(&path)?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()).into()),
    }
    Ok(())
}
