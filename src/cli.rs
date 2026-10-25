use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "creds",
    version,
    about = "Encrypt named secrets with browser-approved keys.",
    long_about = "Encrypt and decrypt named secrets with keys approved through the trusted browser app. Setup creates the local configuration, and check validates it; both operate locally without starting an approval listener.",
    after_help = "Examples:\n  creds setup\n  creds --config ./creds.toml check\n  creds encrypt deploy-token ./token.txt\n  printf '%s' \"$TOKEN\" | creds encrypt deploy-token -\n  creds decrypt deploy-token ./token.txt\n  creds decrypt deploy-token -",
    subcommand_required = true,
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// Use PATH instead of the default configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Create or replace the local configuration.
    #[command(
        long_about = "Create the local configuration and storage directory. Setup prompts for the trusted approval app URL, machine name, storage path, and public key.",
        after_help = "Examples:\n  creds setup\n  creds --config ./creds.toml setup"
    )]
    Setup,

    /// Check the local configuration and storage directory.
    #[command(
        long_about = "Validate the configuration, public key, and storage directory. This command does not start an approval listener.",
        after_help = "Examples:\n  creds check\n  creds --config ./creds.toml check"
    )]
    Check,

    /// Encrypt a named secret from a file or stdin.
    #[command(
        long_about = "Encrypt the input as a named secret after browser approval. INPUT is a file path or - to read plaintext from stdin. Diagnostics and approval instructions go to stderr; successful encryption writes no plaintext to stdout.",
        after_help = "Examples:\n  creds encrypt deploy-token ./token.txt\n  printf '%s' \"$TOKEN\" | creds encrypt deploy-token -\n  creds --config ./creds.toml encrypt deploy-token -"
    )]
    Encrypt {
        /// Case-sensitive name for the secret.
        #[arg(value_name = "NAME")]
        name: String,
        /// File to encrypt, or - to read plaintext from stdin.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
    },

    /// Decrypt a named secret to a file or stdout.
    #[command(
        long_about = "Decrypt a named secret after browser approval. OUTPUT is a new file path or - to write plaintext to stdout. Diagnostics go to stderr.",
        after_help = "Examples:\n  creds decrypt deploy-token ./token.txt\n  creds decrypt deploy-token -\n  creds --config ./creds.toml decrypt deploy-token -"
    )]
    Decrypt {
        /// Case-sensitive name for the secret.
        #[arg(value_name = "NAME")]
        name: String,
        /// New plaintext file to create, or - to write plaintext to stdout.
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::{Parser, error::ErrorKind};
    use std::path::{Path, PathBuf};

    #[test]
    fn parses_commands_and_global_config_before_or_after_the_command() {
        assert!(matches!(
            Cli::try_parse_from(["creds", "setup"]).unwrap().command,
            Commands::Setup
        ));
        assert!(matches!(
            Cli::try_parse_from(["creds", "--config", "creds.toml", "check"])
                .unwrap()
                .command,
            Commands::Check
        ));

        let cli = Cli::try_parse_from(["creds", "check", "--config=creds.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("creds.toml")));

        let cli = Cli::try_parse_from(["creds", "encrypt", "Token", "-"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Encrypt { name, input }
                if name == "Token" && input == Path::new("-")
        ));

        let cli = Cli::try_parse_from(["creds", "decrypt", "Token", "output.txt"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Decrypt { name, output }
                if name == "Token" && output == Path::new("output.txt")
        ));
    }

    #[test]
    fn rejects_missing_unknown_and_extra_arguments() {
        for arguments in [
            vec!["creds", "bogus"],
            vec!["creds", "--unknown", "check"],
            vec!["creds", "setup", "extra"],
            vec!["creds", "check", "extra"],
            vec!["creds", "encrypt", "name"],
            vec!["creds", "encrypt", "name", "input", "extra"],
            vec!["creds", "decrypt"],
            vec!["creds", "decrypt", "name", "output", "extra"],
        ] {
            let error = Cli::try_parse_from(arguments).unwrap_err();
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::MissingSubcommand
                        | ErrorKind::InvalidSubcommand
                        | ErrorKind::UnknownArgument
                        | ErrorKind::MissingRequiredArgument
                        | ErrorKind::TooManyValues
                        | ErrorKind::ArgumentConflict
                ),
                "unexpected parser error kind: {error}"
            );
            assert!(error.to_string().contains("Usage:"), "{error}");
        }
    }

    #[test]
    fn each_command_help_is_specific_and_contains_examples() {
        for (command, expected) in [
            ("setup", "Create the local configuration"),
            ("check", "Validate the configuration"),
            ("encrypt", "File to encrypt"),
            ("decrypt", "write plaintext to stdout"),
        ] {
            let error = Cli::try_parse_from(["creds", command, "--help"]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DisplayHelp);
            let help = error.to_string();
            assert!(help.contains(expected), "{command} help was: {help}");
            assert!(help.contains("Examples:"), "{command} help was: {help}");
        }
    }
}
