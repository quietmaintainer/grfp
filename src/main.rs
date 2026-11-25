use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use grfp::archive;
use grfp::recipe::{self, Profile, TemplatePolicy, TextPolicy, Window};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(version, about = "Lossless global16 file recipe archives")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Encoder {
    /// Candidate row width in bits.
    #[arg(long)]
    width: Option<usize>,
    #[arg(long, value_enum, default_value = "span")]
    text: TextPolicy,
    #[arg(long, value_enum)]
    templates: Option<TemplatePolicy>,
    #[arg(long, value_enum)]
    text_window: Option<Window>,
}

impl From<Encoder> for Profile {
    fn from(value: Encoder) -> Self {
        let (templates, window) = if value.text == TextPolicy::Off {
            (TemplatePolicy::Off, Window::Page)
        } else {
            (TemplatePolicy::Auto, Window::Group)
        };
        Self {
            width: value.width,
            text: value.text,
            templates: value.templates.unwrap_or(templates),
            text_window: value.text_window.unwrap_or(window),
        }
    }
}

#[derive(Args)]
struct Protection {
    /// Repair budget as a percentage of recipe frames.
    #[arg(long, default_value_t = 5)]
    parity: usize,
    #[arg(long, value_parser = ["global16"])]
    fec: Option<String>,
    /// Split the parity rows across this many separate volumes.
    #[arg(long, default_value_t = 0)]
    recovery_volumes: usize,
}

#[derive(Args)]
struct Components {
    /// Additional recovery volume. Repeat for each available volume.
    #[arg(long)]
    volume: Vec<PathBuf>,
    /// Require an Ed25519 signature from this public key.
    #[arg(long)]
    trusted_key: Option<PathBuf>,
}

#[derive(Args)]
struct ArchiveAccess {
    #[command(flatten)]
    components: Components,
    /// Encryption key file for an encrypted archive.
    #[arg(long)]
    key: Option<PathBuf>,
}

impl Components {
    fn options(&self) -> archive::ReadOptions<'_> {
        archive::ReadOptions {
            volumes: &self.volume,
            trusted_key: self.trusted_key.as_deref(),
            ..archive::ReadOptions::default()
        }
    }
}

impl ArchiveAccess {
    fn options(&self) -> archive::ReadOptions<'_> {
        archive::ReadOptions {
            key: self.key.as_deref(),
            ..self.components.options()
        }
    }
}

fn parse_block_size(value: &str) -> Result<usize, String> {
    let normalized = value.to_ascii_lowercase();
    let (digits, scale) = if let Some(digits) = normalized.strip_suffix("kib") {
        (digits, 1024)
    } else {
        (normalized.as_str(), 1)
    };
    let bytes = digits
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .ok_or("Expected a byte count or a size such as 64KiB")?;
    recipe::validate_block_size(bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

#[derive(Subcommand)]
enum Command {
    /// Encode a file or directory and protect it with global16 parity.
    Pack {
        input: PathBuf,
        archive: PathBuf,
        #[command(flatten)]
        profile: Encoder,
        #[command(flatten)]
        protection: Protection,
        /// Original bytes per recovery block, such as 64KiB.
        #[arg(long, value_parser = parse_block_size, default_value = "256KiB")]
        block_size: usize,
        /// Save the filename and metadata of a single file.
        #[arg(long)]
        bundle: bool,
        /// Encrypt using this 32-byte key file.
        #[arg(long)]
        encrypt_key: Option<PathBuf>,
        /// Sign using this Ed25519 private key.
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// Restore the original, inner recipe, and protected archive.
    Recover {
        archive: PathBuf,
        directory: PathBuf,
        #[arg(long)]
        damaged: Option<PathBuf>,
        #[command(flatten)]
        access: ArchiveAccess,
    },
    /// Recover and verify the original file.
    RecoverOriginal {
        archive: PathBuf,
        output: PathBuf,
        /// Optional damaged copy of the original file.
        #[arg(long)]
        damaged: Option<PathBuf>,
        #[command(flatten)]
        access: ArchiveAccess,
    },
    /// Extract archived files and their metadata to a new directory.
    Extract {
        archive: PathBuf,
        directory: PathBuf,
        #[command(flatten)]
        access: ArchiveAccess,
    },
    /// Verify recoverable content and the archive signature.
    Verify {
        archive: PathBuf,
        #[command(flatten)]
        access: ArchiveAccess,
    },
    /// Generate a 32-byte encryption key.
    KeygenEncryption { key: PathBuf },
    /// Generate an Ed25519 signing key and its public key.
    KeygenSigning {
        private_key: PathBuf,
        public_key: PathBuf,
    },
    /// Protect an extracted GRF1 or GRF2 recipe using its original encoder settings.
    Protect {
        recipe: PathBuf,
        archive: PathBuf,
        #[command(flatten)]
        profile: Encoder,
        #[command(flatten)]
        protection: Protection,
    },
    /// Change an intact archive's parity budget.
    Reprotect {
        archive: PathBuf,
        output: PathBuf,
        #[arg(long)]
        parity: Option<usize>,
        #[arg(long, value_parser = ["global16"])]
        fec: Option<String>,
        /// Split the regenerated parity rows across separate volumes.
        #[arg(long, default_value_t = 0)]
        recovery_volumes: usize,
    },
    /// Restore a file from an extracted inner recipe.
    Restore { recipe: PathBuf, output: PathBuf },
    /// Restore an extracted recipe with help from the surviving original.
    Repair {
        recipe: PathBuf,
        damaged: PathBuf,
        output: PathBuf,
    },
    /// Show the archive catalog or inner recipe statistics.
    Inspect {
        archive: PathBuf,
        #[command(flatten)]
        components: Components,
    },
}

fn run(command: Command) -> Result<Value> {
    Ok(match command {
        Command::Pack {
            input,
            archive: output,
            profile,
            protection,
            block_size,
            bundle,
            encrypt_key,
            sign_key,
        } => serde_json::to_value(archive::pack_with(
            &input,
            &output,
            profile.into(),
            &archive::PackOptions {
                parity: protection.parity,
                block_size,
                recovery_volumes: protection.recovery_volumes,
                bundle,
                encrypt_key: encrypt_key.as_deref(),
                sign_key: sign_key.as_deref(),
            },
        )?)?,
        Command::Recover {
            archive: source,
            directory,
            damaged,
            access,
        } => serde_json::to_value(archive::recover_with(
            &source,
            &directory,
            damaged.as_deref(),
            &access.options(),
        )?)?,
        Command::RecoverOriginal {
            archive: source,
            output,
            damaged,
            access,
        } => serde_json::to_value(archive::recover_original_with(
            &source,
            &output,
            damaged.as_deref(),
            &access.options(),
        )?)?,
        Command::Extract {
            archive: source,
            directory,
            access,
        } => serde_json::to_value(archive::extract(&source, &directory, &access.options())?)?,
        Command::Verify {
            archive: source,
            access,
        } => serde_json::to_value(archive::verify(&source, &access.options())?)?,
        Command::KeygenEncryption { key } => {
            archive::generate_encryption_key(&key)?;
            json!({ "key": key })
        }
        Command::KeygenSigning {
            private_key,
            public_key,
        } => {
            archive::generate_signing_key(&private_key, &public_key)?;
            json!({ "privateKey": private_key, "publicKey": public_key })
        }
        Command::Protect {
            recipe,
            archive: output,
            profile,
            protection,
        } => serde_json::to_value(archive::protect_with_volumes(
            &recipe,
            &output,
            profile.into(),
            protection.parity,
            protection.recovery_volumes,
        )?)?,
        Command::Reprotect {
            archive: source,
            output,
            parity,
            recovery_volumes,
            ..
        } => serde_json::to_value(archive::reprotect_with_volumes(
            &source,
            &output,
            parity,
            recovery_volumes,
        )?)?,
        Command::Restore { recipe, output } => recipe::restore(&recipe, &output, None)?,
        Command::Repair {
            recipe,
            damaged,
            output,
        } => recipe::restore(&recipe, &output, Some(&damaged))?,
        Command::Inspect {
            archive: source,
            components,
        } => archive::inspect_with(&source, &components.options())?,
    })
}

fn main() -> ExitCode {
    match run(Cli::parse().command).and_then(|value| Ok(serde_json::to_string_pretty(&value)?)) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("grfp: {error:#}");
            ExitCode::FAILURE
        }
    }
}
