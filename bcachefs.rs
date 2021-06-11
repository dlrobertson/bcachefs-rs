#![deny(missing_docs)]
#![deny(unused)]

//! A implementation of the userspace tooling for the bcachefs filesystem in Rust

use std::convert::TryInto;

use clap::{AppSettings, Clap};
use env_logger::Builder;
use log::{debug, LevelFilter};
use uuid::Uuid;

use libbcachefs::{self, format_device, BchError, Result};

/// Bcachefs userspace tooling.
#[derive(Clap)]
#[clap(version = "1.0", author = "Dan Robertson <dan@dlrobertson.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    /// Set the log level
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,
    /// The real command we will run
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
enum SubCommand {
    /// Format a given device
    Format(FormatArgs),
}

const MIN_BLOCK_SHIFT: u16 = 9;
const MAX_BLOCK_SHIFT: u16 = 15;

fn valid_label(s: &str) -> std::result::Result<(), String> {
    let len = s.bytes().len();
    if len > 32 {
        Err(format!("Label string of length `{}` too long.", len))
    } else {
        Ok(())
    }
}

fn valid_block_size(s: &str) -> std::result::Result<(), String> {
    match s.parse::<u16>() {
        Ok(size) if size >= 1 << MIN_BLOCK_SHIFT && size <= 1 << MAX_BLOCK_SHIFT => Ok(()),
        Ok(size) => Err(format!("invalid block size: {}", size)),
        _ => Err(format!("failed to parse integer: {}", s)),
    }
}

// Most of the complexity comes from sorting out the number of replicas. A
// user may specify `replicas` OR `data-replicas` AND `metadata-replicas`.
/// The arguments that the format subcommand may be provided.
#[derive(Debug, Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct FormatArgs {
    /// The number of metadata-replicas and data-replicas to be created
    #[clap(short = 'r', long = "replicas")]
    #[clap(conflicts_with_all = &["metadata-replicas", "data-replicas"])]
    replicas: Option<u64>,
    /// The number of metadata-replicas to be created
    #[clap(short = 'm', long = "metadata-replicas")]
    #[clap(requires = "data-replicas")]
    metadata_replicas: Option<u64>,
    /// The number of data-replicas to be created
    #[clap(short = 'd', long = "data-replicas")]
    #[clap(requires = "metadata-replicas")]
    data_replicas: Option<u64>,
    /// The formatted device should be encrypted
    #[clap(short = 'e', long = "encrypted")]
    encrypted: bool,
    /// Do not prompt for a passphrase on creation
    #[clap(long = "--no-passphrase")]
    no_passphrase: bool,
    /// Do not attempt to initialize the device
    #[clap(long = "--no-initialize")]
    no_initialize: bool,
    /// The disk label
    #[clap(short = 'l', long = "label", validator = valid_label)]
    label: Option<String>,
    /// The disk uuid
    #[clap(short = 'u', long = "uuid")]
    uuid: Option<Uuid>,
    /// Force creation if a preexisting FS exists
    #[clap(short = 'f', long = "force")]
    force: bool,
    /// The size of the filesystem
    #[clap(long = "superblock-size", default_value = "2048")]
    superblock_size: u64,
    /// The block size of the new FS
    #[clap(long = "block-size", default_value = "512", validator = valid_block_size)]
    block_size: u16,
    /// The devices to format
    #[clap(min_values = 1, required = true)]
    devices: Vec<String>,
}

impl TryInto<libbcachefs::FormatArgs> for FormatArgs {
    type Error = BchError;

    fn try_into(self) -> Result<libbcachefs::FormatArgs> {
        let metadata_replicas;
        let data_replicas;
        match (self.replicas, self.metadata_replicas, self.data_replicas) {
            (None, Some(m_repls), Some(d_repls)) => {
                if m_repls > self.devices.len() as u64 {
                    return Err(BchError::Str(format!(
                        "Invalid --metadata-replicas value `{}` provided for available devices",
                        m_repls
                    )));
                } else if d_repls > self.devices.len() as u64 {
                    return Err(BchError::Str(format!(
                        "Invalid --data-replicas value `{}` provided for available devices",
                        d_repls
                    )));
                } else {
                    metadata_replicas = m_repls;
                    data_replicas = d_repls;
                }
            }
            (Some(repls), None, None) => {
                if repls > self.devices.len() as u64 {
                    return Err(BchError::Str(format!(
                        "Invalid --replicas value `{}` provided for available devices",
                        repls
                    )));
                } else {
                    metadata_replicas = repls;
                    data_replicas = repls;
                }
            }
            (None, None, None) => {
                metadata_replicas = 1;
                data_replicas = 1;
            }
            _ => {
                return Err(BchError::Str(format!(
                    "Invalid replica options provided: replicas={} metadata={} data={}",
                    self.replicas.unwrap_or(0),
                    self.metadata_replicas.unwrap_or(0),
                    self.data_replicas.unwrap_or(0)
                )));
            }
        }

        debug!(
            "metadata_replicas={} data_replicas={}",
            metadata_replicas, data_replicas
        );

        Ok(libbcachefs::FormatArgs {
            metadata_replicas,
            data_replicas,
            encrypted: self.encrypted,
            no_passphrase: self.no_passphrase,
            no_initialize: self.no_initialize,
            label: self.label,
            uuid: self.uuid.unwrap_or(Uuid::new_v4()),
            force: self.force,
            superblock_size: self.superblock_size,
            block_size: self.block_size,
            devices: self.devices,
        })
    }
}

fn main() {
    let opts: Opts = Opts::parse();

    let mut builder = Builder::new();

    match opts.verbose {
        0 => builder.filter_level(LevelFilter::Error),
        1 => builder.filter_level(LevelFilter::Warn),
        2 => builder.filter_level(LevelFilter::Info),
        3..=std::u8::MAX => builder.filter_level(LevelFilter::Debug),
    };

    builder.parse_default_env();
    builder.init();

    match opts.subcmd {
        SubCommand::Format(args) => {
            debug!("format args={:?}", args);
            match args.try_into() {
                Ok(args) => format_device(args),
                Err(e) => {
                    println!("Failed to format input: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
