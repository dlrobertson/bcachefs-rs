#![deny(missing_docs)]

//! Rust library for working with the bcachefs filesystem.

use std::fmt;
use std::io;

use libblkid_rs::BlkidErr;

mod format;
mod super_block;

pub use format::{format_device, Args as FormatArgs, ErrorAction};

pub use super_block::{
    DataTypes, Features, Field, MemberField, MemberFlag, SuperBlock, SuperBlockFlag,
    SuperBlockFlags, SuperBlockLayout,
};

/// Core error type for the bcachefs tooling implementations
#[derive(Debug)]
pub enum BchError {
    /// An error that originated from blkid
    Blkid(BlkidErr),
    /// An error that originated from io in the Rust standard library
    Io(io::Error),
    /// An error that originated from the nix crate
    Nix(nix::Error),
    /// A simple string error
    Str(String),
    /// A error from the uuid library
    Uuid(uuid::Error),
    /// The given buffer was too small
    Exhausted,
    /// The input value is invalid
    Einval(String),
}

impl From<BlkidErr> for BchError {
    fn from(other: BlkidErr) -> BchError {
        BchError::Blkid(other)
    }
}

impl From<io::Error> for BchError {
    fn from(other: io::Error) -> BchError {
        BchError::Io(other)
    }
}

impl From<nix::Error> for BchError {
    fn from(other: nix::Error) -> BchError {
        BchError::Nix(other)
    }
}

impl From<uuid::Error> for BchError {
    fn from(other: uuid::Error) -> BchError {
        BchError::Uuid(other)
    }
}

/// Core result type used by bcahcefs tooling implementations
pub type Result<T> = std::result::Result<T, BchError>;

impl fmt::Display for BchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &BchError::Blkid(ref err) => {
                write!(f, "blkid error: {}", err.to_string())
            }
            &BchError::Io(ref err) => {
                write!(f, "io error: {}", err.to_string())
            }
            &BchError::Nix(ref err) => {
                write!(f, "nix error: {}", err.to_string())
            }
            &BchError::Uuid(ref err) => {
                write!(f, "uuid error: {}", err.to_string())
            }
            &BchError::Str(ref err) => {
                write!(f, "{}", err)
            }
            &BchError::Exhausted => {
                write!(f, "Input buffer too short")
            }
            &BchError::Einval(ref s) => {
                write!(f, "Input value invalid: {}", s)
            }
        }
    }
}
