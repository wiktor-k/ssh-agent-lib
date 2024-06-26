//! Agent protocol errors.

use std::{io, string};

use thiserror::Error;

/// SSH protocol error.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Received string was not UTF-8 encoded.
    #[error("String encoding failed: {0}")]
    StringEncoding(#[from] string::FromUtf8Error),

    /// Input/output error.
    #[error("I/O Error: {0}")]
    IO(#[from] io::Error),

    /// Error decoding SSH structures.
    #[error("SSH encoding error: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    /// SSH key format error.
    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    /// SSH signature error.
    #[error("SSH signature error: {0}")]
    SshSignature(#[from] signature::Error),

    /// Received command was not supported.
    #[error("Command not supported ({command})")]
    UnsupportedCommand {
        /// Command code that was unsupported.
        command: u8,
    },

    /// The client expected a different response.
    #[error("Unexpected response received")]
    UnexpectedResponse,
}

/// Protocol result.
pub type ProtoResult<T> = Result<T, ProtoError>;
