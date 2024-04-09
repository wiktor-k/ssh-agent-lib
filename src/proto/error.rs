use std::{io, string};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("String encoding failed: {0}")]
    StringEncoding(#[from] string::FromUtf8Error),
    #[error("I/O Error: {0}")]
    IO(#[from] io::Error),
    #[error("SSH encoding error: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),
    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("Command not supported ({command})")]
    UnsupportedCommand { command: u8 },
}

pub type ProtoResult<T> = Result<T, ProtoError>;
