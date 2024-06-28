//! SSH agent errors.

use std::io;

use thiserror::Error;

use crate::proto::ProtoError;

/// SSH agent error.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Protocol error.
    #[error("Agent: Protocol error: {0}")]
    Proto(#[from] ProtoError),

    /// Input/output error.
    #[error("Agent: I/O error: {0}")]
    IO(#[from] io::Error),

    /// Other unspecified error.
    #[error("Other error: {0:#}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Generic agent extension failure
    #[error("Generic agent extension failure")]
    ExtensionFailure,

    /// Generic agent failure
    #[error("Generic agent failure")]
    Failure,
}

impl AgentError {
    /// Construct an `AgentError` from other error type.
    pub fn other(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other(Box::new(error))
    }
}
