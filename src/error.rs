use std::io;

use thiserror::Error;

use crate::proto::ProtoError;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("Agent: Protocol error: {0}")]
    Proto(#[from] ProtoError),
    #[error("Agent: I/O error: {0}")]
    IO(#[from] io::Error),
}
