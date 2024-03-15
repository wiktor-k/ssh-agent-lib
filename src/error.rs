use super::proto::error::ProtoError;
use std::io;

#[derive(Debug)]
pub enum AgentError {
    Proto(ProtoError),
    IO(io::Error),
}

impl From<ProtoError> for AgentError {
    fn from(e: ProtoError) -> AgentError {
        AgentError::Proto(e)
    }
}

impl From<io::Error> for AgentError {
    fn from(e: io::Error) -> AgentError {
        AgentError::IO(e)
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Proto(proto) => write!(f, "Agent: Protocol error: {}", proto),
            AgentError::IO(error) => write!(f, "Agent: I/O error: {}", error),
        }
    }
}

impl std::error::Error for AgentError {}
