use super::proto::error::ProtoError;
use std::io;

#[derive(Debug)]
pub enum AgentError {
    User,
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
