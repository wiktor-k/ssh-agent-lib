use std::io;

use crate::proto::ProtoError;

#[derive(Debug)]
pub enum AgentError {
    //Ssh(ssh_key::Error),
    Proto(ProtoError),
    IO(io::Error),
}

impl From<ProtoError> for AgentError {
    fn from(e: ProtoError) -> AgentError {
        AgentError::Proto(e)
    }
}

//impl From<ssh_key::Error> for AgentError {
//    fn from(e: ssh_key::Error) -> AgentError {
//        AgentError::Ssh(e)
//    }
//}

impl From<io::Error> for AgentError {
    fn from(e: io::Error) -> AgentError {
        AgentError::IO(e)
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            //AgentError::Ssh(e) => write!(f, "Agent: Ssh key error: {e}"),
            AgentError::Proto(proto) => write!(f, "Agent: Protocol error: {}", proto),
            AgentError::IO(error) => write!(f, "Agent: I/O error: {}", error),
        }
    }
}

impl std::error::Error for AgentError {}
