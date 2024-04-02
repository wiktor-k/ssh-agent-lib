use std::error::Error;
use std::{io, string};

#[derive(Debug)]
pub enum ProtoError {
    UnexpectedVariant,
    MessageTooLong,
    StringEncoding(string::FromUtf8Error),
    IO(io::Error),
    SshEncoding(ssh_encoding::Error),
    SshKey(ssh_key::Error),
}

impl From<ProtoError> for () {
    fn from(_e: ProtoError) {}
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> ProtoError {
        ProtoError::IO(e)
    }
}

impl From<ssh_encoding::Error> for ProtoError {
    fn from(e: ssh_encoding::Error) -> ProtoError {
        ProtoError::SshEncoding(e)
    }
}

impl From<ssh_key::Error> for ProtoError {
    fn from(e: ssh_key::Error) -> ProtoError {
        ProtoError::SshKey(e)
    }
}

impl From<string::FromUtf8Error> for ProtoError {
    fn from(e: string::FromUtf8Error) -> ProtoError {
        ProtoError::StringEncoding(e)
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProtoError::UnexpectedVariant => None,
            ProtoError::MessageTooLong => None,
            ProtoError::StringEncoding(e) => Some(e),
            ProtoError::IO(e) => Some(e),
            ProtoError::SshEncoding(e) => Some(e),
            ProtoError::SshKey(e) => Some(e),
        }
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProtoError::UnexpectedVariant => f.write_str("Unexpected variant"),
            ProtoError::MessageTooLong => f.write_str("Message too long"),
            ProtoError::StringEncoding(_) => f.write_str("String encoding failed"),
            ProtoError::IO(_) => f.write_str("I/O Error"),
            ProtoError::SshEncoding(_) => f.write_str("SSH encoding Error"),
            ProtoError::SshKey(e) => write!(f, "SSH key Error: {e}"),
        }
    }
}

pub type ProtoResult<T> = Result<T, ProtoError>;
