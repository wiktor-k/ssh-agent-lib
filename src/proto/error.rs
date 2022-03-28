use std::error::Error;
use std::fmt::Display;
use std::{io, string};

#[derive(Debug)]
pub enum ProtoError {
    UnexpectedVariant,
    MessageTooLong,
    StringEncoding(string::FromUtf8Error),
    IO(io::Error),
    Serialization(String),
    Deserialization(String),
}

impl From<ProtoError> for () {
    fn from(_e: ProtoError) -> () {
        ()
    }
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> ProtoError {
        ProtoError::IO(e)
    }
}

impl From<string::FromUtf8Error> for ProtoError {
    fn from(e: string::FromUtf8Error) -> ProtoError {
        ProtoError::StringEncoding(e)
    }
}

impl serde::ser::Error for ProtoError {
    fn custom<T: Display>(msg: T) -> Self {
        ProtoError::Serialization(msg.to_string())
    }
}

impl serde::de::Error for ProtoError {
    fn custom<T: Display>(msg: T) -> Self {
        ProtoError::Deserialization(msg.to_string())
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProtoError::UnexpectedVariant => None,
            ProtoError::MessageTooLong => None,
            ProtoError::StringEncoding(e) => Some(e),
            ProtoError::IO(e) => Some(e),
            ProtoError::Serialization(_) => None,
            ProtoError::Deserialization(_) => None,
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
            ProtoError::Serialization(_) => f.write_str("Serialization Error"),
            ProtoError::Deserialization(_) => f.write_str("Deserialization Error"),
        }
    }
}

pub type ProtoResult<T> = Result<T, ProtoError>;
