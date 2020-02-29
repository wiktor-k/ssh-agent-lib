use std::{string, io};
use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum ProtoError {
    UnexpectedVariant,
    MessageTooLong,
    StringEncoding(string::FromUtf8Error),
    IO(io::Error),
    Serialization(String),
    Deserialization(String)
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
    fn description(&self) -> &str {
        match self {
            ProtoError::UnexpectedVariant => "Unexpected variant",
            ProtoError::MessageTooLong => "Message too long",
            ProtoError::StringEncoding(_) => "String encoding failed",
            ProtoError::IO(_) => "I/O Error",
            ProtoError::Serialization(_) => "Serialization Error",
            ProtoError::Deserialization(_) => "Deserialization Error"
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            ProtoError::UnexpectedVariant => None,
            ProtoError::MessageTooLong => None,
            ProtoError::StringEncoding(e) => Some(e),
            ProtoError::IO(e) => Some(e),
            ProtoError::Serialization(_) => None,
            ProtoError::Deserialization(_) => None
        }
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

pub type ProtoResult<T> = Result<T, ProtoError>;
