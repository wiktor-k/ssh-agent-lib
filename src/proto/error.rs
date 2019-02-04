use std::{string, io};
use std::fmt::Display;

#[derive(Debug)]
pub enum ProtoError { 
    StringEncoding,
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
    fn from(_e: string::FromUtf8Error) -> ProtoError {
        ProtoError::StringEncoding
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
            ProtoError::StringEncoding => "String encoding failed",
            ProtoError::IO(_) => "I/O Error",
            ProtoError::Serialization(_) => "Serialization Error",
            ProtoError::Deserialization(_) => "Deserialization Error"
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            ProtoError::StringEncoding => None,
            ProtoError::IO(error) => Some(error),
            ProtoError::Serialization(_) => None,
            ProtoError::Deserialization(_) => None
        }
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error")
    }
}

pub type ProtoResult<T> = Result<T, ProtoError>;