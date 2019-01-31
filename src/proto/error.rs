use std::{string, io};
use std::fmt::Display;

#[derive(Debug)]
pub enum Error { 
    NotImplemented,
    StringEncoding,
    IO(io::Error),
    Serialization(String),
    Deserialization(String)
}

impl From<Error> for () {
    fn from(e: Error) -> () {
        ()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(_e: string::FromUtf8Error) -> Error {
        Error::StringEncoding
    }
}

impl serde::ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Serialization(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Deserialization(msg.to_string())
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::NotImplemented => "Method not implemented",
            Error::StringEncoding => "String encoding failed",
            Error::IO(_) => "I/O Error",
            Error::Serialization(_) => "Serialization Error",
            Error::Deserialization(_) => "Deserialization Error"
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            Error::NotImplemented => None,
            Error::StringEncoding => None,
            Error::IO(error) => Some(error),
            Error::Serialization(_) => None,
            Error::Deserialization(_) => None
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error")
    }
}

pub type Result<T> = std::result::Result<T, Error>;