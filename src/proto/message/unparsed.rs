//! Generic container for unknown content within a message.

use ssh_encoding::{self, Decode, Encode, Reader, Writer};

use crate::proto::{Error, Result};

/// Generic container for message specific content, which cannot be
/// decoded into a known type.
///
/// This may include:
/// * [`Extension`](super::Extension)-specific content,
/// * Message content in the [`Request::Unknown`](super::request::Request) variant
///
/// Accessing the inner `Vec<u8>` is only possible via conversion methods.
#[derive(Debug, PartialEq, Clone)]
pub struct Unparsed(Vec<u8>);

impl Unparsed {
    /// Decode unparsed bytes as SSH structures.
    pub fn parse<T>(&self) -> std::result::Result<T, <T as Decode>::Error>
    where
        T: Decode,
    {
        let mut v = &self.0[..];
        T::decode(&mut v)
    }

    /// Obtain the unparsed bytes as a `Vec<u8>`, consuming the `Unparsed`
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Unparsed {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Unparsed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Encode for Unparsed {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        Ok(self.0.len())
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        // NOTE: Unparsed fields do not embed a length u32,
        // as the inner Vec<u8> encoding is implementation-defined.
        writer.write(&self.0[..])?;

        Ok(())
    }
}

impl Decode for Unparsed {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        // NOTE: Unparsed fields do not embed a length u32,
        // as the inner Vec<u8> encoding is implementation-defined.
        let mut result = vec![0u8; reader.remaining_len()];
        reader.read(&mut result)?;

        Ok(Self(result))
    }
}
