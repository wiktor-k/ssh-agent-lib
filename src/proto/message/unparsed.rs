//! Generic container for [`Extension`](super::Extension)-specific content

use ssh_encoding::{self, Decode, Encode, Writer};

/// Generic container for [`Extension`](super::Extension)-specific content.
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
}

impl From<Vec<u8>> for Unparsed {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Encode for Unparsed {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        Ok(self.0.len())
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        // NOTE: Unparsed fields do not embed a length u32,
        // as the inner Vec<u8> encoding is implementation-defined
        // (usually an Extension)
        writer.write(&self.0[..])?;

        Ok(())
    }
}
