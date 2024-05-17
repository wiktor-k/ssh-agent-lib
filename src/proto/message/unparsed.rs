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

    /// Expose the inner content in raw format.
    pub fn as_raw(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Creates a new value from a raw content
    pub fn from_raw(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Creates an [`Unparsed`] content from a value.
    /// The value will be encoded according to [`ssh_encoding::Encode`].
    pub fn new<T>(value: &T) -> ssh_encoding::Result<Self>
    where
        T: ssh_encoding::Encode,
    {
        let mut buffer: Vec<u8> = vec![];
        value.encode(&mut buffer)?;
        Ok(Self(buffer))
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
