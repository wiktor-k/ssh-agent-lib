//! Container for SSH agent protocol extension messages

use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};

use crate::proto::{
    extension::{KeyConstraintExtension, MessageExtension},
    Error, Result, Unparsed,
};

/// Container for SSH agent protocol extension messages
///
/// This structure is sent as part of a [`Request::Extension`](super::Request::Extension) (`SSH_AGENT_EXTENSION_RESPONSE`) message.
///
/// Described in [draft-miller-ssh-agent-14 § 3.8](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.8).
#[derive(Clone, PartialEq, Debug)]
pub struct Extension {
    /// Indicates the type of the extension message (as a UTF-8 string)
    ///
    /// Extension names should be suffixed by the implementation domain
    /// as per [RFC4251 § 4.2](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.2),
    /// e.g. "foo@example.com"
    pub name: String,

    /// Extension-specific content
    pub details: Unparsed,
}

impl Extension {
    /// Create a new [`Extension`] from a [`MessageExtension`]
    /// structure implementing [`ssh_encoding::Encode`]
    pub fn new_message<T>(extension: T) -> Result<Self>
    where
        T: MessageExtension + Encode,
    {
        Ok(Self {
            name: T::NAME.into(),
            details: Unparsed::new(&extension)?,
        })
    }

    /// Attempt to parse a an extension object into a
    /// [`MessageExtension`] structure
    /// implementing [`ssh_encoding::Decode`].
    ///
    /// If there is a mismatch between the extension name
    /// and the [`MessageExtension::NAME`], this method
    /// will return [`None`]
    pub fn parse_message<T>(&self) -> std::result::Result<Option<T>, <T as Decode>::Error>
    where
        T: MessageExtension + Decode,
    {
        if T::NAME == self.name {
            Ok(Some(self.details.parse::<T>()?))
        } else {
            Ok(None)
        }
    }

    /// Create a new [`Extension`] from a [`KeyConstraintExtension`]
    /// structure implementing [`ssh_encoding::Encode`]
    pub fn new_key_constraint<T>(extension: T) -> Result<Self>
    where
        T: KeyConstraintExtension + Encode,
    {
        Ok(Self {
            name: T::NAME.into(),
            details: Unparsed::new(&extension)?,
        })
    }

    /// Attempt to parse a an extension object into a
    /// [`KeyConstraintExtension`] structure
    /// implementing [`ssh_encoding::Decode`].
    ///
    /// If there is a mismatch between the extension name
    /// and the [`KeyConstraintExtension::NAME`], this method
    /// will return [`None`]
    pub fn parse_key_constraint<T>(&self) -> std::result::Result<Option<T>, <T as Decode>::Error>
    where
        T: KeyConstraintExtension + Decode,
    {
        if T::NAME == self.name {
            Ok(Some(self.details.parse::<T>()?))
        } else {
            Ok(None)
        }
    }
}

impl Decode for Extension {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let name = String::decode(reader)?;
        let mut details = vec![0; reader.remaining_len()];
        reader.read(&mut details)?;
        Ok(Self {
            name,
            details: Unparsed::from_raw(details),
        })
    }
}

impl Encode for Extension {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.name.encoded_len()?, self.details.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.name.encode(writer)?;
        self.details.encode(writer)?;
        Ok(())
    }
}
