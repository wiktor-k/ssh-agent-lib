//! SSH agent protocol request messages.

use ssh_encoding::{CheckedSum, Decode, Encode, Reader, Writer};

use super::{
    AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, RemoveIdentity,
    SignRequest, SmartcardKey,
};
use crate::proto::{Error, Result};

/// SSH agent protocol request messages.
///
/// These message types are sent from a client *to* an agent.
///
/// Described in [draft-miller-ssh-agent-14 § 3](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3).
#[derive(Clone, PartialEq, Debug)]
pub enum Request {
    /// Request a list of all identities (public key/certificate & comment)
    /// from an agent
    RequestIdentities,

    /// Perform a private key signature operation using a key
    /// stored in the agent
    SignRequest(SignRequest),

    /// Add an identity (private key/certificate & comment) to an agent
    AddIdentity(AddIdentity),

    /// Remove an identity from an agent
    RemoveIdentity(RemoveIdentity),

    /// Remove all identities from an agent
    RemoveAllIdentities,

    /// Add an identity (private key/certificate & comment) to an agent
    /// where the private key is stored on a hardware token
    AddSmartcardKey(SmartcardKey),

    /// Remove a key stored on a hardware token from an agent
    RemoveSmartcardKey(SmartcardKey),

    /// Temporarily lock an agent with a pass-phrase
    Lock(String),

    /// Unlock a locked agaent with a pass-phrase
    Unlock(String),

    /// Add an identity (private key/certificate & comment) to an agent,
    /// with constraints on it's usage
    AddIdConstrained(AddIdentityConstrained),

    /// Add an identity (private key/certificate & comment) to an agent
    /// where the private key is stored on a hardware token,
    /// with constraints on it's usage
    AddSmartcardKeyConstrained(AddSmartcardKeyConstrained),

    /// Send a vendor-specific message via the agent protocol,
    /// identified by an *extension type*.
    Extension(Extension),
}

impl Request {
    /// The protocol message identifier for a given [`Request`] message type.
    ///
    /// Described in [draft-miller-ssh-agent-14 § 6.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-6.1).
    pub fn message_id(&self) -> u8 {
        match self {
            Self::RequestIdentities => 11,
            Self::SignRequest(_) => 13,
            Self::AddIdentity(_) => 17,
            Self::RemoveIdentity(_) => 18,
            Self::RemoveAllIdentities => 19,
            Self::AddSmartcardKey(_) => 20,
            Self::RemoveSmartcardKey(_) => 21,
            Self::Lock(_) => 22,
            Self::Unlock(_) => 23,
            Self::AddIdConstrained(_) => 25,
            Self::AddSmartcardKeyConstrained(_) => 26,
            Self::Extension(_) => 27,
        }
    }
}

impl Decode for Request {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let message_type = u8::decode(reader)?;

        match message_type {
            11 => Ok(Self::RequestIdentities),
            13 => SignRequest::decode(reader).map(Self::SignRequest),
            17 => AddIdentity::decode(reader).map(Self::AddIdentity),
            18 => RemoveIdentity::decode(reader).map(Self::RemoveIdentity),
            19 => Ok(Self::RemoveAllIdentities),
            20 => SmartcardKey::decode(reader).map(Self::AddSmartcardKey),
            21 => SmartcardKey::decode(reader).map(Self::RemoveSmartcardKey),
            22 => Ok(String::decode(reader).map(Self::Lock)?),
            23 => Ok(String::decode(reader).map(Self::Unlock)?),
            25 => AddIdentityConstrained::decode(reader).map(Self::AddIdConstrained),
            26 => AddSmartcardKeyConstrained::decode(reader).map(Self::AddSmartcardKeyConstrained),
            27 => Extension::decode(reader).map(Self::Extension),
            command => Err(Error::UnsupportedCommand { command }),
        }
    }
}

impl Encode for Request {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let message_id_len = 1;
        let payload_len = match self {
            Self::RequestIdentities => 0,
            Self::SignRequest(request) => request.encoded_len()?,
            Self::AddIdentity(identity) => identity.encoded_len()?,
            Self::RemoveIdentity(identity) => identity.encoded_len()?,
            Self::RemoveAllIdentities => 0,
            Self::AddSmartcardKey(key) => key.encoded_len()?,
            Self::RemoveSmartcardKey(key) => key.encoded_len()?,
            Self::Lock(passphrase) => passphrase.encoded_len()?,
            Self::Unlock(passphrase) => passphrase.encoded_len()?,
            Self::AddIdConstrained(key) => key.encoded_len()?,
            Self::AddSmartcardKeyConstrained(key) => key.encoded_len()?,
            Self::Extension(extension) => extension.encoded_len()?,
        };

        [message_id_len, payload_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let message_id: u8 = self.message_id();
        message_id.encode(writer)?;

        match self {
            Self::RequestIdentities => {}
            Self::SignRequest(request) => request.encode(writer)?,
            Self::AddIdentity(identity) => identity.encode(writer)?,
            Self::RemoveIdentity(identity) => identity.encode(writer)?,
            Self::RemoveAllIdentities => {}
            Self::AddSmartcardKey(key) => key.encode(writer)?,
            Self::RemoveSmartcardKey(key) => key.encode(writer)?,
            Self::Lock(passphrase) => passphrase.encode(writer)?,
            Self::Unlock(passphrase) => passphrase.encode(writer)?,
            Self::AddIdConstrained(identity) => identity.encode(writer)?,
            Self::AddSmartcardKeyConstrained(key) => key.encode(writer)?,
            Self::Extension(extension) => extension.encode(writer)?,
        };

        Ok(())
    }
}
