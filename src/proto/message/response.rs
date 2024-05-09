//! SSH agent protocol response messages.
use ssh_encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::Signature;

use super::{Extension, Identity};
use crate::proto::{Error, Result};

/// SSH agent protocol response messages.
///
/// These message types are sent to a client *from* an agent (in response to a [`Request`](super::Request) message).
///
/// Described in [draft-miller-ssh-agent-14 § 3](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3).
#[derive(Clone, PartialEq, Debug)]
pub enum Response {
    /// Indicates generic agent failure
    Failure,

    /// Indicates generic agent success
    Success,

    /// A list of identities, sent in response to
    /// a [`Request::RequestIdentities`](super::Request::RequestIdentities) message.
    IdentitiesAnswer(Vec<Identity>),

    /// A signature, sent in response to
    /// a [`Request::SignRequest`](super::Request::SignRequest) message.
    SignResponse(Signature),

    /// Indicates generic extension failure
    ExtensionFailure,

    /// Send a vendor-specific response message via the agent protocol,
    /// identified by an *extension type*.
    ExtensionResponse(Extension),
}

impl Response {
    /// The protocol message identifier for a given [`Response`](super::Response) message type.
    ///
    /// Described in [draft-miller-ssh-agent-14 § 6.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-6.1).
    pub fn message_id(&self) -> u8 {
        match self {
            Self::Failure => 5,
            Self::Success => 6,
            Self::IdentitiesAnswer(_) => 12,
            Self::SignResponse(_) => 14,
            Self::ExtensionFailure => 28,
            Self::ExtensionResponse(_) => 29,
        }
    }
}

impl Decode for Response {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let message_type = u8::decode(reader)?;

        match message_type {
            5 => Ok(Self::Failure),
            6 => Ok(Self::Success),
            12 => Identity::decode_vec(reader).map(Self::IdentitiesAnswer),
            14 => {
                Ok(reader
                    .read_prefixed(|reader| Signature::decode(reader).map(Self::SignResponse))?)
            }
            28 => Ok(Self::ExtensionFailure),
            29 => Extension::decode(reader).map(Self::ExtensionResponse),
            command => Err(Error::UnsupportedCommand { command }),
        }
    }
}

impl Encode for Response {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let message_id_len = 1;
        let payload_len = match self {
            Self::Failure => 0,
            Self::Success => 0,
            Self::IdentitiesAnswer(ids) => {
                let mut lengths = Vec::with_capacity(1 + ids.len());
                // Prefixed length
                lengths.push(4);

                for id in ids {
                    lengths.push(id.encoded_len()?);
                }

                lengths.checked_sum()?
            }
            Self::SignResponse(response) => response.encoded_len_prefixed()?,
            Self::ExtensionFailure => 0,
            Self::ExtensionResponse(extension) => extension.encoded_len()?,
        };

        [message_id_len, payload_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let message_id: u8 = self.message_id();
        message_id.encode(writer)?;

        match self {
            Self::Failure => {}
            Self::Success => {}
            Self::IdentitiesAnswer(ids) => {
                (ids.len() as u32).encode(writer)?;
                for id in ids {
                    id.encode(writer)?;
                }
            }
            Self::SignResponse(response) => response.encode_prefixed(writer)?,
            Self::ExtensionFailure => {}
            Self::ExtensionResponse(extension) => extension.encode(writer)?,
        };

        Ok(())
    }
}
