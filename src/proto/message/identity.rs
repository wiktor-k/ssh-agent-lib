//! Data returned to the client when listing keys.

use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::public::KeyData;

use super::cert_key_data::CertKeyData;
use crate::proto::{Error, Result};

/// Data returned to the client when listing keys.
///
/// A list of these structures are sent in a [`Response::IdentitiesAnswer`](super::Response::IdentitiesAnswer) (`SSH_AGENT_IDENTITIES_ANSWER`) message body.
///
/// Described in [draft-miller-ssh-agent-14 § 3.5](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.5)
#[derive(Clone, PartialEq, Debug)]
pub struct Identity {
    /// A standard public-key encoding of an underlying key.
    pub pubkey: CertKeyData,

    /// A human-readable comment
    pub comment: String,
}

impl Identity {
    pub(crate) fn decode_vec(reader: &mut impl Reader) -> Result<Vec<Self>> {
        let len = u32::decode(reader)?;
        let mut identities = vec![];

        for _ in 0..len {
            identities.push(Self::decode(reader)?);
        }

        Ok(identities)
    }
}

impl Decode for Identity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(CertKeyData::decode)?;
        let comment = String::decode(reader)?;

        Ok(Self { pubkey, comment })
    }
}

impl Encode for Identity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.pubkey.encoded_len_prefixed()?,
            self.comment.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)?;
        self.comment.encode(writer)?;

        Ok(())
    }
}
