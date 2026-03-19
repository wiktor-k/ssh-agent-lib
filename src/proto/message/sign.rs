//! Signature request with data to be signed with a key in an agent.

use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};

use super::PublicCredential;
use crate::proto::{Error, Result};

/// Signature request with data to be signed with a key in an agent.
///
/// This structure is sent in a [`Request::SignRequest`](super::Request::SignRequest) (`SSH_AGENTC_SIGN_REQUEST`) message.
///
/// Described in [draft-miller-ssh-agent-14 § 3.6](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.6)
#[derive(Clone, PartialEq, Debug)]
pub struct SignRequest {
    /// The public key portion of the [`Identity`](super::Identity) in the agent to sign the data with
    pub credential: PublicCredential,

    /// Binary data to be signed
    pub data: Vec<u8>,

    /// Signature flags, as described in
    /// [draft-miller-ssh-agent-14 § 3.6.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.6.1)
    pub flags: u32,
}

impl Decode for SignRequest {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(PublicCredential::decode)?;
        let data = Vec::decode(reader)?;
        let flags = u32::decode(reader)?;

        Ok(Self {
            credential: pubkey,
            data,
            flags,
        })
    }
}

impl Encode for SignRequest {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.credential.encoded_len_prefixed()?,
            self.data.encoded_len()?,
            self.flags.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.credential.encode_prefixed(writer)?;
        self.data.encode(writer)?;
        self.flags.encode(writer)?;

        Ok(())
    }
}
