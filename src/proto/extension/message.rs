//! SSH agent protocol extension messages
//!
//! Includes extension message definitions from both:
//! - [draft-miller-ssh-agent-14](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html)
//! - [OpenSSH `PROTOCOL.agent`](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent)

use ssh_encoding::{CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};
use ssh_key::{public::KeyData, Signature};

use super::MessageExtension;
use crate::proto::ProtoError;

/// `query` message extension.
///
/// An optional extension request "query" is defined to allow a
/// client to query which, if any, extensions are supported by an agent.
///
/// Described in [draft-miller-ssh-agent-14 § 3.8.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.8.1)
#[derive(Debug, Clone, PartialEq)]
pub struct QueryResponse {
    /// List of supported message extension names
    pub extensions: Vec<String>,
}

impl Encode for QueryResponse {
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        self.extensions.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        self.extensions.encode(writer)
    }
}

impl Decode for QueryResponse {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let extensions = Vec::<String>::decode(reader)?;

        Ok(Self { extensions })
    }
}

impl MessageExtension for QueryResponse {
    const NAME: &'static str = "query";
}

/// `session-bind@openssh.com` message extension.
///
/// This message extension allows an SSH client to bind an
/// agent connection to a particular SSH session.
///
/// *Note*: This is an OpenSSH-specific extension to the agent protocol.
///
/// Described in [OpenSSH PROTOCOL.agent § 1](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L6)
#[derive(Debug, Clone, PartialEq)]
pub struct SessionBind {
    /// Server host public key.
    pub host_key: KeyData,

    /// Hash derived from the initial key exchange.
    pub session_id: Vec<u8>,

    /// Server's signature of the session identifier using the private hostkey.
    pub signature: Signature,

    /// Flag indicating whether this connection should be bound for user authentication or forwarding.
    pub is_forwarding: bool,
}

impl Decode for SessionBind {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let host_key = reader.read_prefixed(KeyData::decode)?;
        let session_id = Vec::decode(reader)?;
        let signature = reader.read_prefixed(Signature::decode)?;
        Ok(Self {
            host_key,
            session_id,
            signature,
            is_forwarding: u8::decode(reader)? != 0,
        })
    }
}

impl Encode for SessionBind {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.host_key.encoded_len_prefixed()?,
            self.session_id.encoded_len()?,
            self.signature.encoded_len_prefixed()?,
            1u8.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.host_key.encode_prefixed(writer)?;
        self.session_id.encode(writer)?;
        self.signature.encode_prefixed(writer)?;

        if self.is_forwarding {
            1u8.encode(writer)
        } else {
            0u8.encode(writer)
        }
    }
}

impl MessageExtension for SessionBind {
    const NAME: &'static str = "session-bind@openssh.com";
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    fn round_trip<T>(msg: T) -> TestResult
    where
        T: Encode + Decode<Error = ProtoError> + std::fmt::Debug + std::cmp::PartialEq,
    {
        let mut buf: Vec<u8> = vec![];
        msg.encode(&mut buf)?;
        let mut re_encoded = &buf[..];

        let msg2 = T::decode(&mut re_encoded)?;
        assert_eq!(msg, msg2);

        Ok(())
    }

    #[test]
    fn parse_bind() -> TestResult {
        let mut buffer: &[u8] = &[
            0, 0, 0, 51, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32,
            177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172,
            240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40, 0, 0, 0, 32, 138, 165, 196,
            144, 149, 107, 183, 188, 222, 182, 34, 173, 59, 118, 9, 35, 186, 147, 114, 114, 50,
            106, 41, 182, 196, 119, 226, 82, 233, 148, 236, 135, 0, 0, 0, 83, 0, 0, 0, 11, 115,
            115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 95, 212, 52, 189, 8, 162, 17,
            3, 15, 218, 2, 4, 136, 7, 47, 57, 121, 6, 194, 165, 221, 27, 175, 241, 6, 57, 84, 141,
            77, 55, 235, 9, 77, 160, 32, 76, 11, 227, 240, 235, 122, 178, 80, 133, 183, 91, 89, 89,
            142, 115, 145, 15, 78, 112, 139, 28, 201, 8, 197, 222, 117, 141, 88, 5, 0,
        ];
        let bind = SessionBind::decode(&mut buffer)?;
        eprintln!("Bind: {bind:#?}");

        round_trip(bind)?;

        Ok(())
    }
}
