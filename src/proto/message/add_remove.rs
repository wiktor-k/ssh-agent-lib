//! Add a key to an agent with or without constraints and supporting data types.

mod constrained;
mod credential;

pub use constrained::*;
pub use credential::*;
use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::public::KeyData;

use crate::proto::{Error, Result};

/// Add a key to an agent.
///
/// This structure is sent in a [`Request::AddIdentity`](super::Request::AddIdentity) (`SSH_AGENTC_ADD_IDENTITY`) message.
///
/// Described in [draft-miller-ssh-agent-14 § 3.2](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.2)
#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentity {
    /// A credential (private & public key, or private key / certificate) to add to the agent
    pub credential: Credential,
}

impl Decode for AddIdentity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let credential = Credential::decode(reader)?;

        Ok(Self { credential })
    }
}

impl Encode for AddIdentity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.credential.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.credential.encode(writer)
    }
}

/// Pointer to a key in a hardware token, along with an optional PIN.
///
/// This structure is sent in a [`Request::AddSmartcardKey`](super::Request::AddSmartcardKey) (`SSH_AGENTC_ADD_SMARTCARD_KEY`) message.
///
/// Described in [draft-miller-ssh-agent-14 § 3.2](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.2)
#[derive(Clone, PartialEq, Debug)]
pub struct SmartcardKey {
    /// An opaque identifier for the hardware token
    ///
    /// Note: the interpretation of "id" is not defined by the protocol,
    /// but is left solely up to the agent.
    pub id: String,

    /// An optional password to unlock the key
    pub pin: String,
}

impl Decode for SmartcardKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let id = String::decode(reader)?;
        let pin = String::decode(reader)?;

        Ok(Self { id, pin })
    }
}

impl Encode for SmartcardKey {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.id.encoded_len()?, self.pin.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.id.encode(writer)?;
        self.pin.encode(writer)?;

        Ok(())
    }
}

/// Remove a key from an agent.
///
/// This structure is sent in a [`Request::RemoveIdentity`](super::Request::RemoveIdentity) (`SSH_AGENTC_REMOVE_IDENTITY`) message.
///
/// Described in [draft-miller-ssh-agent-14 § 3.4](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.4)
#[derive(Clone, PartialEq, Debug)]
pub struct RemoveIdentity {
    /// The public key portion of the [`Identity`](super::Identity) to be removed
    pub pubkey: KeyData,
}

impl Decode for RemoveIdentity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;

        Ok(Self { pubkey })
    }
}

impl Encode for RemoveIdentity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.pubkey.encoded_len_prefixed()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use ssh_key::private::KeypairData;

    use super::*;
    use crate::proto::message::tests::demo_key;

    #[test]
    fn test_add_identity() {
        let msg: &[u8] = &hex!(
            "
	                00 0000 1365 6364 7361 2d73
	    6861 322d 6e69 7374 7032 3536 0000 0008
	    6e69 7374 7032 3536 0000 0041 04cb 244f
	    cdb8 9de9 5bc8 fd76 6e6b 139a bfc2 649f
	    b063 b6c5 e5a9 39e0 67e2 a0d2 150a 660d
	    aca7 8f6c 24a0 4253 73d6 ea83 e36f 8a1f
	    8b82 8a60 e77a 97a9 441b cc09 8700 0000
	    2100 ffd9 f2ce 4d0e e587 0d8d c7cf 771a
	    7669 a0b9 6fe4 4bb5 8a8a 0bc7 5a76 b4f7
	    8240 0000 000c 6261 6c6f 6f40 616e 6765
	    6c61
        "
        );
        let mut reader = msg;

        let out = AddIdentity::decode(&mut reader).expect("parse message");

        let expected = AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ecdsa(demo_key()),
                comment: "baloo@angela".to_string(),
            },
        };
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }
}
