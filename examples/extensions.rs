use ssh_agent_lib::proto::{extension::MessageExtension, Identity, ProtoError};
use ssh_encoding::{CheckedSum, Decode, Encode, Reader, Writer};

pub struct RequestDecryptIdentities;

const DECRYPT_DERIVE_IDS: &str = "decrypt-derive-ids@metacode.biz";

impl MessageExtension for RequestDecryptIdentities {
    const NAME: &'static str = DECRYPT_DERIVE_IDS;
}

impl Encode for RequestDecryptIdentities {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        Ok(0)
    }

    fn encode(&self, _writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        Ok(())
    }
}

impl Decode for RequestDecryptIdentities {
    type Error = ProtoError;

    fn decode(_reader: &mut impl Reader) -> core::result::Result<Self, Self::Error> {
        Ok(Self)
    }
}

#[derive(Debug)]
pub struct DecryptIdentities {
    pub identities: Vec<Identity>,
}

impl MessageExtension for DecryptIdentities {
    const NAME: &'static str = DECRYPT_DERIVE_IDS;
}

impl Decode for DecryptIdentities {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let len = u32::decode(reader)?;
        let mut identities = vec![];

        for _ in 0..len {
            identities.push(Identity::decode(reader)?);
        }

        Ok(Self { identities })
    }
}

impl Encode for DecryptIdentities {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let ids = &self.identities;
        let mut lengths = Vec::with_capacity(1 + ids.len());
        // Prefixed length
        lengths.push(4);

        for id in ids {
            lengths.push(id.encoded_len()?);
        }

        lengths.checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let ids = &self.identities;
        (ids.len() as u32).encode(writer)?;
        for id in ids {
            id.encode(writer)?;
        }
        Ok(())
    }
}

#[allow(dead_code)] // rust will complain if main is missing in example crate
fn main() {
    panic!("This is just a helper lib crate for extensions");
}
