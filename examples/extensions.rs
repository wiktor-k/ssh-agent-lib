use ssh_agent_lib::proto::{extension::MessageExtension, Identity, ProtoError};
use ssh_encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::public::KeyData;

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

const DECRYPT_DERIVE: &str = "decrypt-derive@metacode.biz";

#[derive(Clone, PartialEq, Debug)]
pub struct DecryptDeriveRequest {
    pub pubkey: KeyData,

    pub data: Vec<u8>,

    pub flags: u32,
}

impl MessageExtension for DecryptDeriveRequest {
    const NAME: &'static str = DECRYPT_DERIVE;
}

impl Decode for DecryptDeriveRequest {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;
        let data = Vec::decode(reader)?;
        let flags = u32::decode(reader)?;

        Ok(Self {
            pubkey,
            data,
            flags,
        })
    }
}

impl Encode for DecryptDeriveRequest {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.pubkey.encoded_len_prefixed()?,
            self.data.encoded_len()?,
            self.flags.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)?;
        self.data.encode(writer)?;
        self.flags.encode(writer)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct DecryptDeriveResponse {
    pub data: Vec<u8>,
}

impl MessageExtension for DecryptDeriveResponse {
    const NAME: &'static str = DECRYPT_DERIVE;
}

impl Encode for DecryptDeriveResponse {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.data.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        self.data.encode(writer)
    }
}

impl Decode for DecryptDeriveResponse {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> core::result::Result<Self, Self::Error> {
        Ok(Self {
            data: Vec::decode(reader)?,
        })
    }
}

#[allow(dead_code)] // rust will complain if main is missing in example crate
fn main() {
    panic!("This is just a helper lib crate for extensions");
}
