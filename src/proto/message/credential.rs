use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{public::KeyData, Certificate};

use crate::proto::Error;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Represents a public credential.
pub enum PublicCredential {
    /// Plain public key.
    Key(KeyData),
    /// Signed public key.
    Cert(Certificate),
}

impl PublicCredential {
    /// Returns a reference to the [KeyData].
    pub fn key_data(&self) -> &KeyData {
        match self {
            Self::Key(key) => key,
            Self::Cert(cert) => cert.public_key(),
        }
    }
}

impl Decode for PublicCredential {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> core::result::Result<Self, Self::Error> {
        // TODO: implement parsing certificates
        Ok(Self::Key(KeyData::decode(reader)?))
    }
}

impl Encode for PublicCredential {
    fn encoded_len(&self) -> std::result::Result<usize, ssh_encoding::Error> {
        match self {
            Self::Key(pubkey) => pubkey.encoded_len(),
            Self::Cert(certificate) => certificate.encoded_len(),
        }
    }

    fn encode(
        &self,
        writer: &mut impl ssh_encoding::Writer,
    ) -> std::result::Result<(), ssh_encoding::Error> {
        match self {
            Self::Key(pubkey) => pubkey.encode(writer),
            Self::Cert(certificate) => certificate.encode(writer),
        }
    }
}

impl From<KeyData> for PublicCredential {
    fn from(value: KeyData) -> Self {
        Self::Key(value)
    }
}

impl From<Certificate> for PublicCredential {
    fn from(value: Certificate) -> Self {
        Self::Cert(value)
    }
}
