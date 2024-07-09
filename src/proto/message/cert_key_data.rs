use std::str::FromStr as _;

use ssh_encoding::{CheckedSum as _, Decode, Encode, Reader};
use ssh_key::{public::KeyData, Algorithm, Certificate, PublicKey};

use crate::proto::{Error, Result};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CertKeyData {
    Key(KeyData),
    Cert(Certificate),
}

impl Decode for CertKeyData {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> core::result::Result<Self, Self::Error> {
        let alg = String::decode(reader)?;
        let cert_alg = Algorithm::new_certificate(&alg);

        if let Ok(algorithm) = cert_alg {
            let certificate = Certificate::decode_as(algorithm.clone(), reader)?;
            Ok(Self::Cert(certificate))
        } else {
            let algorithm = Algorithm::from_str(&alg).map_err(ssh_encoding::Error::from)?;
            let pubkey = KeyData::decode_as(reader, algorithm)?;
            Ok(Self::Key(pubkey))
        }
    }
}

impl Encode for CertKeyData {
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

impl From<KeyData> for CertKeyData {
    fn from(value: KeyData) -> Self {
        Self::Key(value)
    }
}

impl From<Certificate> for CertKeyData {
    fn from(value: Certificate) -> Self {
        Self::Cert(value)
    }
}
