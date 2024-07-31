//! A container for a public / private key pair, or a certificate / private key.

use std::str::FromStr as _;

use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::public::KeyData;
use ssh_key::{certificate::Certificate, private::KeypairData, Algorithm};

use crate::proto::{Error, PrivateKeyData, Result};

/// A container for a public / private key pair, or a certificate / private key.
///
/// When adding an identity to an agent, a user can provide either:
/// 1. A public / private key pair
/// 2. An OpenSSH [certificate](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)
///
/// This structure covers both types of identities a user may
/// send to an agent as part of a [`Request::AddIdentity`](crate::proto::Request::AddIdentity) message.
#[derive(Clone, PartialEq, Debug)]
pub enum PrivateCredential {
    /// A public/private key pair
    Key {
        /// Public/private key pair data
        privkey: KeypairData,

        /// Key comment, if any.
        comment: String,
    },

    /// An OpenSSH [certificate](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)
    Cert {
        /// Certificate algorithm.
        algorithm: Algorithm,

        /// Certificate data.
        certificate: Certificate,

        /// Private key data.
        privkey: PrivateKeyData,

        /// Comment, if any.
        comment: String,
    },
}

impl Decode for PrivateCredential {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let alg = String::decode(reader)?;
        let cert_alg = Algorithm::new_certificate(&alg);

        if let Ok(algorithm) = cert_alg {
            let certificate = reader.read_prefixed(|reader| {
                let cert = Certificate::decode(reader)?;
                Ok::<_, Error>(cert)
            })?;
            let privkey = PrivateKeyData::decode_as(reader, algorithm.clone())?;
            let comment = String::decode(reader)?;

            Ok(PrivateCredential::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            })
        } else {
            let algorithm = Algorithm::from_str(&alg).map_err(ssh_encoding::Error::from)?;
            let privkey = KeypairData::decode_as(reader, algorithm)?;
            let comment = String::decode(reader)?;
            Ok(PrivateCredential::Key { privkey, comment })
        }
    }
}

impl Encode for PrivateCredential {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        match self {
            Self::Key { privkey, comment } => {
                [privkey.encoded_len()?, comment.encoded_len()?].checked_sum()
            }
            Self::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            } => [
                algorithm.to_certificate_type().encoded_len()?,
                certificate.encoded_len_prefixed()?,
                privkey.encoded_len()?,
                comment.encoded_len()?,
            ]
            .checked_sum(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::Key { privkey, comment } => {
                privkey.encode(writer)?;
                comment.encode(writer)
            }
            Self::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            } => {
                algorithm.to_certificate_type().encode(writer)?;
                certificate.encode_prefixed(writer)?;
                privkey.encode(writer)?;
                comment.encode(writer)
            }
        }
    }
}

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
