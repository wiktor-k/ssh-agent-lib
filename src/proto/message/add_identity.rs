//! Add a key to an agent with or without constraints and supporting data types.

use core::str::FromStr;

use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::{certificate::Certificate, private::KeypairData, Algorithm};

use super::{EncodingError, Result};
use crate::proto::{KeyConstraint, PrivateKeyData, ProtoError};

/// A container for a public / private key pair, or a certificate / private key.
///
/// When adding an identity to an agent, a user can provide either:
/// 1. A public / private key pair
/// 2. An OpenSSH [certificate](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)
///
/// This structure covers both types of identities a user may
/// send to an agent as part of a [`Request::AddIdentity`](super::Request::AddIdentity) message.
#[derive(Clone, PartialEq, Debug)]
pub enum Credential {
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

impl Decode for Credential {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let alg = String::decode(reader)?;
        let cert_alg = Algorithm::new_certificate(&alg);

        if let Ok(algorithm) = cert_alg {
            let certificate = reader.read_prefixed(|reader| {
                let cert = Certificate::decode(reader)?;
                Ok::<_, ProtoError>(cert)
            })?;
            let privkey = PrivateKeyData::decode_as(reader, algorithm.clone())?;
            let comment = String::decode(reader)?;

            Ok(Credential::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            })
        } else {
            let algorithm = Algorithm::from_str(&alg).map_err(EncodingError::from)?;
            let privkey = KeypairData::decode_as(reader, algorithm)?;
            let comment = String::decode(reader)?;
            Ok(Credential::Key { privkey, comment })
        }
    }
}

impl Encode for Credential {
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
    type Error = ProtoError;

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

/// Add a key to an agent, with constraints on it's use.
///
/// This structure is sent in a [`Request::AddIdConstrained`](super::Request::AddIdConstrained) (`SSH_AGENTC_ADD_ID_CONSTRAINED`) message.
///
/// This is a variant of [`Request::AddIdentity`](super::Request::AddIdentity) with a set of [`KeyConstraint`]s attached.
///
/// Described in [draft-miller-ssh-agent-14 § 3.2](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.2)
#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentityConstrained {
    /// The credential to be added to the agent.
    pub identity: AddIdentity,

    /// Constraints to be placed on the `identity`.
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddIdentityConstrained {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let identity = AddIdentity::decode(reader)?;
        let mut constraints = vec![];

        while !reader.is_finished() {
            constraints.push(KeyConstraint::decode(reader)?);
        }

        Ok(Self {
            identity,
            constraints,
        })
    }
}

impl Encode for AddIdentityConstrained {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.constraints
            .iter()
            .try_fold(self.identity.encoded_len()?, |acc, e| {
                let constraint_len = e.encoded_len()?;
                usize::checked_add(acc, constraint_len).ok_or(EncodingError::Length)
            })
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.identity.encode(writer)?;
        for constraint in &self.constraints {
            constraint.encode(writer)?;
        }
        Ok(())
    }
}
