use ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::Error as KeyError;

use crate::proto::{AddIdentity, Error, Extension, Result, SmartcardKey, Unparsed};

/// A key constraint, used to place limitations on how and where a key can be used.
///
/// Key constraints are set along with a key when are added to an agent.
///
/// Specifically, they appear in special `SSH_AGENTC_ADD_*` message variants:
/// - [`Request::AddIdConstrained`](crate::proto::Request::AddIdConstrained)
/// - [`Request::AddSmartcardKeyConstrained`](crate::proto::Request::AddSmartcardKeyConstrained)
#[derive(Clone, PartialEq, Debug)]
pub enum KeyConstraint {
    /// Limit the key's lifetime by deleting it after the specified duration (in seconds)
    Lifetime(u32),

    /// Require explicit user confirmation for each private key operation using the key.
    Confirm,

    /// Experimental or private-use constraints
    ///
    /// Contains:
    /// - An extension name indicating the type of the constraint (as a UTF-8 string).
    /// - Extension-specific content
    ///
    /// Extension names should be suffixed by the implementation domain
    /// as per [RFC4251 § 4.2](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.2),
    /// e.g. "foo@example.com"
    Extension(Extension),
}

impl Decode for KeyConstraint {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let constraint_type = u8::decode(reader)?;
        // see: https://www.ietf.org/archive/id/draft-miller-ssh-agent-12.html#section-5.2
        Ok(match constraint_type {
            1 => KeyConstraint::Lifetime(u32::decode(reader)?),
            2 => KeyConstraint::Confirm,
            255 => {
                let name = String::decode(reader)?;
                let details: Vec<u8> = Vec::decode(reader)?;
                KeyConstraint::Extension(Extension {
                    name,
                    details: Unparsed::from_raw(details),
                })
            }
            _ => return Err(KeyError::AlgorithmUnknown)?, // FIXME: it should be our own type
        })
    }
}

impl Encode for KeyConstraint {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let base = u8::MAX.encoded_len()?;

        match self {
            Self::Lifetime(lifetime) => base
                .checked_add(lifetime.encoded_len()?)
                .ok_or(ssh_encoding::Error::Length),
            Self::Confirm => Ok(base),
            Self::Extension(extension) => [
                base,
                extension.name.encoded_len()?,
                extension.details.encoded_len_prefixed()?,
            ]
            .checked_sum(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::Lifetime(lifetime) => {
                1u8.encode(writer)?;
                lifetime.encode(writer)
            }
            Self::Confirm => 2u8.encode(writer),
            Self::Extension(extension) => {
                255u8.encode(writer)?;
                extension.name.encode(writer)?;
                extension.details.encode_prefixed(writer)
            }
        }
    }
}

/// Add a key to an agent, with constraints on it's use.
///
/// This structure is sent in a [`Request::AddIdConstrained`](crate::proto::Request::AddIdConstrained) (`SSH_AGENTC_ADD_ID_CONSTRAINED`) message.
///
/// This is a variant of [`Request::AddIdentity`](crate::proto::Request::AddIdentity) with a set of [`KeyConstraint`]s attached.
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
    type Error = Error;

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
                usize::checked_add(acc, constraint_len).ok_or(ssh_encoding::Error::Length)
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

/// Add a key in a hardware token to an agent, with constraints on it's use.
///
/// This structure is sent in a [`Request::AddSmartcardKeyConstrained`](crate::proto::Request::AddSmartcardKeyConstrained) (`SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`) message.
///
/// This is a variant of [`Request::AddSmartcardKey`](crate::proto::Request::AddSmartcardKey) with a set of [`KeyConstraint`]s attached.
///
/// Described in [draft-miller-ssh-agent-14 § 3.2.6](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.2.6)
#[derive(Clone, PartialEq, Debug)]
pub struct AddSmartcardKeyConstrained {
    /// A key stored on a hardware token.
    pub key: SmartcardKey,

    /// Constraints to be placed on the `key`.
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddSmartcardKeyConstrained {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let key = SmartcardKey::decode(reader)?;
        let mut constraints = vec![];

        while !reader.is_finished() {
            constraints.push(KeyConstraint::decode(reader)?);
        }
        Ok(Self { key, constraints })
    }
}

impl Encode for AddSmartcardKeyConstrained {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.constraints
            .iter()
            .try_fold(self.key.encoded_len()?, |acc, e| {
                let constraint_len = e.encoded_len()?;
                usize::checked_add(acc, constraint_len).ok_or(ssh_encoding::Error::Length)
            })
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.key.encode(writer)?;
        for constraint in &self.constraints {
            constraint.encode(writer)?;
        }
        Ok(())
    }
}
