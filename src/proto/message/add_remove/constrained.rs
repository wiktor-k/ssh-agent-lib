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
                    details: Unparsed::from(details),
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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use ssh_key::private::KeypairData;

    use super::*;
    use crate::proto::message::tests::demo_key;
    use crate::proto::Credential;

    #[test]
    fn test_add_identity_constrained() {
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
            6c61 0100 0000 02
        "
        );
        let mut reader = msg;

        let out = AddIdentityConstrained::decode(&mut reader).unwrap();

        let expected = AddIdentityConstrained {
            identity: AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ecdsa(demo_key()),
                    comment: "baloo@angela".to_string(),
                },
            },
            constraints: vec![KeyConstraint::Lifetime(2)],
        };
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(expected.encoded_len().expect("len message"), buf.len());
        assert_eq!(buf, msg);

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
            6c61 ff00 0000 2472 6573 7472 6963 742d
            6465 7374 696e 6174 696f 6e2d 7630 3040
            6f70 656e 7373 682e 636f 6d00 0002 7300
            0002 6f00 0000 0c00 0000 0000 0000 0000
            0000 0000 0002 5700 0000 0000 0000 0a67
            6974 6875 622e 636f 6d00 0000 0000 0000
            3300 0000 0b73 7368 2d65 6432 3535 3139
            0000 0020 e32a aa79 15ce b9b4 49d1 ba50
            ea2a 28bb 1a6e 01f9 0bda 245a 2d1d 8769
            7d18 a265 0000 0001 9700 0000 0773 7368
            2d72 7361 0000 0003 0100 0100 0001 8100
            a3ee 774d c50a 3081 c427 8ec8 5c2e ba8f
            1228 a986 7b7e 5534 ef0c fea6 1c12 fd8f
            568d 5246 3851 ed60 bf09 c62d 594e 8467
            98ae 765a 3204 4aeb e3ca 0945 da0d b0bb
            aad6 d6f2 0224 84be da18 2b0e aff0 b9e9
            224c cbf0 4265 fc5d d675 b300 ec52 0cf8
            15b2 67ab 3816 1f36 a96d 57df e158 2a81
            cb02 0d21 1fb9 7488 3a25 327b da97 04a4
            48dc 6205 e413 6604 1575 7524 79ec 2a06
            cb58 d961 49ca 9bd9 49b2 4644 32ca d44b
            b4bf b7f1 31b1 9310 9f96 63be e59f 0249
            2358 ec68 9d8c c219 ed0e 3332 3036 9f59
            c6ae 54c3 933c 030a cc3e c2a1 4f19 0035
            efd7 277c 658e 5915 6bba 3d7a cfa5 f2bf
            1be3 2706 f3d3 0419 ef95 cae6 d292 6fb1
            4dc9 e204 b384 d3e2 393e 4b87 613d e014
            0b9c be6c 3622 ad88 0ce0 60bb b849 f3b6
            7672 6955 90ec 1dfc d402 b841 daf0 b79d
            59a8 4c4a 6d0a 5350 d9fe 123a a84f 0bea
            363e 24ab 1e50 5022 344e 14bf 6243 b124
            25e6 3d45 996e 18e9 0a0e 7a8b ed9a 07a0
            a62b 6246 867e 7b2b 99a3 d0c3 5d05 7038
            fd69 f01f a5e8 3d62 732b 9372 bb6c c1de
            7019 a7e4 b986 942c fa9d 6f37 5ff0 b239
            0000 0000 6800 0000 1365 6364 7361 2d73
            6861 322d 6e69 7374 7032 3536 0000 0008
            6e69 7374 7032 3536 0000 0041 0449 8a48
            4363 4047 b33a 6c64 64cc bba2 92a0 c050
            7d9e 4b79 611a d832 336e 1b93 7cee e460
            83a0 8bad ba39 c007 53ff 2eaf d262 95d1
            4db0 d166 7660 1ffe f93a 6872 4800 0000
            0000"
        );
        let mut reader = msg;

        let out = AddIdentityConstrained::decode(&mut reader).unwrap();

        let expected = AddIdentityConstrained {
            identity: AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ecdsa(demo_key()),
                    comment: "baloo@angela".to_string(),
                },
            },
            constraints: vec![KeyConstraint::Extension(Extension {
                name: "restrict-destination-v00@openssh.com".to_string(),
                details: Unparsed::from(
                    hex!(
                        "                                    00
                        0002 6f00 0000 0c00 0000 0000 0000 0000
                        0000 0000 0002 5700 0000 0000 0000 0a67
                        6974 6875 622e 636f 6d00 0000 0000 0000
                        3300 0000 0b73 7368 2d65 6432 3535 3139
                        0000 0020 e32a aa79 15ce b9b4 49d1 ba50
                        ea2a 28bb 1a6e 01f9 0bda 245a 2d1d 8769
                        7d18 a265 0000 0001 9700 0000 0773 7368
                        2d72 7361 0000 0003 0100 0100 0001 8100
                        a3ee 774d c50a 3081 c427 8ec8 5c2e ba8f
                        1228 a986 7b7e 5534 ef0c fea6 1c12 fd8f
                        568d 5246 3851 ed60 bf09 c62d 594e 8467
                        98ae 765a 3204 4aeb e3ca 0945 da0d b0bb
                        aad6 d6f2 0224 84be da18 2b0e aff0 b9e9
                        224c cbf0 4265 fc5d d675 b300 ec52 0cf8
                        15b2 67ab 3816 1f36 a96d 57df e158 2a81
                        cb02 0d21 1fb9 7488 3a25 327b da97 04a4
                        48dc 6205 e413 6604 1575 7524 79ec 2a06
                        cb58 d961 49ca 9bd9 49b2 4644 32ca d44b
                        b4bf b7f1 31b1 9310 9f96 63be e59f 0249
                        2358 ec68 9d8c c219 ed0e 3332 3036 9f59
                        c6ae 54c3 933c 030a cc3e c2a1 4f19 0035
                        efd7 277c 658e 5915 6bba 3d7a cfa5 f2bf
                        1be3 2706 f3d3 0419 ef95 cae6 d292 6fb1
                        4dc9 e204 b384 d3e2 393e 4b87 613d e014
                        0b9c be6c 3622 ad88 0ce0 60bb b849 f3b6
                        7672 6955 90ec 1dfc d402 b841 daf0 b79d
                        59a8 4c4a 6d0a 5350 d9fe 123a a84f 0bea
                        363e 24ab 1e50 5022 344e 14bf 6243 b124
                        25e6 3d45 996e 18e9 0a0e 7a8b ed9a 07a0
                        a62b 6246 867e 7b2b 99a3 d0c3 5d05 7038
                        fd69 f01f a5e8 3d62 732b 9372 bb6c c1de
                        7019 a7e4 b986 942c fa9d 6f37 5ff0 b239
                        0000 0000 6800 0000 1365 6364 7361 2d73
                        6861 322d 6e69 7374 7032 3536 0000 0008
                        6e69 7374 7032 3536 0000 0041 0449 8a48
                        4363 4047 b33a 6c64 64cc bba2 92a0 c050
                        7d9e 4b79 611a d832 336e 1b93 7cee e460
                        83a0 8bad ba39 c007 53ff 2eaf d262 95d1
                        4db0 d166 7660 1ffe f93a 6872 4800 0000
                        0000"
                    )
                    .to_vec(),
                ),
            })],
        };

        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(expected.encoded_len().expect("len message"), buf.len());
        assert_eq!(buf, msg);
    }
}
