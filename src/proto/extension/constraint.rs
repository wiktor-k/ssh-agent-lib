//! SSH agent protocol key constraint messages
//!
//! Includes extension message definitions from:
//! - [OpenSSH `PROTOCOL.agent`](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent)

use ssh_encoding::{CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};
use ssh_key::public::KeyData;

use super::KeyConstraintExtension;

// Reserved fields are marked with an empty string
const RESERVED_FIELD: &str = "";

/// `restrict-destination-v00@openssh.com` key constraint extension.
///
/// The key constraint extension supports destination- and forwarding path-
/// restricted keys. It may be attached as a constraint when keys or
/// smartcard keys are added to an agent.
///
/// *Note*: This is an OpenSSH-specific extension to the agent protocol.
///
/// Described in [OpenSSH PROTOCOL.agent § 2](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L38)
#[derive(Debug, Clone, PartialEq)]
pub struct RestrictDestination {
    /// Set of constraints for the destination.
    pub constraints: Vec<DestinationConstraint>,
}

impl Decode for RestrictDestination {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let mut constraints = Vec::new();
        while !reader.is_finished() {
            constraints.push(reader.read_prefixed(DestinationConstraint::decode)?);
        }
        Ok(Self { constraints })
    }
}

impl Encode for RestrictDestination {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.constraints.iter().try_fold(0, |acc, e| {
            let constraint_len = e.encoded_len_prefixed()?;
            usize::checked_add(acc, constraint_len).ok_or(EncodingError::Length)
        })
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        for constraint in &self.constraints {
            constraint.encode_prefixed(writer)?;
        }
        Ok(())
    }
}

impl KeyConstraintExtension for RestrictDestination {
    const NAME: &'static str = "restrict-destination-v00@openssh.com";
}

/// Tuple containing username and hostname with keys.
///
/// *Note*: This is an OpenSSH-specific extension to the agent protocol.
///
/// Described in [OpenSSH PROTOCOL.agent § 2](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L38)
#[derive(Debug, Clone, PartialEq)]
pub struct HostTuple {
    /// Username part of the tuple.
    pub username: String,

    /// Hostname part of the tuple.
    pub hostname: String,

    /// Set of keys for the tuple.
    pub keys: Vec<KeySpec>,
}

impl Decode for HostTuple {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let username = String::decode(reader)?;
        let hostname = String::decode(reader)?;
        let _reserved = String::decode(reader)?;

        let mut keys = Vec::new();
        while !reader.is_finished() {
            keys.push(KeySpec::decode(reader)?);
        }

        Ok(Self {
            username,
            hostname,
            keys,
        })
    }
}

impl Encode for HostTuple {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let prefix = [
            self.username.encoded_len()?,
            self.hostname.encoded_len()?,
            RESERVED_FIELD.encoded_len()?,
        ]
        .checked_sum()?;
        self.keys.iter().try_fold(prefix, |acc, e| {
            let key_len = e.encoded_len()?;
            usize::checked_add(acc, key_len).ok_or(EncodingError::Length)
        })
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.username.encode(writer)?;
        self.hostname.encode(writer)?;
        RESERVED_FIELD.encode(writer)?;
        for key in &self.keys {
            key.encode(writer)?;
        }
        Ok(())
    }
}

/// Key destination constraint.
///
/// One or more [`DestinationConstraint`]s are included in
/// the [`RestrictDestination`] key constraint extension.
///
/// *Note*: This is an OpenSSH-specific extension to the agent protocol.
///
/// Described in [OpenSSH PROTOCOL.agent § 2](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L38)
#[derive(Debug, Clone, PartialEq)]
pub struct DestinationConstraint {
    /// Constraint's `from` endpoint.
    pub from: HostTuple,

    /// Constraint's `to` endpoint.
    pub to: HostTuple,
}

impl Decode for DestinationConstraint {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let from = reader.read_prefixed(HostTuple::decode)?;
        let to = reader.read_prefixed(HostTuple::decode)?;
        let _reserved = String::decode(reader)?;

        Ok(Self { from, to })
    }
}

impl Encode for DestinationConstraint {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.from.encoded_len_prefixed()?,
            self.to.encoded_len_prefixed()?,
            RESERVED_FIELD.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.from.encode_prefixed(writer)?;
        self.to.encode_prefixed(writer)?;
        RESERVED_FIELD.encode(writer)?;
        Ok(())
    }
}

/// Public key specification.
///
/// This structure is included in [`DestinationConstraint`],
/// which in turn is used in the [`RestrictDestination`] key
/// constraint extension.
///
/// *Note*: This is an OpenSSH-specific extension to the agent protocol.
///
/// Described in [OpenSSH PROTOCOL.agent § 2](https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L38)
#[derive(Debug, Clone, PartialEq)]
pub struct KeySpec {
    /// The public parts of the key.
    pub keyblob: KeyData,

    /// Flag indicating if this key is for a CA.
    pub is_ca: bool,
}

impl Decode for KeySpec {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let keyblob = reader.read_prefixed(KeyData::decode)?;
        Ok(Self {
            keyblob,
            is_ca: u8::decode(reader)? != 0,
        })
    }
}

impl Encode for KeySpec {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.keyblob.encoded_len_prefixed()?, 1u8.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.keyblob.encode_prefixed(writer)?;
        // TODO: contribute `impl Encode for bool` in ssh-encoding
        // <https://www.rfc-editor.org/rfc/rfc4251#section-5>
        if self.is_ca {
            1u8.encode(writer)
        } else {
            0u8.encode(writer)
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use testresult::TestResult;

    use super::*;
    use crate::proto::ProtoError;

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
    fn parse_destination_constraint() -> TestResult {
        let mut msg = &hex!(
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
        )[..];

        let destination_constraint = RestrictDestination::decode(&mut msg)?;
        eprintln!("Destination constraint: {destination_constraint:?}");

        round_trip(destination_constraint)?;

        #[rustfmt::skip]
        let mut buffer: &[u8] = const_str::concat_bytes!(
            [0, 0, 0, 110], //
            [0, 0, 0, 12], //from:
            [0, 0, 0, 0], //username
            [0, 0, 0, 0], //hostname
            [0, 0, 0, 0], //reserved
            // no host keys here
            [0, 0, 0, 86], //to:
            [0, 0, 0, 6], b"wiktor",
            [0, 0, 0, 12], b"metacode.biz",
            [0, 0, 0, 0], // reserved, not in the spec authfd.c:469
            [0, 0, 0, 51], //
            [0, 0, 0, 11], //
            b"ssh-ed25519",
            [0, 0, 0, 32], // raw key
            [177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172,
            240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40], //
            [0],  // is_ca
            [0, 0, 0, 0], // reserved, not in the spec, authfd.c:495
        );

        let destination_constraint = RestrictDestination::decode(&mut buffer)?;
        eprintln!("Destination constraint: {destination_constraint:?}");

        round_trip(destination_constraint)?;

        let mut buffer: &[u8] = &[
            0, 0, 0, 102, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 0, 0, 0, 0,
            0, 0, 0, 10, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 0, 0, 0, 0, 0, 0, 0, 51, 0,
            0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 227, 42, 170,
            121, 21, 206, 185, 180, 73, 209, 186, 80, 234, 42, 40, 187, 26, 110, 1, 249, 11, 218,
            36, 90, 45, 29, 135, 105, 125, 24, 162, 101, 0, 0, 0, 0, 0,
        ];
        let destination_constraint = RestrictDestination::decode(&mut buffer)?;
        eprintln!("Destination constraint: {destination_constraint:?}");

        round_trip(destination_constraint)?;

        Ok(())
    }
}
