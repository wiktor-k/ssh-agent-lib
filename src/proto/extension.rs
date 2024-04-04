use ssh_encoding::{Decode, Reader};
use ssh_key::{public::KeyData, Signature};

/// session-bind@openssh.com extension
///
/// This extension allows a ssh client to bind an agent connection to a
/// particular SSH session.
///
/// Spec:
/// <https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L6>
#[derive(Debug, Clone)]
pub struct SessionBind {
    pub host_key: KeyData,
    pub session_id: Vec<u8>,
    pub signature: Signature,
    pub is_forwarding: bool,
}

impl Decode for SessionBind {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let host_key = reader.read_prefixed(KeyData::decode)?;
        let session_id = Vec::decode(reader)?;
        let signature = reader.read_prefixed(Signature::decode)?;
        Ok(Self {
            host_key,
            session_id,
            signature,
            is_forwarding: u8::decode(reader)? != 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RestrictDestination {
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

#[derive(Debug, Clone)]
pub struct DestinationConstraint {
    pub from_username: String,
    pub from_hostname: String,
    pub from_hostkeys: Vec<KeySpec>,
    pub to_username: String,
    pub to_hostname: String,
    pub to_hostkeys: Vec<KeySpec>,
}

impl Decode for DestinationConstraint {
    type Error = crate::proto::error::ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        fn read_user_host_keys(
            reader: &mut impl Reader,
        ) -> Result<(String, String, Vec<KeySpec>), crate::proto::error::ProtoError> {
            let username = String::decode(reader)?;
            let hostname = String::decode(reader)?;
            let _reserved = String::decode(reader)?;

            let mut keys = Vec::new();
            while !reader.is_finished() {
                keys.push(KeySpec::decode(reader)?);
            }

            Ok((username, hostname, keys))
        }

        let (from_username, from_hostname, from_hostkeys) =
            reader.read_prefixed(read_user_host_keys)?;
        let (to_username, to_hostname, to_hostkeys) = reader.read_prefixed(read_user_host_keys)?;
        let _reserved = String::decode(reader)?;
        Ok(Self {
            from_username,
            from_hostname,
            from_hostkeys,
            to_username,
            to_hostname,
            to_hostkeys,
        })
    }
}

#[derive(Debug, Clone)]
pub struct KeySpec {
    pub keyblob: KeyData,
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use testresult::TestResult;

    #[test]
    fn parse_bind() -> TestResult {
        let mut buffer: &[u8] = &[
            0, 0, 0, 51, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32,
            177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172,
            240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40, 0, 0, 0, 32, 138, 165, 196,
            144, 149, 107, 183, 188, 222, 182, 34, 173, 59, 118, 9, 35, 186, 147, 114, 114, 50,
            106, 41, 182, 196, 119, 226, 82, 233, 148, 236, 135, 0, 0, 0, 83, 0, 0, 0, 11, 115,
            115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 95, 212, 52, 189, 8, 162, 17,
            3, 15, 218, 2, 4, 136, 7, 47, 57, 121, 6, 194, 165, 221, 27, 175, 241, 6, 57, 84, 141,
            77, 55, 235, 9, 77, 160, 32, 76, 11, 227, 240, 235, 122, 178, 80, 133, 183, 91, 89, 89,
            142, 115, 145, 15, 78, 112, 139, 28, 201, 8, 197, 222, 117, 141, 88, 5, 0,
        ];
        let bind = SessionBind::decode(&mut buffer)?;
        eprintln!("Bind: {bind:#?}");
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
        let _destination_constraint = RestrictDestination::decode(&mut msg)?;

        #[rustfmt::skip]
        let mut buffer: &[u8] = const_str::concat_bytes!(
            [0, 0, 0, 114], //
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
        Ok(())
    }
}
