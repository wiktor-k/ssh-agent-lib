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
        eprintln!("encoding {}", u32::decode(reader)?);
        let mut constraints = Vec::new();
        while !reader.is_finished() {
            eprintln!("encoding");
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
        //eprintln!("before: {}", u32::decode(reader)?);
        let from_username = String::decode(reader)?;
        eprintln!("from username: {from_username} {}", from_username.len());
        eprintln!("before: {}", u32::decode(reader)?);
        let from_hostname = String::decode(reader)?;
        eprintln!("from hostname: {from_hostname}");
        let from_hostkeys = reader.read_prefixed(|reader| {
            let mut keys = Vec::new();
            while !reader.is_finished() {
                keys.push(KeySpec::decode(reader)?);
            }
            Ok::<_, crate::proto::error::ProtoError>(keys)
        })?;
        let to_username = String::decode(reader)?;
        let to_hostname = String::decode(reader)?;
        let to_hostkeys = reader.read_prefixed(|reader| {
            let mut keys = Vec::new();
            while !reader.is_finished() {
                keys.push(KeySpec::decode(reader)?);
            }
            Ok::<_, crate::proto::error::ProtoError>(keys)
        })?;
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
        let mut buffer: &[u8] = &[
            0, 0, 0, 114, //
            0, 0, 0, 110, //
            0, 0, 0, 12, //from:
            0, 0, 0, 0, //username
            0, 0, 0, 0, //hostname
            0, 0, 0, 0, //reserved
            // no host keys here
            0, 0, 0, 86, //to:
            0, 0, 0, 6, 119, 105, 107, 116, 111, 114, // wiktor
            0, 0, 0, 12, 109, 101, 116, 97, 99, 111, 100, 101, 46, 98, 105,
            122, // metacode.biz
            0, 0, 0, 0, // reserved, not in the spec authfd.c:469
            0, 0, 0, 51, //
            0, 0, 0, 11, //
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, //ssh-ed25519
            0, 0, 0, 32, // raw key
            177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172,
            240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40, //
            0,  // is_ca
            0, 0, 0, 0, // reserved, not in the spec, authfd.c:495
        ];

        let destination_constraint = RestrictDestination::decode(&mut buffer)?;
        eprintln!("Destination constraint: {destination_constraint:?}");
        Ok(())
    }
}
