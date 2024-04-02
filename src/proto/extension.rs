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
}
