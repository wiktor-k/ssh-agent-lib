pub mod serialize;
pub mod deserialize;
mod error;

pub use self::serialize::to_bytes;
pub use self::deserialize::from_bytes;

use serde::{Serialize, Deserialize};
use self::error::Result;

pub trait Blob: Sized {
    fn to_blob(&self) -> Result<Vec<u8>>;
    fn from_blob(blob: &[u8]) -> Result<Self>;
}

impl<'a, T: Serialize + Deserialize<'a>> Blob for T {
    fn to_blob(&self) -> Result<Vec<u8>> {
        serialize::to_bytes(self)
    }
    
    fn from_blob(blob: &[u8]) -> Result<T> {
        deserialize::from_bytes(blob)
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SshKey {
    pub key_type: String,
    pub identifier: String,
    pub key: Vec<u8>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: Vec<u8>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    Failure,
    Success,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    RequestIdentities,
    IdentitiesAnswer(Vec<Identity>),
    SignRequest(SignRequest),
    SignResponse(SignResponse),
    Reserved15,
    Reserved16,
    AddIdentity,
    RemoveIdentity,
    RemoveAllIdentities,
    AddSmartcardKey,
    RemoveSmartcardKey,
    Lock,
    Unlock,
    Reserved24,
    AddIdConstrained,
    AddSmartcardKeyConstrained,
    Extension,
    ExtensionFailure,
}

#[cfg(test)]
mod tests {
    use super::{SshKey, Blob, Message, SignRequest, SignResponse, Identity, to_bytes, from_bytes};

    #[test]
    fn blob_serialization() {
        let key = SshKey {
            key_type: "key_type".to_string(),
            identifier: "identifier".to_string(),
            key: b"key".to_vec()
        };
        let serde_key = SshKey::from_blob(&key.to_blob().unwrap()).unwrap();
        assert_eq!(key, serde_key);
    }
    
    #[test]
    fn message_serialization() {
        let key = SshKey {
            key_type: "key_type".to_string(),
            identifier: "identifier".to_string(),
            key: b"key".to_vec()
        };
        
        let sign_req = Message::SignRequest(
            SignRequest {
                key_blob: key.to_blob().unwrap(),
                data: b"data".to_vec(),
                flags: 24
            }
        );
        let serde_sign_req: Message = from_bytes(&to_bytes(&sign_req).unwrap()).unwrap();
        assert_eq!(sign_req, serde_sign_req);
        
        let sign_resp = Message::SignResponse(
            SignResponse {
                signature: b"signature".to_vec()
            }
        );
        let serde_sign_resp: Message = from_bytes(&to_bytes(&sign_resp).unwrap()).unwrap();
        assert_eq!(sign_resp, serde_sign_resp);
        
        let success = Message::Success;
        let serde_success: Message = from_bytes(&to_bytes(&success).unwrap()).unwrap();
        assert_eq!(success, serde_success);
        
        let ident_ans = Message::IdentitiesAnswer(
            vec![
                Identity {
                    key_blob: b"key_blob_1".to_vec(),
                    comment: "comment_1".to_string()
                },
                Identity {
                    key_blob: b"key_blob_2".to_vec(),
                    comment: "".to_string()
                }
            ]
        );
        let serde_ident_ans: Message = from_bytes(&to_bytes(&ident_ans).unwrap()).unwrap();
        assert_eq!(ident_ans, serde_ident_ans);
    }
}