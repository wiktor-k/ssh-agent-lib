use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Visitor};

use super::private_key::PrivateKey;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub pubkey_blob: Vec<u8>,
    pub comment: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub pubkey_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddIdentity {
    pub privkey: PrivateKey,
    pub comment: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddIdentityConstrained {
    pub identity: AddIdentity,
    pub constraints: Vec<KeyConstraint>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RemoveIdentity {
    pub pubkey_blob: Vec<u8>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SmartcardKey {
    pub id: String,
    pub pin: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyConstraint {
    pub constraint_type: u8,
    pub constraint_data: Vec<u8>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddSmartcardKeyConstrained {
    pub key: SmartcardKey,
    pub constraints: Vec<KeyConstraint>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: String,
    pub extension_contents: ExtensionContents,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ExtensionContents(pub Vec<u8>);

impl Serialize for ExtensionContents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExtensionContents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentsVisitor;

        impl<'de> Visitor<'de> for ContentsVisitor {
            type Value = ExtensionContents;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("raw bytes buffer")
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(ExtensionContents(v))
            }
        }

        deserializer.deserialize_any(ContentsVisitor)
    }
}

pub type Passphrase = String;
pub type SignatureBlob = Vec<u8>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
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
    SignResponse(SignatureBlob),
    Reserved15,
    Reserved16,
    AddIdentity(AddIdentity),
    RemoveIdentity(RemoveIdentity),
    RemoveAllIdentities,
    AddSmartcardKey(SmartcardKey),
    RemoveSmartcardKey(SmartcardKey),
    Lock(Passphrase),
    Unlock(Passphrase),
    Reserved24,
    AddIdConstrained(AddIdentityConstrained),
    AddSmartcardKeyConstrained(AddSmartcardKeyConstrained),
    Extension(Extension),
    ExtensionFailure,
}
