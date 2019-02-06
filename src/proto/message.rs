use super::private_key::PrivateKey;

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
pub struct AddIdentity {
    pub key_contents: PrivateKey,
    pub key_comment: String
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct AddIdentityConstrained {
    pub identity: AddIdentity,
    pub constraints: Vec<KeyConstraint>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RemoveIdentity {
    pub key_blob: Vec<u8>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SmartcardKey {
    pub id: String,
    pub pin: String
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyConstraint {
    pub constraint_type: u8,
    pub constraint_data: Vec<u8>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct AddSmartcardKeyConstrained {
    pub key: SmartcardKey,
    pub constraints: Vec<KeyConstraint>
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Extension {
    extension_type: String,
    extension_contents: Vec<u8>
}

type Passphrase = String;

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