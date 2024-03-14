use ssh_encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::{private::KeypairData, public::KeyData, Error, Result, Signature};

#[derive(Clone, PartialEq, Debug)]
pub struct Identity {
    pub pubkey: KeyData,
    pub comment: String,
}

impl Decode for Identity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;
        let comment = String::decode(reader)?;

        Ok(Self { pubkey, comment })
    }
}

impl Encode for Identity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.pubkey.encoded_len_prefixed()?,
            self.comment.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)?;
        self.comment.encode(writer)?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SignRequest {
    pub pubkey: KeyData,
    pub data: Vec<u8>,
    pub flags: u32,
}

impl Decode for SignRequest {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = KeyData::decode(reader)?;
        let data = Vec::decode(reader)?;
        let flags = u32::decode(reader)?;

        Ok(Self {
            pubkey,
            data,
            flags,
        })
    }
}

impl Encode for SignRequest {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [
            self.pubkey.encoded_len()?,
            self.data.encoded_len()?,
            self.flags.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode(writer)?;
        self.data.encode(writer)?;
        self.flags.encode(writer)?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentity {
    pub privkey: KeypairData,
    pub comment: String,
}

impl Decode for AddIdentity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        println!("foo0");
        let privkey = KeypairData::decode(reader)?;
        println!("foo1");
        let comment = String::decode(reader)?;
        println!("foo2");

        Ok(Self { privkey, comment })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentityConstrained {
    pub identity: AddIdentity,
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddIdentityConstrained {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        todo!();
        //let identity = AddIdentity::decode(reader)?;
        //let constraints = Vec::decode(reader)?;

        //Ok(Self {
        //    identity,
        //    constraints,
        //})
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct RemoveIdentity {
    pub pubkey: KeyData,
}

impl Decode for RemoveIdentity {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;

        Ok(Self { pubkey })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SmartcardKey {
    pub id: String,
    pub pin: String,
}

impl Decode for SmartcardKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let id = String::decode(reader)?;
        let pin = String::decode(reader)?;

        Ok(Self { id, pin })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct KeyConstraint {
    pub constraint_type: u8,
    pub constraint_data: Vec<u8>,
}

impl Decode for KeyConstraint {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let constraint_type = u8::decode(reader)?;
        let constraint_data = Vec::decode(reader)?;

        Ok(Self {
            constraint_type,
            constraint_data,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddSmartcardKeyConstrained {
    pub key: SmartcardKey,
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddSmartcardKeyConstrained {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        todo!()
        //let key = SmartcardKey::decode(reader)?;
        //let constraints = Vec::decode(reader)?;

        //Ok(Self { key, constraints })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Extension {
    pub extension_type: String,
    pub extension_contents: ExtensionContents,
}

impl Decode for Extension {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        todo!()
        //let key = SmartcardKey::decode(reader)?;
        //let constraints = Vec::decode(reader)?;

        //Ok(Self { key, constraints })
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct ExtensionContents(pub Vec<u8>);

pub type Passphrase = String;

#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    Failure,
    Success,
    RequestIdentities,
    IdentitiesAnswer(Vec<Identity>),
    SignRequest(SignRequest),
    SignResponse(Signature),
    AddIdentity(AddIdentity),
    RemoveIdentity(RemoveIdentity),
    RemoveAllIdentities,
    AddSmartcardKey(SmartcardKey),
    RemoveSmartcardKey(SmartcardKey),
    Lock(Passphrase),
    Unlock(Passphrase),
    AddIdConstrained(AddIdentityConstrained),
    AddSmartcardKeyConstrained(AddSmartcardKeyConstrained),
    Extension(Extension),
    ExtensionFailure,
}

impl Decode for Message {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        println!("foo0");
        let message_type = u8::decode(reader)?;
        println!("foo1");

        match message_type {
            5 => Ok(Self::Failure),
            6 => Ok(Self::Success),
            11 => Ok(Self::RequestIdentities),
            12 => todo!(),
            13 => SignRequest::decode(reader).map(Self::SignRequest),
            14 => Signature::decode(reader).map(Self::SignResponse),
            17 => AddIdentity::decode(reader).map(Self::AddIdentity),
            18 => RemoveIdentity::decode(reader).map(Self::RemoveIdentity),
            19 => Ok(Self::RemoveAllIdentities),
            20 => SmartcardKey::decode(reader).map(Self::AddSmartcardKey),
            21 => SmartcardKey::decode(reader).map(Self::RemoveSmartcardKey),
            22 => Ok(Passphrase::decode(reader).map(Self::Lock)?),
            23 => Ok(Passphrase::decode(reader).map(Self::Unlock)?),
            25 => AddIdentityConstrained::decode(reader).map(Self::AddIdConstrained),
            26 => AddSmartcardKeyConstrained::decode(reader).map(Self::AddSmartcardKeyConstrained),
            27 => Extension::decode(reader).map(Self::Extension),
            28 => Ok(Self::ExtensionFailure),
            _ => todo!(),
        }
    }
}

impl Encode for Message {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let command_id = 1;
        let payload_len = match self {
            Self::Failure => 0,
            Self::Success => 0,
            Self::RequestIdentities => 0,
            Self::IdentitiesAnswer(ids) => {
                let mut lengths = Vec::with_capacity(1 + ids.len());
                // Prefixed length
                lengths.push(4);

                for id in ids {
                    lengths.push(id.encoded_len()?);
                }

                lengths.checked_sum()?
            }
            _ => todo!(),
        };

        [command_id, payload_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let command_id: u8 = match self {
            Self::Failure => 5,
            Self::Success => 6,
            Self::RequestIdentities => 11,
            Self::IdentitiesAnswer(_) => 12,
            _ => todo!(),
        };

        command_id.encode(writer)?;
        match self {
            Self::Failure => {}
            Self::Success => {}
            Self::RequestIdentities => {}
            Self::IdentitiesAnswer(ids) => {
                (ids.len() as u32).encode(writer)?;
                for id in ids {
                    id.encode(writer)?;
                }
            }
            _ => todo!(),
        };

        Ok(())
    }
}
