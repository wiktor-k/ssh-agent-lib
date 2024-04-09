use ssh_encoding::{CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};
use ssh_key::{private::KeypairData, public::KeyData, Error, Signature};

use super::ProtoError;

type Result<T> = core::result::Result<T, ProtoError>;

#[derive(Clone, PartialEq, Debug)]
pub struct Identity {
    pub pubkey: KeyData,
    pub comment: String,
}

impl Identity {
    fn decode_vec(reader: &mut impl Reader) -> Result<Vec<Self>> {
        let len = u32::decode(reader)?;
        let mut identities = vec![];

        for _ in 0..len {
            identities.push(Self::decode(reader)?);
        }

        Ok(identities)
    }
}

impl Decode for Identity {
    type Error = ProtoError;

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
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;
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
            self.pubkey.encoded_len_prefixed()?,
            self.data.encoded_len()?,
            self.flags.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)?;
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
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let privkey = KeypairData::decode(reader)?;
        let comment = String::decode(reader)?;

        Ok(Self { privkey, comment })
    }
}

impl Encode for AddIdentity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.privkey.encoded_len()?, self.comment.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.privkey.encode(writer)?;
        self.comment.encode(writer)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentityConstrained {
    pub identity: AddIdentity,
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddIdentityConstrained {
    type Error = ProtoError;

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
                usize::checked_add(acc, constraint_len).ok_or(EncodingError::Length)
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

#[derive(Clone, PartialEq, Debug)]
pub struct RemoveIdentity {
    pub pubkey: KeyData,
}

impl Decode for RemoveIdentity {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let pubkey = reader.read_prefixed(KeyData::decode)?;

        Ok(Self { pubkey })
    }
}

impl Encode for RemoveIdentity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.pubkey.encoded_len_prefixed()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.pubkey.encode_prefixed(writer)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SmartcardKey {
    pub id: String,
    pub pin: String,
}

impl Decode for SmartcardKey {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let id = String::decode(reader)?;
        let pin = String::decode(reader)?;

        Ok(Self { id, pin })
    }
}

impl Encode for SmartcardKey {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.id.encoded_len()?, self.pin.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.id.encode(writer)?;
        self.pin.encode(writer)?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum KeyConstraint {
    Lifetime(u32),
    Confirm,
    Extension(String, Unparsed),
}

impl Decode for KeyConstraint {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let constraint_type = u8::decode(reader)?;
        // see: https://www.ietf.org/archive/id/draft-miller-ssh-agent-12.html#section-5.2
        Ok(match constraint_type {
            1 => KeyConstraint::Lifetime(u32::decode(reader)?),
            2 => KeyConstraint::Confirm,
            255 => {
                let name = String::decode(reader)?;
                let details: Vec<u8> = Vec::decode(reader)?;
                KeyConstraint::Extension(name, details.into())
            }
            _ => return Err(Error::AlgorithmUnknown)?, // FIXME: it should be our own type
        })
    }
}

impl Encode for KeyConstraint {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let base = u8::MAX.encoded_len()?;

        match self {
            Self::Lifetime(lifetime) => base
                .checked_add(lifetime.encoded_len()?)
                .ok_or(EncodingError::Length),
            Self::Confirm => Ok(base),
            Self::Extension(name, content) => {
                [base, name.encoded_len()?, content.0.encoded_len()?].checked_sum()
            }
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::Lifetime(lifetime) => {
                1u8.encode(writer)?;
                lifetime.encode(writer)
            }
            Self::Confirm => 2u8.encode(writer),
            Self::Extension(name, content) => {
                255u8.encode(writer)?;
                name.encode(writer)?;
                content.0.encode(writer)
            }
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddSmartcardKeyConstrained {
    pub key: SmartcardKey,
    pub constraints: Vec<KeyConstraint>,
}

impl Decode for AddSmartcardKeyConstrained {
    type Error = ProtoError;

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
                usize::checked_add(acc, constraint_len).ok_or(EncodingError::Length)
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

#[derive(Clone, PartialEq, Debug)]
pub struct Extension {
    pub name: String,
    pub details: Unparsed,
}

impl Decode for Extension {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let name = String::decode(reader)?;
        let mut details = vec![0; reader.remaining_len()];
        reader.read(&mut details)?;
        Ok(Self {
            name,
            details: details.into(),
        })
    }
}

impl Encode for Extension {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        [self.name.encoded_len()?, self.details.0.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.name.encode(writer)?;

        // NOTE: extension messages do not contain a length!
        writer.write(&self.details.0[..])?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Unparsed(Vec<u8>);

impl Unparsed {
    pub fn parse<T>(&mut self) -> std::result::Result<T, <T as Decode>::Error>
    where
        T: Decode,
    {
        let mut v = &self.0[..];
        T::decode(&mut v)
    }
}

impl From<Vec<u8>> for Unparsed {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Encode for Unparsed {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.0.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.0.encode(writer)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Request {
    RequestIdentities,
    SignRequest(SignRequest),
    AddIdentity(AddIdentity),
    RemoveIdentity(RemoveIdentity),
    RemoveAllIdentities,
    AddSmartcardKey(SmartcardKey),
    RemoveSmartcardKey(SmartcardKey),
    Lock(String),
    Unlock(String),
    AddIdConstrained(AddIdentityConstrained),
    AddSmartcardKeyConstrained(AddSmartcardKeyConstrained),
    Extension(Extension),
}

#[derive(Clone, PartialEq, Debug)]
pub enum Response {
    Failure,
    Success,
    IdentitiesAnswer(Vec<Identity>),
    SignResponse(Signature),
    ExtensionFailure,
}
impl Request {
    pub fn message_id(&self) -> u8 {
        use Request::*;
        match self {
            Self::RequestIdentities => 11,
            SignRequest(_) => 13,
            AddIdentity(_) => 17,
            RemoveIdentity(_) => 18,
            Self::RemoveAllIdentities => 19,
            AddSmartcardKey(_) => 20,
            RemoveSmartcardKey(_) => 21,
            Lock(_) => 22,
            Unlock(_) => 23,
            AddIdConstrained(_) => 25,
            AddSmartcardKeyConstrained(_) => 26,
            Extension(_) => 27,
        }
    }
}

impl Response {
    pub fn message_id(&self) -> u8 {
        use Response::*;
        match self {
            Self::Failure => 5,
            Self::Success => 6,
            IdentitiesAnswer(_) => 12,
            SignResponse(_) => 14,
            Self::ExtensionFailure => 28,
        }
    }
}

impl Decode for Request {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let message_type = u8::decode(reader)?;

        match message_type {
            11 => Ok(Self::RequestIdentities),
            13 => SignRequest::decode(reader).map(Self::SignRequest),
            17 => AddIdentity::decode(reader).map(Self::AddIdentity),
            18 => RemoveIdentity::decode(reader).map(Self::RemoveIdentity),
            19 => Ok(Self::RemoveAllIdentities),
            20 => SmartcardKey::decode(reader).map(Self::AddSmartcardKey),
            21 => SmartcardKey::decode(reader).map(Self::RemoveSmartcardKey),
            22 => Ok(String::decode(reader).map(Self::Lock)?),
            23 => Ok(String::decode(reader).map(Self::Unlock)?),
            25 => AddIdentityConstrained::decode(reader).map(Self::AddIdConstrained),
            26 => AddSmartcardKeyConstrained::decode(reader).map(Self::AddSmartcardKeyConstrained),
            27 => Extension::decode(reader).map(Self::Extension),
            command => Err(ProtoError::UnsupportedCommand { command }),
        }
    }
}

impl Decode for Response {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let message_type = u8::decode(reader)?;

        match message_type {
            5 => Ok(Self::Failure),
            6 => Ok(Self::Success),
            12 => Identity::decode_vec(reader).map(Self::IdentitiesAnswer),
            14 => {
                Ok(reader
                    .read_prefixed(|reader| Signature::decode(reader).map(Self::SignResponse))?)
            }
            28 => Ok(Self::ExtensionFailure),
            command => Err(ProtoError::UnsupportedCommand { command }),
        }
    }
}

impl Encode for Request {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let message_id_len = 1;
        let payload_len = match self {
            Self::RequestIdentities => 0,
            Self::SignRequest(request) => request.encoded_len()?,
            Self::AddIdentity(identity) => identity.encoded_len()?,
            Self::RemoveIdentity(identity) => identity.encoded_len()?,
            Self::RemoveAllIdentities => 0,
            Self::AddSmartcardKey(key) => key.encoded_len()?,
            Self::RemoveSmartcardKey(key) => key.encoded_len()?,
            Self::Lock(passphrase) => passphrase.encoded_len()?,
            Self::Unlock(passphrase) => passphrase.encoded_len()?,
            Self::AddIdConstrained(key) => key.encoded_len()?,
            Self::AddSmartcardKeyConstrained(key) => key.encoded_len()?,
            Self::Extension(extension) => extension.encoded_len()?,
        };

        [message_id_len, payload_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let message_id: u8 = self.message_id();
        message_id.encode(writer)?;

        match self {
            Self::RequestIdentities => {}
            Self::SignRequest(request) => request.encode(writer)?,
            Self::AddIdentity(identity) => identity.encode(writer)?,
            Self::RemoveIdentity(identity) => identity.encode(writer)?,
            Self::RemoveAllIdentities => {}
            Self::AddSmartcardKey(key) => key.encode(writer)?,
            Self::RemoveSmartcardKey(key) => key.encode(writer)?,
            Self::Lock(passphrase) => passphrase.encode(writer)?,
            Self::Unlock(passphrase) => passphrase.encode(writer)?,
            Self::AddIdConstrained(identity) => identity.encode(writer)?,
            Self::AddSmartcardKeyConstrained(key) => key.encode(writer)?,
            Self::Extension(extension) => extension.encode(writer)?,
        };

        Ok(())
    }
}
impl Encode for Response {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        let message_id_len = 1;
        let payload_len = match self {
            Self::Failure => 0,
            Self::Success => 0,
            Self::IdentitiesAnswer(ids) => {
                let mut lengths = Vec::with_capacity(1 + ids.len());
                // Prefixed length
                lengths.push(4);

                for id in ids {
                    lengths.push(id.encoded_len()?);
                }

                lengths.checked_sum()?
            }
            Self::SignResponse(response) => response.encoded_len_prefixed()?,
            Self::ExtensionFailure => 0,
        };

        [message_id_len, payload_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        let message_id: u8 = self.message_id();
        message_id.encode(writer)?;

        match self {
            Self::Failure => {}
            Self::Success => {}
            Self::IdentitiesAnswer(ids) => {
                (ids.len() as u32).encode(writer)?;
                for id in ids {
                    id.encode(writer)?;
                }
            }
            Self::SignResponse(response) => response.encode_prefixed(writer)?,
            Self::ExtensionFailure => {}
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Note: yes, some of those tests carry a private key, this is a key that
    //       was generated for the purpose of those tests

    use hex_literal::hex;
    use p256::{
        elliptic_curve::{bigint::Uint, ScalarPrimitive},
        EncodedPoint,
    };
    use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData};

    use super::*;

    fn demo_key() -> EcdsaKeypair {
        EcdsaKeypair::NistP256 {
            public: EncodedPoint::from_affine_coordinates(
                &hex!("cb244fcdb89de95bc8fd766e6b139abfc2649fb063b6c5e5a939e067e2a0d215").into(),
                &hex!("0a660daca78f6c24a0425373d6ea83e36f8a1f8b828a60e77a97a9441bcc0987").into(),
                false,
            ),
            private: EcdsaPrivateKey::from(p256::SecretKey::new(
                ScalarPrimitive::new(Uint::from_be_hex(
                    "ffd9f2ce4d0ee5870d8dc7cf771a7669a0b96fe44bb58a8a0bc75a76b4f78240",
                ))
                .unwrap(),
            )),
        }
    }

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
                privkey: KeypairData::Ecdsa(demo_key()),
                comment: "baloo@angela".to_string(),
            },
            constraints: vec![KeyConstraint::Lifetime(2)],
        };
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
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
                privkey: KeypairData::Ecdsa(demo_key()),
                comment: "baloo@angela".to_string(),
            },
            constraints: vec![KeyConstraint::Extension(
                "restrict-destination-v00@openssh.com".to_string(),
                hex!(
                    "
                                                 00
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
                .to_vec()
                .into(),
            )],
        };

        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }

    #[test]
    fn test_add_identity() {
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
	    6c61
        "
        );
        let mut reader = msg;

        let out = AddIdentity::decode(&mut reader).expect("parse message");

        let expected = AddIdentity {
            privkey: KeypairData::Ecdsa(demo_key()),
            comment: "baloo@angela".to_string(),
        };
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }

    #[test]
    fn test_parse_identities() {
        let msg: &[u8] = &hex!(
            "
            0c000000010000006800000013656364
            73612d736861322d6e69737470323536
            000000086e6973747032353600000041
            04cb244fcdb89de95bc8fd766e6b139a
            bfc2649fb063b6c5e5a939e067e2a0d2
            150a660daca78f6c24a0425373d6ea83
            e36f8a1f8b828a60e77a97a9441bcc09
            870000000c62616c6f6f40616e67656c
            61"
        );
        let mut reader = msg;

        let out = Response::decode(&mut reader).expect("parse message");

        let expected = Response::IdentitiesAnswer(vec![Identity {
            pubkey: KeyData::Ecdsa(demo_key().into()),
            comment: "baloo@angela".to_string(),
        }]);
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }
}
