use core::str::FromStr;

use ssh_encoding::{CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};
use ssh_key::{
    certificate::Certificate, private::KeypairData, public::KeyData, Algorithm, Error, Signature,
};

use super::{PrivateKeyData, ProtoError};

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
pub enum Credential {
    Key {
        privkey: KeypairData,
        comment: String,
    },
    Cert {
        algorithm: Algorithm,
        certificate: Certificate,
        privkey: PrivateKeyData,
        comment: String,
    },
}

impl Decode for Credential {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let alg = String::decode(reader)?;
        let cert_alg = Algorithm::new_certificate(&alg);

        if let Ok(algorithm) = cert_alg {
            let certificate = reader.read_prefixed(|reader| {
                let cert = Certificate::decode(reader)?;
                Ok::<_, ProtoError>(cert)
            })?;
            let privkey = PrivateKeyData::decode_as(reader, algorithm.clone())?;
            let comment = String::decode(reader)?;

            Ok(Credential::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            })
        } else {
            let algorithm = Algorithm::from_str(&alg).map_err(EncodingError::from)?;
            let privkey = KeypairData::decode_as(reader, algorithm)?;
            let comment = String::decode(reader)?;
            Ok(Credential::Key { privkey, comment })
        }
    }
}

impl Encode for Credential {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        match self {
            Self::Key { privkey, comment } => {
                [privkey.encoded_len()?, comment.encoded_len()?].checked_sum()
            }
            Self::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            } => [
                algorithm.to_certificate_type().encoded_len()?,
                certificate.encoded_len_prefixed()?,
                privkey.encoded_len()?,
                comment.encoded_len()?,
            ]
            .checked_sum(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::Key { privkey, comment } => {
                privkey.encode(writer)?;
                comment.encode(writer)
            }
            Self::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            } => {
                algorithm.to_certificate_type().encode(writer)?;
                certificate.encode_prefixed(writer)?;
                privkey.encode(writer)?;
                comment.encode(writer)
            }
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentity {
    pub credential: Credential,
}

impl Decode for AddIdentity {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let credential = Credential::decode(reader)?;

        Ok(Self { credential })
    }
}

impl Encode for AddIdentity {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        self.credential.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        self.credential.encode(writer)
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
        match self {
            Self::RequestIdentities => 11,
            Self::SignRequest(_) => 13,
            Self::AddIdentity(_) => 17,
            Self::RemoveIdentity(_) => 18,
            Self::RemoveAllIdentities => 19,
            Self::AddSmartcardKey(_) => 20,
            Self::RemoveSmartcardKey(_) => 21,
            Self::Lock(_) => 22,
            Self::Unlock(_) => 23,
            Self::AddIdConstrained(_) => 25,
            Self::AddSmartcardKeyConstrained(_) => 26,
            Self::Extension(_) => 27,
        }
    }
}

impl Response {
    pub fn message_id(&self) -> u8 {
        match self {
            Self::Failure => 5,
            Self::Success => 6,
            Self::IdentitiesAnswer(_) => 12,
            Self::SignResponse(_) => 14,
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
    use ssh_key::{
        private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData, RsaPrivateKey},
        Mpint,
    };

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
            credential: Credential::Key {
                privkey: KeypairData::Ecdsa(demo_key()),
                comment: "baloo@angela".to_string(),
            },
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

    #[test]
    fn test_parse_certificates() {
        let msg: &[u8] = &hex!(
            "
            190000001c7373682d7273612d
            636572742d763031406f70656e737368 2e636f6d000003200000001c7373682d
            7273612d636572742d763031406f7065 6e7373682e636f6d00000020c551bbbb
            4b7a8cd1f0e5f01689926b0253d51cd2 30aec837b6439f86ad4f9b9a00000003
            0100010000018100e041915757995631 9a7f810b747b25187f5ff26556f7ff03
            7b57fa7d5911d55abd59438d98a2205a 87def0805ea6d8881f9790a010cbe0a2
            0d6145abac98de4fa3fc0f2b53b8241d b205b79e64e0a7ccd33f9f2cd34ae9d2
            ce791bc6aabc8fe1951e37a7af04b3fa 0b029710e7e958403c7bf6d40c13b264
            834f37402ec6630c486014b68413793d b3340bceb6aa4c703170048b59c944c5
            2678f91f872d169619eb39066bc78021 925efd226113f2523ecbefdaf5caa853
            36b760e7e458f7abd1af48917a778805 535dcf45345b2ed4c4aab2286bd12f38
            "
            "
            1173e856e95929ac27515608606f07ff 8514188e2e9b14c822cfd8ce12946f2b
            562c3f51b4a86317ebce585a832af467 f8ea27fd3ed1aa59d187825e9e771ad8
            c383f6fdef2853ed22579bc00a7fcf52 d9906d25dcd5e80ae35115aeb4bcba67
            1fa865c26bde46272806c4991fc9d548 878d2b99ba522083b8863d7c434c21bd
            42da838ed0355ad2fde62e8d0684bcc1 94f2911f235c85ffd3b2b4870e95460a
            2d3422130ccecf610000000000000001 000000010000000664617272656e0000
            000a0000000664617272656e00000000 660f5cc400000000660f6b3c00000000
            00000082000000157065726d69742d58 31312d666f7277617264696e67000000
            00000000177065726d69742d6167656e 742d666f7277617264696e6700000000
            000000167065726d69742d706f72742d 666f7277617264696e67000000000000
            "
            "
            000a7065726d69742d70747900000000 0000000e7065726d69742d757365722d
            72630000000000000000000000330000 000b7373682d65643235353139000000
            20dc83ccfc6ef8488b329f7360572863 25de5905237e55d7711e0a0a8d792ce2
            cb000000530000000b7373682d656432 353531390000004001f88ec5a9f1cbd5
            4c1668b3e33ac6f52c32dff0c51207fb b55a55b88b8809c369e9ac008e3228dd
            90978ff2d6bebd9bbb392883bcb56d9f 81f6afc200ce270300000180063980b0
            5c8b42329056de1f025eb78d68fdf1b2 631811302c75913b86e81b288c975e6b
            ff04cf464705a2ce23de7085c2ff79e7 5cfefd393f4b0420253b55269f9307cc
            627b8ac6579c5fb3dbf9c5c39658a285 57e83132419a98491ef0aae35a785937
            f0785e5ae430c83edb0a91b95efa6b84 0851a8c4c025b00752330dd153be15be
            "
            "
            190f79b0d31548877e5fcecd498c8206 488dc0f8c25216db63850e86a82194aa
            a94dc3585f35cf73bb8f464566d6821d e52f18d5ee37a7e718e228adf314668d
            b1285eea7e34fa71e9ff787eeac0bf3f 97d038a5dd9ecf6a9782a6d1354f5a74
            be42c6cd15aaf6efa77e06018e0a8d90 dcaffac60972a58e39e2773269ab3ac3
            0d352d66586cf8e19a821b29016b0f75 aaaad7caf17ed4913665999fe491e0bd
            2c08141dafeeb08bfe5bedea52ab46e3 3851def2204462b59fa83f853d1e3645
            c6b7e4d8e4d95fe3b74e34fe3e37c53d 026be9c19643ab4014bb82ef922208af
            68435bdc89bdbe0518655bb3ea28078b ebb7bde88ff44970181bd381000000c1
            00e0dd19b95c563d9198f0f4e4b19677 fd17465875757da008b93c0138fd89d7
            1a1f5669d967b69814462530642a5595 de4ee39a838ac8d38136cc2c20f7a7e6
            "
            "
            2bbba10146a35a2b8fba51b70a0b1a43 b43fd26b84ae5a7d1ef7857eab7b2301
            0c1d35c3cc1c781407f45875684a63a2 5a3f71fd32f0984dab7b70febadb1fe4
            4395f80a228f46f3f7dd05205d453c40 4d88712d2051cfac3a33e888a6fea26b
            332f5ac58edfad6a64cb16e39280aacc 607d32f90fb6fe45b21bd288fe9d4fc6
            b2000000c100faba9137f37dc9ab8b28 21ce0c444b03f5ea6ea5059488214ecc
            cc02417c601e32e923710d2dc1417bfe 293502aed390eb93e544a51fd4686b4b
            520e49f559e259b9cd1c2e08e41cfb36 b4979bd5f4f6917d73aeb4a47d7cfc71
            14ec7773aec5a54b0cdc4244cdd1db8a cc8c98955bf1abbe35db3dc7f540ff8a
            858a61399001f0f9c4c440de7a50ab1a 55ff1bb24f3ecdba42ca8a34a83bc76f
            fc5687d9093ba4eba91723b9ae5acdcf c650d8d95b5e8fda85ce957075079d2a
            "
            "
            134f4ed9b181000000c100e4f8860753 2262eaf1db3f11d02535c32a7506acb9
            bcd2b3e9b852a71fea134921015399be 8830db4000b7f33ec3af71b56448178b
            d4d3310ad322855c80aff5bf29fbeebd bbb09a3f09cd5fc017f0d004c08c3f56
            9e4efc15c5fa9474e0bae15e7b416ca5 bd0f053d869f3908bc042bd111af7fc5
            97ef541f70140ccdbae1d5bc781d3dc1 4b3a113f939f1da21d2031d4f37805d3
            6fc420a728ffbeed8e1e1ddb8d4d232d f1e02a152965694139f38b5a60b9198c
            513ac733f51f2c04164de10000000c62 616c6f6f40616e67656c610100000002
        "
        );
        let mut reader = msg;

        let out = Request::decode(&mut reader).expect("parse message");

        let certificate = &hex!(
            "
            0000001c7373682d7273612d63657274 2d763031406f70656e7373682e636f6d
            00000020c551bbbb4b7a8cd1f0e5f016 89926b0253d51cd230aec837b6439f86
            Ad4f9b9a000000030100010000018100 e0419157579956319a7f810b747b2518
            7f5ff26556f7ff037b57fa7d5911d55a bd59438d98a2205a87def0805ea6d888
            1f9790a010cbe0a20d6145abac98de4f a3fc0f2b53b8241db205b79e64e0a7cc
            " "
            D33f9f2cd34ae9d2ce791bc6aabc8fe1 951e37a7af04b3fa0b029710e7e95840
            3c7bf6d40c13b264834f37402ec6630c 486014b68413793db3340bceb6aa4c70
            3170048b59c944c52678f91f872d1696 19eb39066bc78021925efd226113f252
            3ecbefdaf5caa85336b760e7e458f7ab d1af48917a778805535dcf45345b2ed4
            C4aab2286bd12f381173e856e95929ac 27515608606f07ff8514188e2e9b14c8
            " "
            22cfd8ce12946f2b562c3f51b4a86317 ebce585a832af467f8ea27fd3ed1aa59
            D187825e9e771ad8c383f6fdef2853ed 22579bc00a7fcf52d9906d25dcd5e80a
            E35115aeb4bcba671fa865c26bde4627 2806c4991fc9d548878d2b99ba522083
            B8863d7c434c21bd42da838ed0355ad2 fde62e8d0684bcc194f2911f235c85ff
            D3b2b4870e95460a2d3422130ccecf61 00000000000000010000000100000006
            " "
            64617272656e0000000a000000066461 7272656e00000000660f5cc400000000
            660f6b3c000000000000008200000015 7065726d69742d5831312d666f727761
            7264696e670000000000000017706572 6d69742d6167656e742d666f72776172
            64696e6700000000000000167065726d 69742d706f72742d666f727761726469
            6e67000000000000000a7065726d6974 2d707479000000000000000e7065726d
            " "
            69742d757365722d7263000000000000 0000000000330000000b7373682d6564
            323535313900000020dc83ccfc6ef848 8b329f736057286325de5905237e55d7
            711e0a0a8d792ce2cb00000053000000 0b7373682d6564323535313900000040
            01f88ec5a9f1cbd54c1668b3e33ac6f5 2c32dff0c51207fbb55a55b88b8809c3
            69e9ac008e3228dd90978ff2d6bebd9b bb392883bcb56d9f81f6afc200ce2703
        "
        )[..];
        let mut reader = certificate;
        let certificate = Certificate::decode(&mut reader).unwrap();

        let expected = Request::AddIdConstrained(AddIdentityConstrained {
            identity: AddIdentity {
                credential: Credential::Cert {
                    algorithm: Algorithm::new("ssh-rsa").unwrap(),
                    certificate,
                    privkey: PrivateKeyData::Rsa(RsaPrivateKey {
                        d: Mpint::from_bytes(&hex!(
                            "
                            063980B05C8B42329056DE1F025EB78D 68FDF1B2631811302C75913B86E81B28
                            8C975E6BFF04CF464705A2CE23DE7085 C2FF79E75CFEFD393F4B0420253B5526
                            9F9307CC627B8AC6579C5FB3DBF9C5C3 9658A28557E83132419A98491EF0AAE3
                            5A785937F0785E5AE430C83EDB0A91B9 5EFA6B840851A8C4C025B00752330DD1
                            53BE15BE190F79B0D31548877E5FCECD 498C8206488DC0F8C25216DB63850E86
                            A82194AAA94DC3585F35CF73BB8F4645 66D6821DE52F18D5EE37A7E718E228AD
                            F314668DB1285EEA7E34FA71E9FF787E EAC0BF3F97D038A5DD9ECF6A9782A6D1
                            354F5A74BE42C6CD15AAF6EFA77E0601 8E0A8D90DCAFFAC60972A58E39E27732
                            69AB3AC30D352D66586CF8E19A821B29 016B0F75AAAAD7CAF17ED4913665999F
                            E491E0BD2C08141DAFEEB08BFE5BEDEA 52AB46E33851DEF2204462B59FA83F85
                            3D1E3645C6B7E4D8E4D95FE3B74E34FE 3E37C53D026BE9C19643AB4014BB82EF
                            922208AF68435BDC89BDBE0518655BB3 EA28078BEBB7BDE88FF44970181BD381
                            "
                        ))
                        .unwrap(),
                        iqmp: Mpint::from_bytes(&hex!(
                            "
                            00E0DD19B95C563D9198F0F4E4B19677 FD17465875757DA008B93C0138FD89D7
                            1A1F5669D967B69814462530642A5595 DE4EE39A838AC8D38136CC2C20F7A7E6
                            2BBBA10146A35A2B8FBA51B70A0B1A43 B43FD26B84AE5A7D1EF7857EAB7B2301
                            0C1D35C3CC1C781407F45875684A63A2 5A3F71FD32F0984DAB7B70FEBADB1FE4
                            4395F80A228F46F3F7DD05205D453C40 4D88712D2051CFAC3A33E888A6FEA26B
                            332F5AC58EDFAD6A64CB16E39280AACC 607D32F90FB6FE45B21BD288FE9D4FC6
                            B2"
                        ))
                        .unwrap(),
                        p: Mpint::from_bytes(&hex!(
                            "
                            00FABA9137F37DC9AB8B2821CE0C444 B03F5EA6EA5059488214ECCCC02417C
                            601E32E923710D2DC1417BFE293502A ED390EB93E544A51FD4686B4B520E49
                            F559E259B9CD1C2E08E41CFB36B4979 BD5F4F6917D73AEB4A47D7CFC7114EC
                            7773AEC5A54B0CDC4244CDD1DB8ACC8 C98955BF1ABBE35DB3DC7F540FF8A85
                            8A61399001F0F9C4C440DE7A50AB1A5 5FF1BB24F3ECDBA42CA8A34A83BC76F
                            FC5687D9093BA4EBA91723B9AE5ACDC FC650D8D95B5E8FDA85CE957075079D
                            2A134F4ED9B181"
                        ))
                        .unwrap(),
                        q: Mpint::from_bytes(&hex!(
                            "
                            00E4F88607532262EAF1DB3F11D0253 5C32A7506ACB9BCD2B3E9B852A71FEA
                            134921015399BE8830DB4000B7F33EC 3AF71B56448178BD4D3310AD322855C
                            80AFF5BF29FBEEBDBBB09A3F09CD5FC 017F0D004C08C3F569E4EFC15C5FA94
                            74E0BAE15E7B416CA5BD0F053D869F3 908BC042BD111AF7FC597EF541F7014
                            0CCDBAE1D5BC781D3DC14B3A113F939 F1DA21D2031D4F37805D36FC420A728
                            FFBEED8E1E1DDB8D4D232DF1E02A152 965694139F38B5A60B9198C513AC733
                            F51F2C04164DE1"
                        ))
                        .unwrap(),
                    }),
                    comment: "baloo@angela".to_string(),
                },
            },
            constraints: vec![KeyConstraint::Lifetime(2)],
        });
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }
}
