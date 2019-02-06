use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer, SerializeTuple};
use super::error::ProtoError;
use super::private_key;

pub type MpInt = Vec<u8>;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RsaKey {
    pub e: MpInt,
    pub n: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct DssKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaKey {
    pub identifier: String,
    pub q: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Ed25519Key {
    pub enc_a: String
}

#[derive(PartialEq, Debug)]
pub enum PublicKey {
    Dss(DssKey),
    Ed25519(Ed25519Key),
    Rsa(RsaKey),
    EcDsa(EcDsaKey)
}

impl From<private_key::RsaKey> for RsaKey {
    fn from(key: private_key::RsaKey) -> Self {
        Self {
            e: key.e,
            n: key.n
        }
    }
}

impl From<private_key::DssKey> for DssKey {
    fn from(key: private_key::DssKey) -> Self {
        Self {
            p: key.p,
            q: key.q,
            g: key.g,
            y: key.y
        }
    }
}

impl From<private_key::EcDsaKey> for EcDsaKey {
    fn from(key: private_key::EcDsaKey) -> Self {
        Self {
            identifier: key.identifier,
            q: key.q
        }
    }
}

impl From<private_key::Ed25519Key> for Ed25519Key {
    fn from(key: private_key::Ed25519Key) -> Self {
        Self {
            enc_a: key.enc_a
        }
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut serialize_tuple = serializer.serialize_tuple(2)?;
        
        match self {
            PublicKey::Dss(key) => {
                serialize_tuple.serialize_element("ssh-dsa")?;
                serialize_tuple.serialize_element(key)?;
            },
            PublicKey::Ed25519(key) => {
                serialize_tuple.serialize_element("ssh-ed25519")?;
                serialize_tuple.serialize_element(key)?;
            },
            PublicKey::Rsa(key) => {
                serialize_tuple.serialize_element("ssh-rsa")?;
                serialize_tuple.serialize_element(key)?;
            },
            PublicKey::EcDsa(key) => {
                serialize_tuple.serialize_element(
                    format!("ecdsa-sha2-{}", key.identifier).as_str()
                )?;
                serialize_tuple.serialize_element(key)?;
            }
        };
        
        serialize_tuple.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PublicKey, D::Error> {
        struct KeyVisitor;
        
        impl<'de> serde::de::Visitor<'de> for KeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Public Key with format (type, key)")
            }

            fn visit_seq<V: serde::de::SeqAccess<'de>>(
                self,
                mut seq: V
            ) -> Result<PublicKey, V::Error> {
                let key_type: String = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                match key_type.as_str() {
                    "ssh-dss" => {
                        let key: DssKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Dss(key))
                    },
                    "ssh-ed25519" => {
                        let key: Ed25519Key = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Ed25519(key))
                    },
                    "ssh-rsa" => {
                        let key: RsaKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Rsa(key))
                    },
                    other => {
                        if other.starts_with("ecdsa-sha2-") {
                            let key: EcDsaKey = seq.next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                            Ok(PublicKey::EcDsa(key))
                        } else {
                            Err(Error::custom(ProtoError::UnexpectedVariant))
                        }
                    } 
                }
            }
        }
        
        deserializer.deserialize_tuple(2, KeyVisitor)
    }
}