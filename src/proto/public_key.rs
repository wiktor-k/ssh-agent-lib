use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer, SerializeTuple};
use super::error::ProtoError;
use super::private_key;

pub type MpInt = Vec<u8>;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RsaPublicKey {
    pub e: MpInt,
    pub n: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct DssPublicKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaPublicKey {
    pub identifier: String,
    pub q: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    pub enc_a: String
}

#[derive(PartialEq, Debug)]
pub enum PublicKey {
    Dss(DssPublicKey),
    Ed25519(Ed25519PublicKey),
    Rsa(RsaPublicKey),
    EcDsa(EcDsaPublicKey)
}

impl From<private_key::RsaPrivateKey> for RsaPublicKey {
    fn from(key: private_key::RsaPrivateKey) -> Self {
        Self {
            e: key.e,
            n: key.n
        }
    }
}

impl From<private_key::DssPrivateKey> for DssPublicKey {
    fn from(key: private_key::DssPrivateKey) -> Self {
        Self {
            p: key.p,
            q: key.q,
            g: key.g,
            y: key.y
        }
    }
}

impl From<private_key::EcDsaPrivateKey> for EcDsaPublicKey {
    fn from(key: private_key::EcDsaPrivateKey) -> Self {
        Self {
            identifier: key.identifier,
            q: key.q
        }
    }
}

impl From<private_key::Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(key: private_key::Ed25519PrivateKey) -> Self {
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
                        let key: DssPublicKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Dss(key))
                    },
                    "ssh-ed25519" => {
                        let key: Ed25519PublicKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Ed25519(key))
                    },
                    "ssh-rsa" => {
                        let key: RsaPublicKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PublicKey::Rsa(key))
                    },
                    other => {
                        if other.starts_with("ecdsa-sha2-") {
                            let key: EcDsaPublicKey = seq.next_element()?
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