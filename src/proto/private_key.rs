use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer, SerializeTuple};
use super::error::ProtoError;

pub type MpInt = Vec<u8>;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct DssPrivateKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt,
    pub x: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct Ed25519PrivateKey {
    pub enc_a: String,
    pub k_enc_a: String
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    pub n: MpInt,
    pub e: MpInt,
    pub d: MpInt,
    pub iqmp: MpInt,
    pub p: MpInt,
    pub q: MpInt
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub d: MpInt
}

#[derive(PartialEq, Debug)]
pub enum PrivateKey {
    Dss(DssPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Rsa(RsaPrivateKey),
    EcDsa(EcDsaPrivateKey)
}

impl Serialize for PrivateKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut serialize_tuple = serializer.serialize_tuple(2)?;
        
        match self {
            PrivateKey::Dss(key) => {
                serialize_tuple.serialize_element("ssh-dsa")?;
                serialize_tuple.serialize_element(key)?;
            },
            PrivateKey::Ed25519(key) => {
                serialize_tuple.serialize_element("ssh-ed25519")?;
                serialize_tuple.serialize_element(key)?;
            },
            PrivateKey::Rsa(key) => {
                serialize_tuple.serialize_element("ssh-rsa")?;
                serialize_tuple.serialize_element(key)?;
            },
            PrivateKey::EcDsa(key) => {
                serialize_tuple.serialize_element(
                    format!("ecdsa-sha2-{}", key.identifier).as_str()
                )?;
                serialize_tuple.serialize_element(key)?;
            }
        };
        
        serialize_tuple.end()
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PrivateKey, D::Error> {
        struct KeyVisitor;
        
        impl<'de> serde::de::Visitor<'de> for KeyVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Private Key with format (type, key)")
            }

            fn visit_seq<V: serde::de::SeqAccess<'de>>(
                self,
                mut seq: V
            ) -> Result<PrivateKey, V::Error> {
                let key_type: String = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                match key_type.as_str() {
                    "ssh-dss" => {
                        let key: DssPrivateKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PrivateKey::Dss(key))
                    },
                    "ssh-ed25519" => {
                        let key: Ed25519PrivateKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PrivateKey::Ed25519(key))
                    },
                    "ssh-rsa" => {
                        let key: RsaPrivateKey = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(PrivateKey::Rsa(key))
                    },
                    other => {
                        if other.starts_with("ecdsa-sha2-") {
                            let key: EcDsaPrivateKey = seq.next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                            Ok(PrivateKey::EcDsa(key))
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