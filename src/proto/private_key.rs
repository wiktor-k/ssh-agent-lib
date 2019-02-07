use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer, SerializeTuple};
use super::error::ProtoError;

pub type MpInt = Vec<u8>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DssPrivateKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt,
    pub x: MpInt
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Ed25519PrivateKey {
    pub enc_a: String,
    pub k_enc_a: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    pub n: MpInt,
    pub e: MpInt,
    pub d: MpInt,
    pub iqmp: MpInt,
    pub p: MpInt,
    pub q: MpInt
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub d: MpInt
}

#[derive(Clone, PartialEq, Debug)]
pub enum PrivateKey {
    Dss(DssPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Rsa(RsaPrivateKey),
    EcDsa(EcDsaPrivateKey)
}

pub trait KeyEnum {
    fn key_type(&self) -> String;
}

pub trait Key {
    const KEY_TYPE: &'static str;
    fn key_type(&self) -> String {
        Self::KEY_TYPE.to_string()
    }
}

impl Key for RsaPrivateKey {
    const KEY_TYPE: &'static str = "ssh-rsa";
}

impl Key for DssPrivateKey {
    const KEY_TYPE: &'static str = "ssh-dss";
}

impl Key for Ed25519PrivateKey {
    const KEY_TYPE: &'static str = "ssh-ed25519";
}

impl Key for EcDsaPrivateKey {
    const KEY_TYPE: &'static str = "ecdsa-sha2";
    
    fn key_type(&self) -> String {
        format!("{}-{}", Self::KEY_TYPE, self.identifier).to_string()
    }
}

#[macro_export]
macro_rules! impl_key_enum_ser_de {
    ($class_name:path, $(($variant_name:path, $variant_class:ty)),* ) => {
        impl KeyEnum for $class_name {
            fn key_type(&self) -> String {
                match self {
                    $($variant_name(key) => key.key_type()),*
                }
            }
        }
        
        impl Serialize for $class_name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut serialize_tuple = serializer.serialize_tuple(2)?;
                
                match self {
                    $(
                        $variant_name(key) => {
                            serialize_tuple.serialize_element(&key.key_type())?;
                            serialize_tuple.serialize_element(key)?;
                        }
                    ),*
                };
                serialize_tuple.end()
            }
        }
        
        impl<'de> Deserialize<'de> for $class_name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$class_name, D::Error> {
                struct KeyVisitor;
                
                impl<'de> serde::de::Visitor<'de> for KeyVisitor {
                    type Value = $class_name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("Key with format (type, key)")
                    }

                    fn visit_seq<V: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: V
                    ) -> Result<Self::Value, V::Error> {
                        let key_type: String = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                        let key_type_str = key_type.as_str();
                        
                        $(
                            if key_type_str.starts_with(<$variant_class>::KEY_TYPE) {
                                let key: $variant_class = seq.next_element()?
                                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                                return Ok($variant_name(key))
                            }
                        )*
                        
                        return Err(Error::custom(ProtoError::UnexpectedVariant));
                    }
                }
                
                deserializer.deserialize_tuple(2, KeyVisitor)
            }
        }
    };
}

impl_key_enum_ser_de!(
    PrivateKey,
    (PrivateKey::Dss, DssPrivateKey),
    (PrivateKey::Rsa, RsaPrivateKey),
    (PrivateKey::EcDsa, EcDsaPrivateKey),
    (PrivateKey::Ed25519, Ed25519PrivateKey)
);