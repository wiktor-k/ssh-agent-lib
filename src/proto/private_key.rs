use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error};
use serde::ser::{Serializer, SerializeTuple};
use super::error::ProtoError;
use super::key_type::{KeyType, KeyTypeEnum};

pub type MpInt = Vec<u8>;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DssPrivateKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt,
    pub x: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Ed25519PrivateKey {
    pub enc_a: Vec<u8>,
    pub k_enc_a: Vec<u8>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SkEd25519PrivateKey {
    pub enc_a: Vec<u8>,
    pub application: String,
    pub flags: u8,
    pub key_handle: Vec<u8>,
    pub reserved: Vec<u8>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    pub n: MpInt,
    pub e: MpInt,
    pub d: MpInt,
    pub iqmp: MpInt,
    pub p: MpInt,
    pub q: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub d: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SkEcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub application: String,
    pub flags: u8,
    pub key_handle: Vec<u8>,
    pub reserved: Vec<u8>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PrivateKey {
    Dss(DssPrivateKey),
    Ed25519(Ed25519PrivateKey),
    SkEd25519(SkEd25519PrivateKey),
    Rsa(RsaPrivateKey),
    EcDsa(EcDsaPrivateKey),
    SkEcDsa(SkEcDsaPrivateKey)
}

impl KeyType for RsaPrivateKey {
    const KEY_TYPE: &'static str = "ssh-rsa";
}

impl KeyType for DssPrivateKey {
    const KEY_TYPE: &'static str = "ssh-dss";
}

impl KeyType for Ed25519PrivateKey {
    const KEY_TYPE: &'static str = "ssh-ed25519";
}

impl KeyType for SkEd25519PrivateKey {
    const KEY_TYPE: &'static str = "sk-ssh-ed25519@openssh.com";
}

impl KeyType for EcDsaPrivateKey {
    const KEY_TYPE: &'static str = "ecdsa-sha2";
    
    fn key_type(&self) -> String {
        format!("{}-{}", Self::KEY_TYPE, self.identifier)
    }
}

impl KeyType for SkEcDsaPrivateKey {
    const KEY_TYPE: &'static str = "sk-ecdsa-sha2";

    fn key_type(&self) -> String {
        format!("{}-{}@openssh.com", Self::KEY_TYPE, self.identifier)
    }
}

impl_key_type_enum_ser_de!(
    PrivateKey,
    (PrivateKey::Dss, DssPrivateKey),
    (PrivateKey::Rsa, RsaPrivateKey),
    (PrivateKey::EcDsa, EcDsaPrivateKey),
    (PrivateKey::SkEcDsa, SkEcDsaPrivateKey),
    (PrivateKey::Ed25519, Ed25519PrivateKey),
    (PrivateKey::SkEd25519, SkEd25519PrivateKey)
);
