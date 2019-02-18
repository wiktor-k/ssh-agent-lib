use serde::{Deserialize, Serialize};

use super::private_key::*;
use super::key_type::{KeyType};
use super::to_bytes;

pub type MpInt = Vec<u8>;

pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    pub blob: Vec<u8>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaSignature {
    pub identifier: String,
    pub data: EcDsaSignatureData
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EcDsaSignatureData {
    pub r: Vec<u8>,
    pub s: Vec<u8>
}

impl From<EcDsaSignature> for Signature {
    fn from(signature: EcDsaSignature) -> Signature {
        Signature {
            algorithm: format!("{}-{}", EcDsaPrivateKey::KEY_TYPE, signature.identifier),
            blob: to_bytes(&signature.data).unwrap()
        }
    }
}
