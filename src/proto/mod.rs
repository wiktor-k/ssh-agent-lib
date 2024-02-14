pub mod de;
pub mod ser;

#[macro_use]
pub mod key_type;
pub mod error;
pub mod extension;
pub mod message;
pub mod private_key;
pub mod public_key;
pub mod signature;

#[cfg(test)]
mod tests;

pub use self::de::from_bytes;
pub use self::ser::to_bytes;

pub use self::error::*;
pub use self::key_type::*;
pub use self::message::*;
pub use self::private_key::*;
pub use self::public_key::*;
pub use self::signature::*;

use serde::{Deserialize, Serialize};

pub type MpInt = Vec<u8>;

pub trait Blob: Sized {
    fn to_blob(&self) -> ProtoResult<Vec<u8>>;
    fn from_blob(blob: &[u8]) -> ProtoResult<Self>;
}

impl<'a, T: Serialize + Deserialize<'a>> Blob for T {
    fn to_blob(&self) -> ProtoResult<Vec<u8>> {
        to_bytes(self)
    }

    fn from_blob(blob: &[u8]) -> ProtoResult<T> {
        from_bytes(blob)
    }
}

pub mod recursive {
    use super::{from_bytes, to_bytes};
    use serde::{
        de::{self, Deserializer, Visitor},
        ser::{Error, Serializer},
        Deserialize, Serialize,
    };
    use std::{fmt, marker::PhantomData};

    pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        serializer.serialize_bytes(&to_bytes(obj).map_err(S::Error::custom)?)
    }

    pub fn deserialize<'de, T, D>(deserialize: D) -> Result<T, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct RecursiveVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for RecursiveVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = T;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an integer between -2^31 and 2^31")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                from_bytes(value).map_err(E::custom)
            }
        }

        deserialize.deserialize_bytes(RecursiveVisitor(PhantomData::<T>))
    }
}
