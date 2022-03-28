pub mod de;
pub mod ser;

#[macro_use]
pub mod key_type;
pub mod error;
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
