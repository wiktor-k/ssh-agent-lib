pub mod ser;
pub mod de;

#[macro_use]
pub mod key_type;
pub mod private_key;
pub mod public_key;
pub mod signature;
pub mod message;
pub mod error;

#[cfg(test)]
mod tests;

pub use self::ser::to_bytes;
pub use self::de::from_bytes;

pub use self::key_type::*;
pub use self::private_key::*;
pub use self::public_key::*;
pub use self::signature::*;
pub use self::message::*;
pub use self::error::*;

use serde::{Serialize, Deserialize};

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
