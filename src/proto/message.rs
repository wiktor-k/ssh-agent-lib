//! Agent protocol message structures.

mod add_remove;
mod cert_key_data;
mod extension;
mod identity;
mod request;
mod response;
mod sign;
mod unparsed;

pub use self::{
    add_remove::*, cert_key_data::*, extension::*, identity::*, request::*, response::*, sign::*,
    unparsed::*,
};
#[doc(hidden)]
/// For compatibility with pre-0.5.0 type alias in this module
/// that duplicated crate::proto::error::ProtoResult
pub use super::Result;
