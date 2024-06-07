#![doc = include_str!("../README.md")]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod proto;

#[cfg(feature = "agent")]
pub mod agent;
pub mod blocking;
#[cfg(feature = "agent")]
pub mod client;
#[cfg(feature = "codec")]
pub mod codec;
pub mod error;

#[cfg(feature = "agent")]
pub use async_trait::async_trait;
//
// re-export dependencies that are used in the public API of our crate
pub use secrecy;
pub use ssh_encoding;
pub use ssh_key;
