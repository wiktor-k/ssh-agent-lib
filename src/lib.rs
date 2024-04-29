#![doc = include_str!("../README.md")]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod proto;

#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "agent")]
pub mod client;
#[cfg(feature = "codec")]
pub mod codec;
pub mod error;

#[cfg(feature = "agent")]
pub use async_trait::async_trait;
