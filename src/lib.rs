#![doc = include_str!("../README.md")]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]

pub mod proto;

#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "codec")]
pub mod codec;
pub mod error;

#[cfg(feature = "agent")]
pub use async_trait::async_trait;

#[cfg(feature = "agent")]
pub use self::agent::Agent;
