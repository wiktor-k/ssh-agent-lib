use ssh_encoding::{Decode, Encode};

use super::code;

/// Structured responses to `Reply` messages sent from the agent
pub trait Response: Decode + Encode + Sized {
    /// Message number of this response
    const COMMAND_CODE: code::ResponseCode;
}
