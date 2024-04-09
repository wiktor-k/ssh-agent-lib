use ssh_encoding::{Decode, Encode};

use super::{code, response::Response};

/// Request that might be sent to an agent.
/// Each request has a coresponding `ResponseType`.
pub trait Request: Encode + Decode + Sized {
    /// Message number for this request
    const REQUEST_CODE: code::RequestCode;

    /// Response type for this request
    type ResponseType: Response;
}
