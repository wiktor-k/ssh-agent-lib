use super::error::{ProtoError, ProtoResult};

/// Message numbers used for requests from the client to the agent.
///
/// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-message-numbers
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum RequestCode {
    RequestIdentities = 11,
    SignRequest = 13,
    AddIdentity = 17,
    RemoveIdentity = 18,
    RemoveAllIdentities = 19,
    AddSmartcardKey = 20,
    RemoveSmartcardKey = 21,
    Lock = 22,
    Unlock = 23,
    AddIdConstrained = 25,
    AddSmartcardKeyConstrained = 26,
    Extension = 27,
}

impl RequestCode {
    /// Convert an unsigned byte into a [`RequestCode`] (if valid)
    pub fn from_u8(byte: u8) -> ProtoResult<Self> {
        let out = match byte {
            11 => Self::RequestIdentities,
            13 => Self::SignRequest,
            17 => Self::AddIdentity,
            18 => Self::RemoveIdentity,
            19 => Self::RemoveAllIdentities,
            20 => Self::AddSmartcardKey,
            21 => Self::RemoveSmartcardKey,
            22 => Self::Lock,
            23 => Self::Unlock,
            25 => Self::AddIdConstrained,
            26 => Self::AddSmartcardKeyConstrained,
            27 => Self::Extension,
            command => Err(ProtoError::UnsupportedCommand { command })?,
        };

        Ok(out)
    }

    /// Serialize the request code as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Message numbers used for requests from the agent to the client.
///
/// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-message-numbers
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum ResponseCode {
    Failure = 5,
    Success = 6,
    IdentitiesAnswer = 12,
    SignResponse = 14,
    ExtensionFailure = 28,
}

impl ResponseCode {
    /// Convert an unsigned byte into a [`ResponseCode`] (if valid)
    pub fn from_u8(byte: u8) -> ProtoResult<Self> {
        let out = match byte {
            5 => Self::Failure,
            6 => Self::Success,
            12 => Self::IdentitiesAnswer,
            14 => Self::SignResponse,
            28 => Self::ExtensionFailure,
            command => Err(ProtoError::UnsupportedCommand { command })?,
        };
        Ok(out)
    }

    /// Serialize the response code as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}
