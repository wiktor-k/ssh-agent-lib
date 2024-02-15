use serde::{Deserialize, Serialize};

use super::recursive;
use super::signature::Signature;

/// SSH key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub alg: String,
    pub blob: Vec<u8>,
}

/// session-bind@openssh.com extension
///
/// This extension allows a ssh client to bind an agent connection to a
/// particular SSH session.
///
/// Spec:
/// <https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L6>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBind {
    #[serde(with = "recursive")]
    pub host_key: SshKey,
    pub session_id: Vec<u8>,
    #[serde(with = "recursive")]
    pub signature: Signature,
    pub is_forwarding: bool,
}
