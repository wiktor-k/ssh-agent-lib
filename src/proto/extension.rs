use ssh_key::{public::KeyData, Signature};

/// session-bind@openssh.com extension
///
/// This extension allows a ssh client to bind an agent connection to a
/// particular SSH session.
///
/// Spec:
/// <https://github.com/openssh/openssh-portable/blob/cbbdf868bce431a59e2fa36ca244d5739429408d/PROTOCOL.agent#L6>
#[derive(Debug, Clone)]
pub struct SessionBind {
    pub host_key: KeyData,
    pub session_id: Vec<u8>,
    pub signature: Signature,
    pub is_forwarding: bool,
}
