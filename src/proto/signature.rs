//! Agent protocol signature flag constants.

/// The `SSH_AGENT_RSA_SHA2_256` signature flag, as described in
/// [draft-miller-ssh-agent-14 § 3.6.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.6.1)
pub const RSA_SHA2_256: u32 = 0x02;
/// The `SSH_AGENT_RSA_SHA2_512` signature flag, as described in
/// [draft-miller-ssh-agent-14 § 3.6.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.6.1)
pub const RSA_SHA2_512: u32 = 0x04;
