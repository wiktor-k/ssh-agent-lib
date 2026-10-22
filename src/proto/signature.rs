//! Agent protocol signature flag constants.

/// The `SSH_AGENT_RSA_SHA2_256` signature flag, as described in
/// [RFC9987 § 5.6.1](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.6.1)
pub const RSA_SHA2_256: u32 = 0x02;
/// The `SSH_AGENT_RSA_SHA2_512` signature flag, as described in
/// [RFC9987 § 5.6.1](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.6.1)
pub const RSA_SHA2_512: u32 = 0x04;
