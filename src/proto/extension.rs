//! SSH agent extension structures (messages & key constraints)

pub mod constraint;
pub mod message;

pub use self::constraint::*;
pub use self::message::*;

/// SSH agent protocol message extension
///
/// Described in [draft-miller-ssh-agent-14 § 3.8](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.8)
pub trait MessageExtension: 'static {
    /// Extension name, indicating the type of the message (as a UTF-8 string).
    ///
    /// Extension names should be suffixed by the implementation domain
    /// as per [RFC4251 § 4.2](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.2),
    const NAME: &'static str;
}

/// SSH agent protocol key constraint extension
///
/// Described in [draft-miller-ssh-agent-14 § 3.2.7.3](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-3.2.7.3)
pub trait KeyConstraintExtension: 'static {
    /// Extension name, indicating the type of the key constraint (as a UTF-8 string).
    ///
    /// Extension names should be suffixed by the implementation domain
    /// as per [RFC4251 § 4.2](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.2),
    const NAME: &'static str;
}
