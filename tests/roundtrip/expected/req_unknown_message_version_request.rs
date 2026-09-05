use hex_literal::hex;
use ssh_agent_lib::proto::{Request, Unparsed};

/// From [PR#112](https://github.com/wiktor-k/ssh-agent-lib/pull/112), this
/// payload is an:
/// > `SSH2_AGENT_REQUEST_VERSION` (message type 1) with a "2.0" payload,
/// > as sent by `net-ssh` during agent negotiation.
/// 
/// This message type is defined in the `net-ssh` documentation [1].
/// 
/// Message type 1, at least from an RFC perspective is not a supported
/// SSH agent command. We should capture this as a `Request::Unknown`,
/// retaining the body in case an implementation wants to parse it.
/// 
/// [1] https://net-ssh.github.io/net-ssh/classes/Net/SSH/Authentication/Agent.html
pub fn expected() -> Request {
    Request::Unknown {
        message_id: 1,
        payload: Unparsed::from(hex!("00000003 322E30").to_vec())
    }
}
