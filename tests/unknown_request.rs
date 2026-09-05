//! Integration test: the agent must reply `SSH_AGENT_FAILURE` to requests of an
//! unknown type and keep the connection open, instead of dropping it.
//!
//! This mirrors the behaviour of OpenSSH's `ssh-agent` and is required by
//! [draft-miller-ssh-agent-14 § 4.1](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html#section-4.1):
//!
//! > SSH_AGENT_FAILURE messages are also sent in reply to requests with unknown types.
//!
//! Some clients (for example Ruby's `net-ssh`) probe the agent with a legacy
//! `SSH2_AGENT_REQUEST_VERSION` (type 1) message that most agents do not
//! implement. Such probes must not kill the connection.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, Request, Response};
use ssh_encoding::{Decode, Encode};

#[derive(Clone, Default)]
struct DummyAgent;

#[ssh_agent_lib::async_trait]
impl Session for DummyAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(Vec::new())
    }
}

fn spawn_agent(addr: &str) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let addr = addr.to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(async { tokio::net::TcpListener::bind(&addr).await.unwrap() });
    let sock_addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        rt.block_on(async move { listen(listener, DummyAgent).await.unwrap() });
    });
    (sock_addr, handle)
}

/// Wait until the agent is accepting connections on `addr`.
fn wait_for_socket(addr: std::net::SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for agent socket");
}

/// Write a raw agent request frame (length prefix + body) and read the raw
/// response frame, mimicking how low-level clients such as `net-ssh` talk to
/// the agent. Returns `None` if the connection was closed without a reply.
fn raw_roundtrip(stream: &mut TcpStream, body: &[u8]) -> Option<Vec<u8>> {
    let mut request = Vec::new();
    (body.len() as u32).encode(&mut request).unwrap();
    request.extend_from_slice(body);
    stream.write_all(&request).unwrap();

    let mut header = [0u8; 4];
    if stream.read_exact(&mut header).is_err() {
        return None;
    }
    let len = u32::from_be_bytes(header) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).ok()?;
    Some(response)
}

#[test]
fn unknown_request_type_replies_failure_and_keeps_connection_open() {
    let (addr, handle) = spawn_agent("127.0.0.1:0");
    wait_for_socket(addr);

    let mut stream = TcpStream::connect(addr).unwrap();

    // `SSH2_AGENT_REQUEST_VERSION` (message type 1) with a "2.0" payload,
    // as sent by `net-ssh` during agent negotiation. Message type 1 is not a
    // supported SSH agent command.
    let request_body = [1u8, 0, 0, 0, 3, b'2', b'.', b'0'];
    let response = raw_roundtrip(&mut stream, &request_body)
        .expect("agent must reply instead of closing the connection");

    // The response must be an SSH_AGENT_FAILURE (message type 5) with no body.
    let mut rest = &response[..];
    let decoded = Response::decode(&mut rest).unwrap();
    assert_eq!(decoded, Response::Failure);
    assert_eq!(response[0], 5, "expected SSH_AGENT_FAILURE (5)");

    // At the protocol level, the unknown request must decode into a
    // `Request::Unknown` which retains the message type byte *and* the body.
    let decoded = Request::decode(&mut &request_body[..]).unwrap();
    let Request::Unknown {
        message_id,
        payload,
    } = &decoded
    else {
        panic!("expected Request::Unknown");
    };
    assert_eq!(*message_id, 1, "expected SSH2_AGENT_REQUEST_VERSION (1)");
    assert_eq!(payload.as_ref(), &[0, 0, 0, 3, b'2', b'.', b'0']);

    // The request must encode back to the original wire bytes.
    let mut reencoded = Vec::new();
    decoded.encode(&mut reencoded).unwrap();
    assert_eq!(reencoded, request_body);

    // The connection must stay usable: issue a supported request afterwards.
    let mut request = Vec::new();
    Request::RequestIdentities.encode(&mut request).unwrap();
    let response = raw_roundtrip(&mut stream, &request)
        .expect("connection must remain open after an unknown request type");
    let mut rest = &response[..];
    let decoded = Response::decode(&mut rest).unwrap();
    assert!(matches!(decoded, Response::IdentitiesAnswer(_)));

    stream.shutdown(Shutdown::Both).unwrap();
    // The agent keeps accepting connections, so detach instead of joining.
    drop(handle);
}
