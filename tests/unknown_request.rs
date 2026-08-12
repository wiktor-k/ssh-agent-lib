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

use std::os::unix::net::UnixStream as StdUnixStream;
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

fn spawn_agent(socket_path: &std::path::Path) -> std::thread::JoinHandle<()> {
    let socket_path = socket_path.to_path_buf();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            listen(listener, DummyAgent).await.unwrap();
        });
    })
}

/// Wait until the agent is accepting connections on `socket_path`.
fn wait_for_socket(socket_path: &std::path::Path) {
    for _ in 0..100 {
        if StdUnixStream::connect(socket_path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for agent socket");
}

/// Write a raw agent request frame (length prefix + body) and read the raw
/// response frame, mimicking how low-level clients such as `net-ssh` talk to
/// the agent. Returns `None` if the connection was closed without a reply.
fn raw_roundtrip(stream: &mut StdUnixStream, body: &[u8]) -> Option<Vec<u8>> {
    use std::io::{Read, Write};

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
    let socket_path =
        std::env::temp_dir().join(format!("ssh-agent-lib-unknown-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let handle = spawn_agent(&socket_path);
    wait_for_socket(&socket_path);

    let mut stream = StdUnixStream::connect(&socket_path).unwrap();

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

    // The connection must stay usable: issue a supported request afterwards.
    let mut request = Vec::new();
    Request::RequestIdentities.encode(&mut request).unwrap();
    let response = raw_roundtrip(&mut stream, &request)
        .expect("connection must remain open after an unknown request type");
    let mut rest = &response[..];
    let decoded = Response::decode(&mut rest).unwrap();
    assert!(matches!(decoded, Response::IdentitiesAnswer(_)));

    drop(stream);
    // The agent keeps accepting connections, so detach instead of joining.
    drop(handle);

    let _ = std::fs::remove_file(&socket_path);
}
