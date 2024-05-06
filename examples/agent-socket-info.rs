//! This example shows how to access the underlying socket info.
//! The socket info can be used to implement fine-grained access controls based on UID/GID.
//!
//! Run the example with: `cargo run --example agent-socket-info -- -H unix:///tmp/sock`
//! Then inspect the socket info with: `SSH_AUTH_SOCK=/tmp/sock ssh-add -L` which should display
//! something like this:
//!
//! ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA unix: addr: (unnamed) cred: UCred { pid: Some(68463), uid: 1000, gid: 1000 }

use clap::Parser;
use service_binding::Binding;
use ssh_agent_lib::{
    agent::{bind, Agent, Session},
    error::AgentError,
    proto::Identity,
};
use ssh_key::public::KeyData;
use testresult::TestResult;

#[derive(Debug, Default)]
struct AgentSocketInfo {
    comment: String,
}

#[ssh_agent_lib::async_trait]
impl Session for AgentSocketInfo {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(vec![Identity {
            // this is just a dummy key, the comment is important
            pubkey: KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([0; 32])),
            comment: self.comment.clone(),
        }])
    }
}

#[cfg(unix)]
impl Agent<tokio::net::UnixListener> for AgentSocketInfo {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        Self {
            comment: format!(
                "unix: addr: {:?} cred: {:?}",
                socket.peer_addr().unwrap(),
                socket.peer_cred().unwrap()
            ),
        }
    }
}

impl Agent<tokio::net::TcpListener> for AgentSocketInfo {
    fn new_session(&mut self, _socket: &tokio::net::TcpStream) -> impl Session {
        Self {
            comment: "tcp".into(),
        }
    }
}

#[cfg(windows)]
impl Agent<ssh_agent_lib::agent::NamedPipeListener> for AgentSocketInfo {
    fn new_session(
        &mut self,
        _socket: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> impl Session {
        Self {
            comment: "pipe".into(),
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short = 'H', long)]
    host: Binding,
}

#[tokio::main]
async fn main() -> TestResult {
    env_logger::init();

    let args = Args::parse();
    bind(args.host.try_into()?, AgentSocketInfo::default()).await?;
    Ok(())
}
