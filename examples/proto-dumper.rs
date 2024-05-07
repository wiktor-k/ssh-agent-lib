//! This example illustrates a couple of features: First, it
//! implements a forwarder, exposing an SSH agent socket and
//! forwarding to a different one. Secondly it shows how to work with
//! low-level handling of messages instead of parsed high-level
//! structures.
//!
//! Run with
//! RUST_LOG=info cargo run --example proto-dumper -- --target unix://$SSH_AUTH_SOCK -H unix:///tmp/test.sock

use clap::Parser;
use service_binding::Binding;
use ssh_agent_lib::{
    agent::bind,
    agent::Agent,
    agent::Session,
    async_trait,
    client::connect,
    error::AgentError,
    proto::{Request, Response},
};
use ssh_encoding::Encode;

struct DumpAndForward {
    target: Box<dyn Session>,
    session: u64,
    id: u64,
}

#[async_trait]
impl Session for DumpAndForward {
    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        use std::io::Write;

        self.id += 1;
        let req_file = format!("req-{}-{}.bin", self.session, self.id);
        log::info!("Writing request {message:?} to {req_file}");

        let mut req = std::fs::File::create(req_file)?;
        let mut buf = vec![];
        message.encode(&mut buf).map_err(AgentError::other)?;
        req.write_all(&buf)?;
        drop(req);

        let response = self.target.handle(message).await?;

        let resp_file = format!("resp-{}-{}.bin", self.session, self.id);
        log::info!("Writing response {response:?} to {resp_file}");
        let mut resp = std::fs::File::create(resp_file)?;
        let mut buf = vec![];
        response.encode(&mut buf).map_err(AgentError::other)?;
        resp.write_all(&buf)?;
        drop(resp);

        Ok(response)
    }
}

struct Forwarder {
    target: Binding,
    id: u64,
}

#[cfg(unix)]
impl Agent<tokio::net::UnixListener> for Forwarder {
    fn new_session(&mut self, _socket: &tokio::net::UnixStream) -> impl Session {
        self.create_new_session()
    }
}

impl Agent<tokio::net::TcpListener> for Forwarder {
    fn new_session(&mut self, _socket: &tokio::net::TcpStream) -> impl Session {
        self.create_new_session()
    }
}

#[cfg(windows)]
impl Agent<ssh_agent_lib::agent::NamedPipeListener> for Forwarder {
    fn new_session(
        &mut self,
        _socket: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> impl Session {
        self.create_new_session()
    }
}

impl Forwarder {
    fn create_new_session(&mut self) -> impl Session {
        self.id += 1;
        DumpAndForward {
            target: connect(self.target.clone().try_into().unwrap()).unwrap(),
            session: self.id,
            id: 0,
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    /// Target SSH agent to which we will proxy all requests.
    #[clap(long)]
    target: Binding,

    /// Source that we will bind to.
    #[clap(long, short = 'H')]
    host: Binding,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    bind(
        args.host.try_into()?,
        Forwarder {
            target: args.target,
            id: 0,
        },
    )
    .await?;

    Ok(())
}
