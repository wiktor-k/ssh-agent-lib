//! Traits for implementing custom SSH agents

use std::fmt;
use std::io;

use async_trait::async_trait;
use futures::{SinkExt, TryStreamExt};
use ssh_key::Signature;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

use super::error::AgentError;
use super::proto::message::{Request, Response};
use crate::codec::Codec;
use crate::proto::AddIdentity;
use crate::proto::AddIdentityConstrained;
use crate::proto::AddSmartcardKeyConstrained;
use crate::proto::Extension;
use crate::proto::Identity;
use crate::proto::ProtoError;
use crate::proto::RemoveIdentity;
use crate::proto::SignRequest;
use crate::proto::SmartcardKey;

/// Type representing a socket that asynchronously returns a list of streams.
#[async_trait]
pub trait ListeningSocket {
    /// Stream type that represents an accepted socket.
    type Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Waits until a client connects and returns connected stream.
    async fn accept(&mut self) -> io::Result<Self::Stream>;
}

#[cfg(unix)]
#[async_trait]
impl ListeningSocket for UnixListener {
    type Stream = UnixStream;
    async fn accept(&mut self) -> io::Result<Self::Stream> {
        UnixListener::accept(self).await.map(|(s, _addr)| s)
    }
}

#[async_trait]
impl ListeningSocket for TcpListener {
    type Stream = TcpStream;
    async fn accept(&mut self) -> io::Result<Self::Stream> {
        TcpListener::accept(self).await.map(|(s, _addr)| s)
    }
}

/// Listener for Windows Named Pipes.
#[cfg(windows)]
#[derive(Debug)]
pub struct NamedPipeListener(NamedPipeServer, std::ffi::OsString);

#[cfg(windows)]
impl NamedPipeListener {
    /// Bind to a pipe path.
    pub fn bind(pipe: impl Into<std::ffi::OsString>) -> std::io::Result<Self> {
        let pipe = pipe.into();
        Ok(NamedPipeListener(
            ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe)?,
            pipe,
        ))
    }
}

#[cfg(windows)]
#[async_trait]
impl ListeningSocket for NamedPipeListener {
    type Stream = NamedPipeServer;
    async fn accept(&mut self) -> io::Result<Self::Stream> {
        self.0.connect().await?;
        Ok(std::mem::replace(
            &mut self.0,
            ServerOptions::new().create(&self.1)?,
        ))
    }
}

/// Represents one active SSH connection.
///
/// This type is implemented by agents that want to handle incoming SSH agent
/// connections.
#[async_trait]
pub trait Session: 'static + Sync + Send + Unpin {
    /// Request a list of keys managed by this session.
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 11,
        }))
    }

    /// Perform a private key signature operation.
    async fn sign(&mut self, _request: SignRequest) -> Result<Signature, AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 13,
        }))
    }

    /// Add a private key to the agent.
    async fn add_identity(&mut self, _identity: AddIdentity) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 17,
        }))
    }

    /// Add a private key to the agent with a set of constraints.
    async fn add_identity_constrained(
        &mut self,
        _identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 25,
        }))
    }

    /// Remove private key from an agent.
    async fn remove_identity(&mut self, _identity: RemoveIdentity) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 18,
        }))
    }

    /// Remove all keys from an agent.
    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 19,
        }))
    }

    /// Add a key stored on a smartcard.
    async fn add_smartcard_key(&mut self, _key: SmartcardKey) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 20,
        }))
    }

    /// Add a key stored on a smartcard with a set of constraints.
    async fn add_smartcard_key_constrained(
        &mut self,
        _key: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 26,
        }))
    }

    /// Remove a smartcard key from the agent.
    async fn remove_smartcard_key(&mut self, _key: SmartcardKey) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 21,
        }))
    }

    /// Temporarily lock the agent with a password.
    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 22,
        }))
    }

    /// Unlock the agent with a password.
    async fn unlock(&mut self, _key: String) -> Result<(), AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 23,
        }))
    }

    /// Invoke a custom, vendor-specific extension on the agent.
    async fn extension(&mut self, _extension: Extension) -> Result<Option<Extension>, AgentError> {
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 27,
        }))
    }

    /// Handle a raw SSH agent request and return agent response.
    ///
    /// Note that it is preferable to use high-level functions instead of
    /// this function. This function should be overridden only for custom
    /// messages, outside of the SSH agent protocol specification.
    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        match message {
            Request::RequestIdentities => {
                return Ok(Response::IdentitiesAnswer(self.request_identities().await?))
            }
            Request::SignRequest(request) => {
                return Ok(Response::SignResponse(self.sign(request).await?))
            }
            Request::AddIdentity(identity) => self.add_identity(identity).await?,
            Request::RemoveIdentity(identity) => self.remove_identity(identity).await?,
            Request::RemoveAllIdentities => self.remove_all_identities().await?,
            Request::AddSmartcardKey(key) => self.add_smartcard_key(key).await?,
            Request::RemoveSmartcardKey(key) => self.remove_smartcard_key(key).await?,
            Request::Lock(key) => self.lock(key).await?,
            Request::Unlock(key) => self.unlock(key).await?,
            Request::AddIdConstrained(identity) => self.add_identity_constrained(identity).await?,
            Request::AddSmartcardKeyConstrained(key) => {
                self.add_smartcard_key_constrained(key).await?
            }
            Request::Extension(extension) => {
                return match self.extension(extension).await? {
                    Some(response) => Ok(Response::ExtensionResponse(response)),
                    None => Ok(Response::Success),
                }
            }
        }
        Ok(Response::Success)
    }
}

async fn handle_socket<S>(
    mut session: impl Session,
    mut adapter: Framed<S::Stream, Codec<Request, Response>>,
) -> Result<(), AgentError>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    loop {
        if let Some(incoming_message) = adapter.try_next().await? {
            log::debug!("Request: {incoming_message:?}");
            let response = match session.handle(incoming_message).await {
                Ok(message) => message,
                Err(AgentError::ExtensionFailure) => {
                    log::error!("Extension failure handling message");
                    Response::ExtensionFailure
                }
                Err(e) => {
                    log::error!("Error handling message: {:?}", e);
                    Response::Failure
                }
            };
            log::debug!("Response: {response:?}");

            adapter.send(response).await?;
        } else {
            // Reached EOF of the stream (client disconnected),
            // we can close the socket and exit the handler.
            return Ok(());
        }
    }
}

/// Factory of sessions for the given type of sockets.
pub trait Agent<S>: 'static + Send + Sync
where
    S: ListeningSocket + fmt::Debug + Send,
{
    /// Create a [`Session`] object for a given `socket`.
    fn new_session(&mut self, socket: &S::Stream) -> impl Session;
}

/// Listen for connections on a given socket and use session factory
/// to create new session for each accepted socket.
pub async fn listen<S>(mut socket: S, mut sf: impl Agent<S>) -> Result<(), AgentError>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    log::info!("Listening; socket = {:?}", socket);
    loop {
        match socket.accept().await {
            Ok(socket) => {
                let session = sf.new_session(&socket);
                tokio::spawn(async move {
                    let adapter = Framed::new(socket, Codec::<Request, Response>::default());
                    if let Err(e) = handle_socket::<S>(session, adapter).await {
                        log::error!("Agent protocol error: {:?}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("Failed to accept socket: {:?}", e);
                return Err(AgentError::IO(e));
            }
        }
    }
}

#[cfg(unix)]
impl<T> Agent<tokio::net::UnixListener> for T
where
    T: Default + Send + Sync + Session,
{
    fn new_session(&mut self, _socket: &tokio::net::UnixStream) -> impl Session {
        Self::default()
    }
}

impl<T> Agent<tokio::net::TcpListener> for T
where
    T: Default + Send + Sync + Session,
{
    fn new_session(&mut self, _socket: &tokio::net::TcpStream) -> impl Session {
        Self::default()
    }
}

#[cfg(windows)]
impl<T> Agent<NamedPipeListener> for T
where
    T: Default + Send + Sync + Session,
{
    fn new_session(
        &mut self,
        _socket: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> impl Session {
        Self::default()
    }
}

/// Bind to a service binding listener.
#[cfg(unix)]
pub async fn bind<SF>(listener: service_binding::Listener, sf: SF) -> Result<(), AgentError>
where
    SF: Agent<tokio::net::UnixListener> + Agent<tokio::net::TcpListener>,
{
    match listener {
        #[cfg(unix)]
        service_binding::Listener::Unix(listener) => {
            listen(UnixListener::from_std(listener)?, sf).await
        }
        service_binding::Listener::Tcp(listener) => {
            listen(TcpListener::from_std(listener)?, sf).await
        }
        _ => Err(AgentError::IO(std::io::Error::other(
            "Unsupported type of a listener.",
        ))),
    }
}

/// Bind to a service binding listener.
#[cfg(windows)]
pub async fn bind<SF>(listener: service_binding::Listener, sf: SF) -> Result<(), AgentError>
where
    SF: Agent<NamedPipeListener> + Agent<tokio::net::TcpListener>,
{
    match listener {
        service_binding::Listener::Tcp(listener) => {
            listen(TcpListener::from_std(listener)?, sf).await
        }
        service_binding::Listener::NamedPipe(pipe) => {
            listen(NamedPipeListener::bind(pipe)?, sf).await
        }
    }
}
