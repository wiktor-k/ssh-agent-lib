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

#[async_trait]
pub trait ListeningSocket {
    type Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static;

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

#[cfg(windows)]
#[derive(Debug)]
pub struct NamedPipeListener(NamedPipeServer, std::ffi::OsString);

#[cfg(windows)]
impl NamedPipeListener {
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

#[async_trait]
pub trait Session: 'static + Sync + Send + Sized {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 11 }))
    }

    async fn sign(
        &mut self,
        _request: SignRequest,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 13 }))
    }

    async fn add_identity(
        &mut self,
        _identity: AddIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 17 }))
    }

    async fn add_identity_constrained(
        &mut self,
        _identity: AddIdentityConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 25 }))
    }

    async fn remove_identity(
        &mut self,
        _identity: RemoveIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 18 }))
    }

    async fn remove_all_identities(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 19 }))
    }

    async fn add_smartcard_key(
        &mut self,
        _key: SmartcardKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 20 }))
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        _key: AddSmartcardKeyConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 26 }))
    }

    async fn remove_smartcard_key(
        &mut self,
        _key: SmartcardKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 21 }))
    }

    async fn lock(&mut self, _key: String) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 22 }))
    }

    async fn unlock(&mut self, _key: String) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 23 }))
    }

    async fn extension(&mut self, _extension: Extension) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(ProtoError::UnsupportedCommand { command: 27 }))
    }

    async fn handle(&mut self, message: Request) -> Result<Response, Box<dyn std::error::Error>> {
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
            Request::Extension(extension) => self.extension(extension).await?,
        }
        Ok(Response::Success)
    }

    async fn handle_socket<S>(
        &mut self,
        mut adapter: Framed<S::Stream, Codec<Request, Response>>,
    ) -> Result<(), AgentError>
    where
        S: ListeningSocket + fmt::Debug + Send,
    {
        loop {
            if let Some(incoming_message) = adapter.try_next().await? {
                log::debug!("Request: {incoming_message:?}");
                let response = match self.handle(incoming_message).await {
                    Ok(message) => message,
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
}

#[async_trait]
pub trait Agent: 'static + Sync + Send + Sized {
    fn new_session(&mut self) -> impl Session;
    async fn listen<S>(mut self, mut socket: S) -> Result<(), AgentError>
    where
        S: ListeningSocket + fmt::Debug + Send,
    {
        log::info!("Listening; socket = {:?}", socket);
        loop {
            match socket.accept().await {
                Ok(socket) => {
                    let mut session = self.new_session();
                    tokio::spawn(async move {
                        let adapter = Framed::new(socket, Codec::<Request, Response>::default());
                        if let Err(e) = session.handle_socket::<S>(adapter).await {
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
    async fn bind(mut self, listener: service_binding::Listener) -> Result<(), AgentError> {
        match listener {
            #[cfg(unix)]
            service_binding::Listener::Unix(listener) => {
                self.listen(UnixListener::from_std(listener)?).await
            }
            service_binding::Listener::Tcp(listener) => {
                self.listen(TcpListener::from_std(listener)?).await
            }
            #[cfg(windows)]
            service_binding::Listener::NamedPipe(pipe) => {
                self.listen(NamedPipeListener::bind(pipe)?).await
            }
            #[cfg(not(windows))]
            service_binding::Listener::NamedPipe(_) => Err(AgentError::IO(std::io::Error::other(
                "Named pipes supported on Windows only",
            ))),
        }
    }
}

impl<T> Agent for T
where
    T: Default + Session,
{
    fn new_session(&mut self) -> impl Session {
        Self::default()
    }
}
