use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use futures::{SinkExt, TryStreamExt};
use log::{error, info};
use ssh_encoding::{Decode, Encode};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};

use std::fmt;
use std::io;
use std::marker::Unpin;
use std::mem::size_of;

use super::error::AgentError;
use super::proto::message::Message;

#[derive(Debug)]
pub struct MessageCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut bytes = &src[..];

        if bytes.len() < size_of::<u32>() {
            return Ok(None);
        }

        let length = bytes.read_u32::<BigEndian>()? as usize;

        if bytes.len() < length {
            return Ok(None);
        }

        let message: Message = Message::decode(&mut bytes)?;
        src.advance(size_of::<u32>() + length);
        Ok(Some(message))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = AgentError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut bytes = Vec::new();

        let len = item.encoded_len().unwrap() as u32;
        len.encode(&mut bytes)?;

        item.encode(&mut bytes)?;

        dst.put(&*bytes);
        Ok(())
    }
}

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
    pub fn new(pipe: std::ffi::OsString) -> std::io::Result<Self> {
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
    async fn handle(&mut self, message: Message) -> Result<Message, Box<dyn std::error::Error>>;

    async fn handle_socket<S>(
        &mut self,
        mut adapter: Framed<S::Stream, MessageCodec>,
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
                        error!("Error handling message: {:?}", e);
                        Message::Failure
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
        info!("Listening; socket = {:?}", socket);
        loop {
            match socket.accept().await {
                Ok(socket) => {
                    let mut session = self.new_session();
                    tokio::spawn(async move {
                        let adapter = Framed::new(socket, MessageCodec);
                        if let Err(e) = session.handle_socket::<S>(adapter).await {
                            error!("Agent protocol error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept socket: {:?}", e);
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
                self.listen(NamedPipeListener::new(pipe)?).await
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
