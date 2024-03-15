use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, TryStreamExt};
use log::{error, info};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_util::codec::{Decoder, Encoder, Framed};

use std::fmt;
use std::io;
use std::marker::Unpin;
use std::mem::size_of;

use super::error::AgentError;
use super::proto::message::Message;
use super::proto::{from_bytes, to_bytes};

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

        let message: Message = from_bytes(bytes)?;
        src.advance(size_of::<u32>() + length);
        Ok(Some(message))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = AgentError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = to_bytes(&to_bytes(&item)?)?;
        dst.put(&*bytes);
        Ok(())
    }
}

#[async_trait]
pub trait ListeningSocket {
    type Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static;

    async fn accept(&self) -> io::Result<Self::Stream>;
}

#[async_trait]
impl ListeningSocket for UnixListener {
    type Stream = UnixStream;
    async fn accept(&self) -> io::Result<Self::Stream> {
        UnixListener::accept(self).await.map(|(s, _addr)| s)
    }
}

#[async_trait]
impl ListeningSocket for TcpListener {
    type Stream = TcpStream;
    async fn accept(&self) -> io::Result<Self::Stream> {
        TcpListener::accept(self).await.map(|(s, _addr)| s)
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
                let response = match self.handle(incoming_message).await {
                    Ok(message) => message,
                    Err(e) => {
                        error!("Error handling message: {:?}", e);
                        Message::Failure
                    }
                };

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
    async fn listen<S>(mut self, socket: S) -> Result<(), AgentError>
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
}

impl<T> Agent for T
where
    T: Default + Session,
{
    fn new_session(&mut self) -> impl Session {
        Self::default()
    }
}
