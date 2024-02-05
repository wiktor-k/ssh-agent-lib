use byteorder::{BigEndian, ReadBytesExt};
use bytes::BytesMut;
use log::{error, info};
use tokio::net::TcpListener;
use tokio::net::UnixListener;
use tokio_util::codec::{Decoder, Encoder, Framed};

use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::mem::size_of;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Buf;
use bytes::BufMut;
use futures::SinkExt;
use futures::StreamExt;
use futures::TryFutureExt;
use futures::TryStreamExt;

use super::error::AgentError;
use super::proto::message::Message;
use super::proto::{from_bytes, to_bytes};

struct MessageCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, Self::Error> {
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
        dst.put(&bytes[..]);
        Ok(())
    }
}

macro_rules! handle_clients {
    ($self:ident, $wrapper:ident, $socket:ident) => {{
        use futures::FutureExt;
        use futures::TryFutureExt;
        info!("Listening; socket = {:?}", $socket);
        let arc_self = Arc::new(Mutex::new($self));
        tokio_stream::wrappers::$wrapper::new($socket)
            .map_err(|e| error!("Failed to accept socket; error = {:?}", e))
            .for_each(move |socket| {
                let socket = socket.unwrap(); //FIXME
                let (mut write, read) = Framed::new(socket, MessageCodec).split();
                let arc_self = Arc::clone(&arc_self);
                let arc_self = arc_self.lock().unwrap();
                let connection = write.send_all(&mut std::pin::pin!(read.and_then(|message| {
                    arc_self.handle_async(message).map_err(move |e| {
                        error!("Error handling message; error = {:?}", e);
                        AgentError::User
                    })
                })));
                //.map(move |_| ())
                //.map_err(|e| error!("Error while handling message; error = {:?}", e));
                tokio::task::spawn_local(connection).map(move |_| ())
                //async { tokio::task::spawn_local(connection); }
            })
        //.map_err(|e| e.into())
    }};
}

pub trait Agent: 'static + Sync + Send + Sized {
    type Error: Debug + Send + Sync;

    fn handle(&self, message: Message) -> Result<Message, Self::Error>;

    async fn handle_async(&self, message: Message) -> Result<Message, Self::Error> {
        self.handle(message)
    }

    #[allow(clippy::unit_arg)]
    fn run_listener(self, socket: UnixListener) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(handle_clients!(self, UnixListenerStream, socket));
        Ok(res)
    }

    fn run_unix(self, path: impl AsRef<Path>) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.run_listener(UnixListener::bind(path)?)
    }

    #[allow(clippy::unit_arg)]
    fn run_tcp(self, addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(async {
            let socket = TcpListener::bind(&addr.parse::<SocketAddr>().unwrap())
                .await
                .unwrap(); // FIXMEx2
            handle_clients!(self, TcpListenerStream, socket);
        });
        Ok(res)
    }
}
