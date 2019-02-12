use tokio_uds::UnixListener;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use tokio::prelude::*;

use std::error::Error;
use std::fmt::Debug;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;

use super::proto::{from_bytes, to_bytes};
use super::proto::message::Message;
use super::error::AgentError;

use bytes::{BytesMut, BufMut};

use byteorder::{BigEndian, ReadBytesExt};

use tokio::codec::{Framed, Encoder, Decoder};

use futures::future::FutureResult;

struct MessageCodec;

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

impl Encoder for MessageCodec {
    type Item = Message;
    type Error = AgentError;
    
    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = to_bytes(&to_bytes(&item)?)?;
        dst.put(bytes);
        Ok(())
    }
}

macro_rules! handle_clients {
    ($self:ident, $socket:ident) => {{
        info!("Listening; socket = {:?}", $socket);
        let arc_self = Arc::new($self);
        $socket.incoming()
            .map_err(|e| error!("Failed to accept socket; error = {:?}", e))
            .for_each(move |socket| {
                let (write, read) = Framed::new(socket, MessageCodec).split();
                let arc_self = arc_self.clone();
                let connection = write.send_all(read.and_then(move |message| {
                    arc_self.handle_async(message).map_err(|e| {
                        error!("Error handling message; error = {:?}", e);
                        AgentError::User
                    })
                })).map(|_| ())
                   .map_err(|e| error!("Error while handling message; error = {:?}", e));
                tokio::spawn(connection)
            }).map_err(|e| e.into())
    }};
}

pub trait Agent: 'static + Sync + Send + Sized {
    type Error: Debug + Send + Sync;
    
    fn handle(&self, message: Message) -> Result<Message, Self::Error>;
    
    fn handle_async(
        &self,
        message: Message
    ) -> Box<Future<Item = Message, Error = Self::Error> + Send + Sync> {
        Box::new(FutureResult::from(self.handle(message)))
    }
    
    fn run_unix(self, path: impl AsRef<Path>) -> Result<(), Box<Error>> {
        let socket = UnixListener::bind(path)?;
        Ok(tokio::run(handle_clients!(self, socket)))
    }

    fn run_tcp(self, addr: &str) -> Result<(), Box<Error>> {
        let socket = TcpListener::bind(&addr.parse::<SocketAddr>()?)?;
        Ok(tokio::run(handle_clients!(self, socket)))
    }
}
