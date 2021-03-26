use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BytesMut, BufMut, Buf};
use futures::{SinkExt, StreamExt, future::Future};

use log::{error, info};

use tokio_util::codec::{Framed, Encoder, Decoder};
use tokio::net::{TcpListener, UnixListener};

use std::{error::Error};
use std::fmt::Debug;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;
use std::net::SocketAddr;

use super::error::AgentError;
use super::proto::message::Message;
use super::proto::{from_bytes, to_bytes};

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

impl Encoder<Message> for MessageCodec {
    type Error = AgentError;
    
    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = to_bytes(&to_bytes(&item)?)?;
        dst.put(bytes.as_slice());
        Ok(())
    }
}

macro_rules! handle_clients {
    ($arc_self:ident, $listener:ident) => {{
        loop {
            let (socket, socket_addr) = $listener.accept().await?;
            let arc_self = $arc_self.clone();
            tokio::spawn(async move {
                info!("New connection; addr = {:?}", socket_addr);
                let (mut sink, mut stream) = Framed::new(socket, MessageCodec).split();
                while let Some(message_result) = stream.next().await {
                    if let Ok(message) = message_result {
                        let result = arc_self.handle_async(message).await;
                        if let Ok(result) = result {
                            let _ = sink.send(result).await;
                        } else if let Err(e) = result {
                            error!("Error while handling message; error = {:?}", e);
                        }
                    } else if let Err(e) = message_result {
                        error!("Error while decoding message; error = {:?}", e);
                    }
                }
            });
        }
    }};
}

pub trait Agent: 'static + Sync + Send + Sized {
    type Error: Debug + Send + Sync;
    
    fn handle(&self, message: Message) -> Result<Message, Self::Error>;
    
    fn handle_async(
        &self,
        message: Message
    ) -> Box<dyn Future<Output = Result<Message, Self::Error>> + Send + Sync + Unpin> {
        Box::new(futures::future::ready(self.handle(message)))
    }
    
    fn run_unix(self, path: impl AsRef<Path>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build()?;
        let arc_self = Arc::new(self);
        runtime.block_on(async {
            let listener = UnixListener::bind(path)?;
            handle_clients!(arc_self, listener);
        })
    }

    fn run_tcp(self, addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build()?;
        let arc_self = Arc::new(self);
        runtime.block_on(async {
            let listener = TcpListener::bind(&addr.parse::<SocketAddr>()?).await?;
            handle_clients!(arc_self, listener);
        })
    }
}
