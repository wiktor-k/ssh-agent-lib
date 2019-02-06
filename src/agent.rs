use tokio_uds::UnixListener;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use tokio::prelude::*;

use std::mem::size_of;

use super::proto::{from_bytes, to_bytes};
use super::proto::message::Message;
use super::proto::error::ProtoError;

use bytes::{BytesMut, BufMut};

use byteorder::{BigEndian, ReadBytesExt};

use tokio::codec::{Framed, Encoder, Decoder};

struct MessageCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = ProtoError;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut bytes = &src[..];
        
        if bytes.len() < size_of::<u32>() {
            return Ok(None);
        }
        
        let length = bytes.read_u32::<BigEndian>()? as usize;
        
        if bytes.len() < length {
            return Ok(None)
        }
        
        let message: Message = from_bytes(bytes)?;
        src.advance(size_of::<u32>() + length);
        Ok(Some(message))
    }
}

impl Encoder for MessageCodec {
    type Item = Message;
    type Error = ProtoError;
    
    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = to_bytes(&to_bytes(&item)?)?;
        dst.put(bytes);
        Ok(())
    }
}

macro_rules! handle_clients {
    ($socket:ident, $process:ident) => {
        $socket.incoming()
            .map_err(|e| error!("Failed to accept socket; error = {:?}", e))
            .for_each(move |socket| {
                let (write, read) = Framed::new(socket, MessageCodec).split();
                let connection = write.send_all(read.map($process))
                    .map(|_| ())
                    .map_err(|e| error!("Error while reading message; error = {:?}", e));
                tokio::spawn(connection)
            }).map_err(|e| e.into());
    };
}

pub fn start_unix<F>(path: &str, process: &'static F) -> Result<(), Box<std::error::Error>>
where
    F: Fn(Message) -> Message + Send + Sync
{
    let socket = UnixListener::bind(path)?;
    info!("Listening; socket = {:?}", socket);
    tokio::run(handle_clients!(socket, process));
    Ok(())
}

pub fn start_tcp<F>(addr: &str, process: &'static F) -> Result<(), Box<std::error::Error>>
where
    F: Fn(Message) -> Message + Send + Sync
{
    let socket = TcpListener::bind(&addr.parse::<SocketAddr>()?)?;
    info!("Listening; socket = {:?}", socket);
    tokio::run(handle_clients!(socket, process));
    Ok(())
}