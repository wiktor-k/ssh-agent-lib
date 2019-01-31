//#![deny(warnings)]

extern crate tokio;

use tokio::io;
use tokio::net::TcpListener;
use tokio::prelude::*;

use std::net::SocketAddr;
use std::mem::size_of;

use futures::future;

use byteorder::{BigEndian, ReadBytesExt};

use tokio_uds::*;

use ssh_agent::proto::deserialize::from_bytes;
use ssh_agent::proto::{Message, Blob, Identity};

fn process(request: &Message) -> Option<Message> {
    match request {
        Message::RequestIdentities => {
            let identity = Identity {
                key_blob: b"key_blob".to_vec(),
                comment: "some comment".to_string()
            };
            Some(Message::IdentitiesAnswer(vec![identity]))
        },
        _ => Some(Message::Failure)
    }
}

fn main() -> Result<(), Box<std::error::Error>> {
    let addr = "127.0.0.1:8080".parse::<SocketAddr>()?;
    
    let socket = UnixListener::bind("connect.sock")?;
    println!("Listening on: {}", addr);
    
    let done = socket.incoming()
        .map_err(|e| println!("failed to accept socket; error = {:?}", e))
        .for_each(move |socket| {
            let receive = future::loop_fn(socket, |socket| {
                let size_buffer: Vec<u8> = vec![0; size_of::<u32>()];
                io::read_exact(socket, size_buffer)
                    .and_then(|(socket, size_buffer)| {
                        let size = size_buffer.as_slice().read_u32::<BigEndian>().unwrap();
                        let message_buffer: Vec<u8> = vec![0; size as usize];
                        io::read_exact(socket, message_buffer)
                    })
                    .map_err(|e| println!("error reading; error = {:?}", e))
                    .and_then(|(socket, request_buffer)| {
                        if request_buffer.len() > 0 {
                            let request: Message = from_bytes(&request_buffer).unwrap();
                            let response = process(&request);
                            println!("Request: {:?}", request);
                            println!("Response: {:?}", response);
                            if let Some(response) = response {
                                let response_blob = response.to_blob().unwrap();
                                let response_buffer = response_blob.to_blob().unwrap();
                                let send = io::write_all(socket, response_buffer)
                                    .map_err(|e| println!("error sending; error = {:?}", e))
                                    .map(|(socket, _)| socket);
                                return future::Either::B(send);
                            }
                        }
                        return future::Either::A(future::ok(socket));
                    })
                    .map(future::Loop::Continue)
            });
            tokio::spawn(receive)
        });

    tokio::run(done);
    Ok(())
}