use tokio::io;
//use tokio::net::TcpListener;
use tokio_uds::UnixListener;
use tokio::prelude::*;

use std::mem::size_of;

use futures::future::{self, Loop, Either};

use byteorder::{BigEndian, ReadBytesExt};

use ssh_agent::proto::{from_bytes, to_bytes};
use ssh_agent::proto::message::{Message, Identity};
use ssh_agent::proto::error::ProtoResult;

use serde::{Serialize, Deserialize};

struct Response<T> {
    content: T,
    close: bool
}

impl<'de, T: Serialize + Deserialize<'de>> Response<T> {
    fn new(content: T, close: bool) -> Self {
        Self {
            content: content,
            close: close
        }
    }
    
    fn close(content: T) -> Self {
        Self::new(content, true)
    }
    
    fn ok(content: T) -> Self {
        Self::new(content, false)
    }
    
    fn encode(&self) -> ProtoResult<Response<Vec<u8>>> {
        to_bytes(&self.content).and_then(|v| to_bytes(&v))
                               .map(|v| Response::new(v, self.close))
    }
}

fn process(request: &Message) -> Response<Message> {
    match request {
        Message::RequestIdentities => {
            let identity = Identity {
                key_blob: b"key_blob".to_vec(),
                comment: "some comment".to_string()
            };
            Response::ok(Message::IdentitiesAnswer(vec![identity]))
        },
        _ => Response::close(Message::Failure)
    }
}

fn main() -> Result<(), Box<std::error::Error>> {
    let path = "connect.sock";
    let socket = UnixListener::bind(path)?;
    println!("Listening on: {}", path);
    
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
                            let request = from_bytes(&request_buffer);
                            let response = request.map(|r| process(&r))
                                                  .and_then(|r| r.encode());
                            if let Result::Err(_) = response {
                                return Either::A(Err(()).into());
                            }
                            let response = response.unwrap();
                            let close = response.close;
                            let content = response.content;
                            return Either::B(
                                io::write_all(socket, content)
                                    .map_err(|e| println!("error sending; error = {:?}", e))
                                    .map(move |(socket, _)| {
                                        if close {
                                            Loop::Break(())
                                        } else {
                                            Loop::Continue(socket)
                                        }
                                    })
                            )
                        }
                        return Either::A(future::ok(Loop::Continue(socket)));
                    })
                    .map_err(|e| println!("error reading; error = {:?}", e))
            });
            tokio::spawn(receive)
        });

    tokio::run(done);
    Ok(())
}