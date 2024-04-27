//! Traits for SSH agent sockets

use std::fmt;
use std::io;
use std::net;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{unix::SocketAddr as UnixSocketAddr, unix::UCred, UnixListener, UnixStream};
use tokio::net::{TcpListener, TcpStream};
#[cfg(windows)]
use windows::{
    Win32::Foundation::HANDLE,
    Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId},
};

/// Type representing a socket that asynchronously returns a list of streams.
#[async_trait]
pub trait ListeningSocket {
    /// Stream type that represents an accepted socket.
    type Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Type that represents a client to an accepted socket.
    type ClientInfo: fmt::Debug + Send + Unpin + 'static;

    /// Waits until a client connects and returns connected stream.
    async fn accept(&mut self) -> io::Result<Self::Stream>;

    /// Given an accepted socket, return platform-specific
    /// information about the client
    fn client_info(stream: &Self::Stream) -> io::Result<Self::ClientInfo>;
}

/// Type representing a client to a Unix Socket
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixClientInfo {
    /// The socket address of the remote half of this connection.
    pub socket_addr: UnixSocketAddr,

    /// Effective credentials of the process which connected
    /// to the socket
    pub credentials: UCred,
}

#[cfg(unix)]
#[async_trait]
impl ListeningSocket for UnixListener {
    type Stream = UnixStream;
    type ClientInfo = UnixClientInfo;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        UnixListener::accept(self).await.map(|(s, _addr)| s)
    }

    fn client_info(stream: &Self::Stream) -> io::Result<Self::ClientInfo> {
        Ok(UnixClientInfo {
            socket_addr: stream.peer_addr()?,
            credentials: stream.peer_cred()?,
        })
    }
}

/// Type representing a client to a TCP socket
#[derive(Debug)]
pub struct TcpClientInfo(pub net::SocketAddr);

#[async_trait]
impl ListeningSocket for TcpListener {
    type Stream = TcpStream;
    type ClientInfo = TcpClientInfo;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        TcpListener::accept(self).await.map(|(s, _addr)| s)
    }

    fn client_info(stream: &Self::Stream) -> io::Result<Self::ClientInfo> {
        Ok(TcpClientInfo(stream.peer_addr()?))
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

/// Type representing a client to a Named Pipe
#[cfg(windows)]
#[derive(Debug)]
pub struct NamedPipeClientInfo {
    /// The client process identifier for the named pipe.
    pub pid: u32,

    /// the client session identifier for the named pipe.
    pub session_id: u32,
}

#[cfg(windows)]
#[async_trait]
impl ListeningSocket for NamedPipeListener {
    type Stream = NamedPipeServer;
    type ClientInfo = NamedPipeClientInfo;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        self.0.connect().await?;
        Ok(std::mem::replace(
            &mut self.0,
            ServerOptions::new().create(&self.1)?,
        ))
    }

    fn client_info(stream: &Self::Stream) -> io::Result<Self::ClientInfo> {
        let mut pid: u32 = Default::default();
        let mut session_id: u32 = Default::default();

        // SAFETY: This handle must be created by the CreateNamedPipe function.
        // [`NamedPipeServer`]s are created with [`CreateNamedPipeW`] [1],
        // and return `Err` if the handle is invalid [2]
        //
        // References:
        // 1. https://docs.rs/tokio/latest/src/tokio/net/windows/named_pipe.rs.html#2345
        // 2. https://docs.rs/tokio/latest/src/tokio/net/windows/named_pipe.rs.html#2356
        unsafe {
            GetNamedPipeClientProcessId(HANDLE(stream.as_raw_handle() as isize), &mut pid)?;
            GetNamedPipeClientSessionId(HANDLE(stream.as_raw_handle() as isize), &mut session_id)?;
        }

        Ok(NamedPipeClientInfo { pid, session_id })
    }
}
