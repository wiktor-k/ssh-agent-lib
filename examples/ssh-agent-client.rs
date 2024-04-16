use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;
#[cfg(unix)]
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let mut client = {
        let stream = UnixStream::connect(std::env::var("SSH_AUTH_SOCK")?).await?;
        Client::new(stream)
    };
    #[cfg(windows)]
    let mut client = {
        let stream = loop {
            // https://docs.rs/windows-sys/latest/windows_sys/Win32/Foundation/constant.ERROR_PIPE_BUSY.html
            const ERROR_PIPE_BUSY: u32 = 231u32;

            // correct way to do it taken from
            // https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/struct.NamedPipeClient.html
            match ClientOptions::new().open(std::env::var("SSH_AUTH_SOCK")?) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => (),
                Err(e) => Err(e)?,
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        Client::new(stream)
    };

    eprintln!(
        "Identities that this agent knows of: {:#?}",
        client.request_identities().await?
    );

    Ok(())
}
