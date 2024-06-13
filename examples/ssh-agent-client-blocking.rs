mod extensions;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use extensions::{DecryptIdentities, RequestDecryptIdentities};
#[cfg(windows)]
use interprocess::os::windows::named_pipe::*;
use ssh_agent_lib::{blocking::Client, proto::Extension};

fn main() -> testresult::TestResult {
    let socket = std::env::var("SSH_AUTH_SOCK")?;
    #[cfg(unix)]
    let mut client = Client::new(UnixStream::connect(socket)?);
    #[cfg(windows)]
    let mut client = Client::new(DuplexPipeStream::<pipe_mode::Bytes>::connect_by_path(
        socket,
    )?);

    eprintln!(
        "Identities that this agent knows of: {:#?}",
        client.request_identities()?
    );

    if let Ok(Some(identities)) =
        client.extension(Extension::new_message(RequestDecryptIdentities)?)
    {
        let identities = identities.parse_message::<DecryptIdentities>()?;
        eprintln!("Decrypt identities that this agent knows of: {identities:#?}",);
    } else {
        eprintln!("No decryption identities found.");
    }

    Ok(())
}
