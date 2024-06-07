mod extensions;

#[cfg(unix)]
fn main() -> testresult::TestResult {
    use std::os::unix::net::UnixStream;

    use extensions::{DecryptIdentities, RequestDecryptIdentities};
    use ssh_agent_lib::{blocking::Client, proto::Extension};

    let mut client = Client::new(UnixStream::connect(std::env::var("SSH_AUTH_SOCK")?)?);

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

#[cfg(windows)]
fn main() {
    eprintln!("Sadly, there are no high-quality sync named pipe crates as of 2024");
}
