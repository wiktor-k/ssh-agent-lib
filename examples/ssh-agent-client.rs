use service_binding::Binding;
use ssh_agent_lib::client::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let mut client =
        connect(Binding::FilePath(std::env::var("SSH_AUTH_SOCK")?.into()).try_into()?)?;

    #[cfg(windows)]
    let mut client =
        connect(Binding::NamedPipe(std::env::var("SSH_AUTH_SOCK")?.into()).try_into()?)?;

    eprintln!(
        "Identities that this agent knows of: {:#?}",
        client.request_identities().await?
    );

    Ok(())
}
