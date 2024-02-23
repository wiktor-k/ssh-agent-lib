# ssh-agent-lib

A collection of types for writing custom SSH agents.

This makes it possible to utilize remote keys not supported by the
default OpenSSH agent.

## Example

This example starts listening on a Unix socket `connect.sock` and
processes requests.

```rust,no_run
use async_trait::async_trait;
use tokio::net::UnixListener;

use ssh_agent_lib::agent::{Session, Agent};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::{Message, SignRequest};

#[derive(Default)]
struct MyAgent;

#[async_trait]
impl Session for MyAgent {
    async fn handle(&mut self, message: Message) -> Result<Message, AgentError> {
        match message {
            Message::SignRequest(request) => {
                // get the signature by signing `request.data`
                let signature = vec![];
                Ok(Message::SignResponse(signature))
            },
            _ => Ok(Message::Failure),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let agent = MyAgent;
    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);
    let socket = UnixListener::bind(socket)?;

    agent.listen(socket).await?;
    Ok(())
}
```

For more elaborate example see `examples` directory.

## Note

This library has been forked from
[sekey/ssh-agent.rs](https://github.com/sekey/ssh-agent.rs) as the
upstream seems not be maintained (at least as of 2022).

# License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you shall be licensed as above, without any additional terms or conditions.
