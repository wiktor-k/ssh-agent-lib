# ssh-agent.rs

A collection of types for writing custom SSH agents.

This makes it possible to utilize remote keys not supported by the
default OpenSSH agent.

## Example

This example starts listening on a Unix socket `connect.sock` and
processes requests.

```rust,no_run
use ssh_agent::agent::Agent;
use ssh_agent::proto::message::{Message, SignRequest};

struct MyAgent;

impl Agent for MyAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
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

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let agent = MyAgent;
    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);

    agent.run_unix(socket)?;
    Ok(())
}
```

For more elaborate example see `examples` directory.

## Note

This library has been forked from
[sekey/ssh-agent.rs](https://github.com/sekey/ssh-agent.rs) as the
upstream seems not be maintained (at least as of 2022).
