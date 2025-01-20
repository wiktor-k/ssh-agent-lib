# Agent examples

The examples in this directory show slightly more elaborate use-cases that can be implemented using this crate.

## Agents

### `random-key`

Generates a new random key and supports only the basic operations used by the OpenSSH client: retrieving supported public keys (`request_identities`) and signing using the ephemeral key (`sign_request`).

### `key-storage`

Implements a simple agent which remembers RSA private keys (added via `ssh-add`) and allows fetching their public keys and signing using three different signing mechanisms.

This example additionally shows how to extract extensions from messages and works on all major OSes.

It is used in integration tests that run as part of the CI.

### `agent-socket-info`

Shows how to extract information about the underlying connection.
For example under Unix systems this displays connecting process PID.
To keep the example brief the data is printed as part of a fake public key comment.

## Clients

### `proto-dumper`

A simple forwarding example which works as an agent and client at the same time dumping all messages and forwarding them to the next agent.

### `ssh-agent-client`

Dumps identities stored by the agent.
Additionally invokes an extension and reads the result.

### `ssh-agent-client-blocking`

Dumps identities stored by the agent using blocking (synchronous) API.
