# Agent examples

The examples in this directory show slightly more elaborate use-cases that can be implemented using this crate.

## Agents

### `key-storage`

Implements a simple agent which remembers RSA private keys (added via `ssh-add`) and allows fetching their public keys and signing using three different signing mechanisms.

This example additionally shows how to extract extensions from messages and works on all major OSes.

It is used in integration tests that run as part of the CI.

### `openpgp-card-agent`

Allows using OpenPGP Card devices to sign SSH requests.
The PIN is stored in memory and can be time-constrained using SSH constraints.
For the sake of simplicity this agent supports only `ed25519` subkeys.

This example additionally shows how to create custom protocol based on SSH extensions (in this case decrypt/derive feature).

### `agent-socket-info`

Shows how to extract information about the underlying connection.
For example under Unix systems this displays connecting process PID.
To keep the example brief the data is printed as part of a fake public key comment.

## Clients

### `pgp-wrapper`

Wraps SSH keys in OpenPGP data thus allowing OpenPGP applications (such as GnuPG) to read and work with SSH keys.
This makes it possible to create OpenPGP signatures utilizing SSH keys.

If the connecting agent supports derive/decrypt extension this example additionally creates a decryption subkey and can be used to decrypt OpenPGP data.

### `proto-dumper`

A simple forwarding example which works as an agent and client at the same time dumping all messages and forwarding them to the next agent.

### `ssh-agent-client`

Dumps identities stored by the agent.
Additionally invokes an extension and reads the result.

### `ssh-agent-client-blocking`

Dumps identities stored by the agent using blocking (synchronous) API.
