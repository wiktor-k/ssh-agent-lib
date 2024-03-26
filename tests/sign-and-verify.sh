#!/bin/bash

set -euxo pipefail

rm -rf ssh-agent.sock Cargo.toml.sig id_rsa id_rsa.pub agent.pub

cargo run --example key_storage &

while [ ! -e ssh-agent.sock ]; do
  echo "Waiting for ssh-agent.sock"
  sleep 1
done

ssh-keygen -t rsa -f id_rsa -N ""
export SSH_AUTH_SOCK=ssh-agent.sock
ssh-add id_rsa
ssh-add -L | tee agent.pub
ssh-keygen -Y sign -f agent.pub -n file < Cargo.toml > Cargo.toml.sig
ssh-keygen -Y check-novalidate -n file -f agent.pub -s Cargo.toml.sig < Cargo.toml

rm -rf ssh-agent.sock Cargo.toml.sig id_rsa id_rsa.pub agent.pub

