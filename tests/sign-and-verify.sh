#!/bin/bash

set -euxo pipefail

rm -rf ssh-agent.sock Cargo.toml.sig id_rsa id_rsa.pub agent.pub ca_user_key ca_user_key.pub id_rsa-cert.pub
RUST_LOG=info cargo run --example key_storage &

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

rm -rf Cargo.toml.sig agent.pub

# Test other commands:
export SSH_ASKPASS=`pwd`/tests/pwd-test.sh
# AddSmartcardKey
echo | ssh-add -s test
# AddSmartcardKeyConstrained
echo | ssh-add -c -t 4 -s test
# Lock
echo | ssh-add -x
# Unlock
echo | ssh-add -X
# AddIdConstrained
ssh-add -t 2 id_rsa

rm -rf id_rsa id_rsa.pub

# Create and sign SSH user certificate
# see: https://cottonlinux.com/ssh-certificates/
echo | ssh-keygen -f ca_user_key
ssh-keygen -t rsa -f id_rsa -N ""
echo | ssh-keygen -s ca_user_key -I darren -n darren -V +1h -z 1 id_rsa.pub
# Add the key with the cert
if [ $(ssh-add -h 2>&1 | grep -ic hostkey_file) -eq 1 ]; then
  # has support for RestrictDestination constraint (ubuntu)
  ssh-add -t 2 -H tests/known_hosts -h github.com id_rsa
else
  # does not support RestrictDestination constraint (macos)
  ssh-add -t 2 id_rsa
fi
  
# clean up the only leftover
rm -rf id_rsa id_rsa.pub id_rsa-cert.pub ca_user_key ca_user_key.pub
