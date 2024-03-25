use async_trait::async_trait;
use log::info;
#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener;
#[cfg(not(windows))]
use tokio::net::UnixListener;

use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::proto::message::{self, Message, SignRequest};
use ssh_agent_lib::proto::private_key::PrivateKey;
use ssh_agent_lib::proto::public_key::PublicKey;
use ssh_agent_lib::proto::signature::{self, Signature};
use ssh_agent_lib::proto::{from_bytes, to_bytes};

use std::error::Error;
use std::sync::{Arc, Mutex};

use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::BigUint;
use sha1::Sha1;

#[derive(Clone, PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
}

struct KeyStorage {
    identities: Arc<Mutex<Vec<Identity>>>,
}

impl KeyStorage {
    fn identity_index_from_pubkey(identities: &Vec<Identity>, pubkey: &PublicKey) -> Option<usize> {
        for (index, identity) in identities.iter().enumerate() {
            if &identity.pubkey == pubkey {
                return Some(index);
            }
        }
        None
    }

    fn identity_from_pubkey(&self, pubkey: &PublicKey) -> Option<Identity> {
        let identities = self.identities.lock().unwrap();

        let index = Self::identity_index_from_pubkey(&identities, pubkey)?;
        Some(identities[index].clone())
    }

    fn identity_add(&self, identity: Identity) {
        let mut identities = self.identities.lock().unwrap();
        if Self::identity_index_from_pubkey(&identities, &identity.pubkey).is_none() {
            identities.push(identity);
        }
    }

    fn identity_remove(&self, pubkey: &PublicKey) -> Result<(), Box<dyn Error>> {
        let mut identities = self.identities.lock().unwrap();

        if let Some(index) = Self::identity_index_from_pubkey(&identities, pubkey) {
            identities.remove(index);
            Ok(())
        } else {
            Err(From::from("Failed to remove identity: identity not found"))
        }
    }

    fn sign(&self, sign_request: &SignRequest) -> Result<Signature, Box<dyn Error>> {
        let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob)?;

        if let Some(identity) = self.identity_from_pubkey(&pubkey) {
            match identity.privkey {
                PrivateKey::Rsa(ref key) => {
                    let algorithm;

                    let private_key = rsa::RsaPrivateKey::from_components(
                        BigUint::from_bytes_be(&key.n),
                        BigUint::from_bytes_be(&key.e),
                        BigUint::from_bytes_be(&key.d),
                        vec![
                            BigUint::from_bytes_be(&key.p),
                            BigUint::from_bytes_be(&key.q),
                        ],
                    )?;
                    let mut rng = rand::thread_rng();
                    let data = &sign_request.data;

                    let signature = if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                        algorithm = "rsa-sha2-512";
                        SigningKey::<Sha512>::new(private_key).sign_with_rng(&mut rng, data)
                    } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                        algorithm = "rsa-sha2-256";
                        SigningKey::<Sha256>::new(private_key).sign_with_rng(&mut rng, data)
                    } else {
                        algorithm = "ssh-rsa";
                        SigningKey::<Sha1>::new(private_key).sign_with_rng(&mut rng, data)
                    };

                    Ok(Signature {
                        algorithm: algorithm.to_string(),
                        blob: signature.to_bytes().to_vec(),
                    })
                }
                _ => Err(From::from("Signature for key type not implemented")),
            }
        } else {
            Err(From::from("Failed to create signature: identity not found"))
        }
    }

    fn handle_message(&self, request: Message) -> Result<Message, Box<dyn Error>> {
        info!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in self.identities.lock().unwrap().iter() {
                    identities.push(message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey)?,
                        comment: identity.comment.clone(),
                    })
                }
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = from_bytes(&identity.pubkey_blob)?;
                self.identity_remove(&pubkey)?;
                Ok(Message::Success)
            }
            Message::AddIdentity(identity) => {
                self.identity_add(Identity {
                    pubkey: PublicKey::from(&identity.privkey),
                    privkey: identity.privkey,
                    comment: identity.comment,
                });
                Ok(Message::Success)
            }
            Message::SignRequest(request) => {
                let signature = to_bytes(&self.sign(&request)?)?;
                Ok(Message::SignResponse(signature))
            }
            _ => Err(From::from(format!("Unknown message: {:?}", request))),
        };
        info!("Response {:?}", response);
        response
    }
}

#[async_trait]
impl Session for KeyStorage {
    async fn handle(&mut self, message: Message) -> Result<Message, Box<dyn std::error::Error>> {
        self.handle_message(message)
    }
}

struct KeyStorageAgent {
    identities: Arc<Mutex<Vec<Identity>>>,
}

impl KeyStorageAgent {
    fn new() -> Self {
        Self {
            identities: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl Agent for KeyStorageAgent {
    fn new_session(&mut self) -> impl Session {
        KeyStorage {
            identities: Arc::clone(&self.identities),
        }
    }
}

#[tokio::main]
#[cfg(not(windows))]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = "ssh-agent.sock";
    let _ = std::fs::remove_file(socket); // remove the socket if exists

    KeyStorageAgent::new()
        .listen(UnixListener::bind(socket)?)
        .await?;
    Ok(())
}

#[tokio::main]
#[cfg(windows)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    KeyStorageAgent::new()
        .listen(NamedPipeListener::new(r"\\.\pipe\agent".into())?)
        .await?;
    Ok(())
}
