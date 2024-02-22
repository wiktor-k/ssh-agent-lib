use async_trait::async_trait;
use log::info;
use tokio::net::UnixListener;

use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::{self, Message, SignRequest};
use ssh_agent_lib::proto::signature::{self};
use ssh_key::{
    private::{KeypairData, PrivateKey, RsaKeypair},
    public::PublicKey,
    Algorithm, HashAlg, Signature,
};

use std::error::Error;
use std::fs::remove_file;
use std::sync::RwLock;

use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::Signer;

#[derive(Clone, PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
}

struct KeyStorage {
    identities: RwLock<Vec<Identity>>,
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            identities: RwLock::new(vec![]),
        }
    }

    fn identity_index_from_pubkey(identities: &Vec<Identity>, pubkey: &PublicKey) -> Option<usize> {
        for (index, identity) in identities.iter().enumerate() {
            if &identity.pubkey == pubkey {
                return Some(index);
            }
        }
        return None;
    }

    fn identity_from_pubkey(&self, pubkey: &PublicKey) -> Option<Identity> {
        let identities = self.identities.read().unwrap();

        let index = Self::identity_index_from_pubkey(&identities, pubkey)?;
        Some(identities[index].clone())
    }

    fn identity_add(&self, identity: Identity) {
        let mut identities = self.identities.write().unwrap();
        if Self::identity_index_from_pubkey(&identities, &identity.pubkey) == None {
            identities.push(identity);
        }
    }

    fn identity_remove(&self, pubkey: &PublicKey) -> Result<(), Box<dyn Error>> {
        let mut identities = self.identities.write().unwrap();

        if let Some(index) = Self::identity_index_from_pubkey(&identities, &pubkey) {
            identities.remove(index);
            Ok(())
        } else {
            Err(From::from("Failed to remove identity: identity not found"))
        }
    }

    fn sign(&self, sign_request: &SignRequest) -> Result<Signature, Box<dyn Error>> {
        let pubkey: PublicKey = sign_request.pubkey.clone().try_into()?;

        if let Some(identity) = self.identity_from_pubkey(&pubkey) {
            match identity.privkey.key_data() {
                KeypairData::Rsa(ref key) => {
                    let algorithm;
                    let digest;

                    if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                        algorithm = Algorithm::Rsa {
                            hash: Some(HashAlg::Sha512),
                        };
                        digest = MessageDigest::sha512();
                    } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                        algorithm = Algorithm::Rsa {
                            hash: Some(HashAlg::Sha256),
                        };
                        digest = MessageDigest::sha256();
                    } else {
                        algorithm = Algorithm::Rsa { hash: None };
                        digest = MessageDigest::sha1();
                    }

                    let keypair = PKey::from_rsa(rsa_openssl_from_ssh(key)?)?;
                    let mut signer = Signer::new(digest, &keypair)?;
                    signer.update(&sign_request.data)?;

                    Ok(Signature::new(algorithm, signer.sign_to_vec()?).unwrap())
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
                for identity in self.identities.read().unwrap().iter() {
                    identities.push(message::Identity {
                        pubkey: identity.pubkey.key_data().clone(),
                        comment: identity.comment.clone(),
                    })
                }
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = identity.pubkey.try_into()?;
                self.identity_remove(&pubkey)?;
                Ok(Message::Success)
            }
            Message::AddIdentity(identity) => {
                println!("add_identity0");
                let privkey = PrivateKey::try_from(identity.privkey).unwrap();
                self.identity_add(Identity {
                    pubkey: PublicKey::from(&privkey),
                    privkey: privkey,
                    comment: identity.comment,
                });
                println!("add_identity1");
                Ok(Message::Success)
            }
            Message::SignRequest(request) => {
                let signature = self.sign(&request)?;
                Ok(Message::SignResponse(signature))
            }
            _ => Err(From::from(format!("Unknown message: {:?}", request))),
        };
        info!("Response {:?}", response);
        return response;
    }
}

#[async_trait]
impl Session for KeyStorage {
    async fn handle(&mut self, message: Message) -> Result<Message, AgentError> {
        self.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}

impl Agent for KeyStorage {
    fn new_session(&mut self) -> impl Session {
        KeyStorage::new()
    }
}

fn rsa_openssl_from_ssh(ssh_rsa: &RsaKeypair) -> Result<Rsa<Private>, Box<dyn Error>> {
    let n = BigNum::from_slice(&ssh_rsa.public.n.as_bytes())?;
    let e = BigNum::from_slice(&ssh_rsa.public.e.as_bytes())?;
    let d = BigNum::from_slice(&ssh_rsa.private.d.as_bytes())?;
    let qi = BigNum::from_slice(&ssh_rsa.private.iqmp.as_bytes())?;
    let p = BigNum::from_slice(&ssh_rsa.private.p.as_bytes())?;
    let q = BigNum::from_slice(&ssh_rsa.private.q.as_bytes())?;
    let dp = &d % &(&p - &BigNum::from_u32(1)?);
    let dq = &d % &(&q - &BigNum::from_u32(1)?);

    Ok(Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let agent = KeyStorage::new();
    let socket = "connect.sock";
    let _ = remove_file(socket);
    env_logger::init();
    let socket = UnixListener::bind(socket)?;

    agent.listen(socket).await?;
    Ok(())
}
