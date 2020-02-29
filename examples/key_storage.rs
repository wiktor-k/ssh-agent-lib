use log::info;

use ssh_agent::proto::{from_bytes, to_bytes};
use ssh_agent::proto::message::{self, Message, SignRequest};
use ssh_agent::proto::signature::{self, Signature};
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::private_key::{PrivateKey, RsaPrivateKey};
use ssh_agent::agent::Agent;

use std::sync::RwLock;
use std::error::Error;
use std::fs::remove_file;

use openssl::sign::Signer;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::bn::BigNum;
use openssl::pkey::Private;

#[derive(Clone, PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String
}

struct KeyStorage {
    identities: RwLock<Vec<Identity>>
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            identities: RwLock::new(vec![])
        }
    }
    
    fn identity_index_from_pubkey(
        identities: &Vec<Identity>,
        pubkey: &PublicKey
    ) -> Option<usize> {
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
        let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob)?;
        
        if let Some(identity) = self.identity_from_pubkey(&pubkey) {
            match identity.privkey {
                PrivateKey::Rsa(ref key) => {
                    let algorithm;
                    let digest;
                    
                    if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                        algorithm = "rsa-sha2-512";
                        digest = MessageDigest::sha512();
                    } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                        algorithm = "rsa-sha2-256";
                        digest = MessageDigest::sha256();
                    } else {
                        algorithm = "ssh-rsa";
                        digest = MessageDigest::sha1();
                    }
                    
                    let keypair = PKey::from_rsa(rsa_openssl_from_ssh(key)?)?;
                    let mut signer = Signer::new(digest, &keypair)?;
                    signer.update(&sign_request.data)?;
                    
                    Ok(Signature {
                        algorithm: algorithm.to_string(),
                        blob: signer.sign_to_vec()?
                    })
                },
                _ => Err(From::from("Signature for key type not implemented"))
            }
        } else {
            Err(From::from("Failed to create signature: identity not found"))
        }
    }
    
    fn handle_message(&self, request: Message) -> Result<Message, Box<dyn Error>>  {
        info!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in self.identities.read().unwrap().iter() {
                    identities.push(message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey)?,
                        comment: identity.comment.clone()
                    })
                }
                Ok(Message::IdentitiesAnswer(identities))
            },
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = from_bytes(&identity.pubkey_blob)?;
                self.identity_remove(&pubkey)?;
                Ok(Message::Success)
            },
            Message::AddIdentity(identity) => {
                self.identity_add(Identity {
                    pubkey: PublicKey::from(&identity.privkey),
                    privkey: identity.privkey,
                    comment: identity.comment
                });
                Ok(Message::Success)
            },
            Message::SignRequest(request) => {
                let signature = to_bytes(&self.sign(&request)?)?;
                Ok(Message::SignResponse(signature))
            },
            _ => Err(From::from(format!("Unknown message: {:?}", request)))
        };
        info!("Response {:?}", response);
        return response;
    }
}

impl Agent for KeyStorage {
    type Error = ();
    
    fn handle(&self, message: Message) -> Result<Message, ()> {
        self.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}


fn rsa_openssl_from_ssh(ssh_rsa: &RsaPrivateKey) -> Result<Rsa<Private>, Box<dyn Error>> {
    let n = BigNum::from_slice(&ssh_rsa.n)?;
    let e = BigNum::from_slice(&ssh_rsa.e)?;
    let d = BigNum::from_slice(&ssh_rsa.d)?;
    let qi = BigNum::from_slice(&ssh_rsa.iqmp)?;
    let p = BigNum::from_slice(&ssh_rsa.p)?;
    let q = BigNum::from_slice(&ssh_rsa.q)?;
    let dp = &d % &(&p - &BigNum::from_u32(1)?);
    let dq = &d % &(&q - &BigNum::from_u32(1)?);
    
    Ok(Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let agent = KeyStorage::new();
    let socket = "connect.sock";
    let _ = remove_file(socket);
    
    env_logger::init();
    agent.run_unix(socket)?;
    Ok(())
}
