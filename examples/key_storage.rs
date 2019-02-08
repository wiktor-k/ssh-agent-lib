#[macro_use]
extern crate log;
extern crate env_logger;
extern crate openssl;

use ssh_agent::proto::{from_bytes, to_bytes};
use ssh_agent::proto::message::{self, Message, SignRequest};
use ssh_agent::proto::signature::{self, Signature};
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::private_key::{PrivateKey, RsaPrivateKey};

use futures::future::FutureResult;

use ssh_agent::agent;

use std::sync::{Mutex, Arc};
use std::error::Error;

use openssl::sign::Signer;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::bn::BigNum;
use openssl::pkey::Private;

#[derive(PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String
}

struct KeyStorage {
    identities: Vec<Identity>
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            identities: vec![]
        }
    }
    
    fn identity_index_from_pubkey(&self, pubkey: &PublicKey) -> Option<usize> {
        for (index, identity) in self.identities.iter().enumerate() {
            if &identity.pubkey == pubkey {
                return Some(index);
            }
        }
        return None;
    }
    
    fn identity_from_pubkey(&self, pubkey: &PublicKey) -> Option<&Identity> {
        self.identity_index_from_pubkey(pubkey).map(|i| &self.identities[i])
    }
    
    fn sign(&self, sign_request: &SignRequest) -> Result<Signature, Box<Error>> {
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
    
    fn handle_message(&mut self, request: Message) -> Result<Message, Box<Error>>  {
        info!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in &self.identities {
                    identities.push(message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey)?,
                        comment: identity.comment.clone()
                    })
                }
                Ok(Message::IdentitiesAnswer(identities))
            },
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = from_bytes(&identity.pubkey_blob)?;
                if let Some(index) = self.identity_index_from_pubkey(&pubkey) {
                    self.identities.remove(index);
                    Ok(Message::Success)
                } else {
                    Err(From::from("Failed to remove identity: identity not found"))
                }
            },
            Message::AddIdentity(identity) => {
                let pubkey = PublicKey::from(&identity.privkey);
                if self.identity_from_pubkey(&pubkey) == None {
                    self.identities.push(Identity {
                        pubkey: pubkey,
                        privkey: identity.privkey,
                        comment: identity.comment
                    });
                }
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

fn rsa_openssl_from_ssh(ssh_rsa: &RsaPrivateKey) -> Result<Rsa<Private>, Box<Error>> {
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

fn main() -> Result<(), Box<std::error::Error>> {
    let storage = Arc::new(Mutex::new(KeyStorage::new()));
    
    env_logger::init();
    agent::start_unix("connect.sock", move |request| {
        FutureResult::from(storage.clone().lock().unwrap()
                           .handle_message(request)
                           .map_err(|error| {
                               error!("Error handling message; error = {}", error.description());
                           }))
    })?;
    Ok(())
}