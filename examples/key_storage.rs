#[macro_use]
extern crate log;
extern crate env_logger;

extern crate openssl;

use ssh_agent::proto::{from_bytes, to_bytes};
use ssh_agent::proto::message::{self, Message, SignRequest};
use ssh_agent::proto::signature::{self, Signature};
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::private_key::{PrivateKey, RsaPrivateKey};

use ssh_agent::agent;

use std::sync::{Mutex, Arc};

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
    
    fn sign(&self, sign_request: &SignRequest) -> Option<Signature> {
        let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob).unwrap();
        let identity = self.identity_from_pubkey(&pubkey)?;
        
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
                
                let keypair = PKey::from_rsa(rsa_openssl_from_ssh(key)).unwrap();
                let mut signer = Signer::new(digest, &keypair).unwrap();
                signer.update(&sign_request.data).unwrap();
                
                Some(Signature {
                    algorithm: algorithm.to_string(),
                    blob: signer.sign_to_vec().unwrap()
                })
            },
            _ => None
        }
    }
    
    fn handle_message(&mut self, request: Message) -> Message {
        debug!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                Message::IdentitiesAnswer(self.identities.iter().map(|identity| {
                    message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey).unwrap(),
                        comment: identity.comment.clone()
                    }
                }).collect())
            },
            Message::RemoveIdentity(identity) => {
                let pubkey: PublicKey = from_bytes(&identity.pubkey_blob).unwrap();
                if let Some(index) = self.identity_index_from_pubkey(&pubkey) {
                    self.identities.remove(index);
                    Message::Success
                } else {
                    Message::Failure
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
                Message::Success
            },
            Message::SignRequest(request) => {
                if let Some(signature) = self.sign(&request) {
                    Message::SignResponse(to_bytes(&signature).unwrap())
                } else {
                    Message::Failure
                }
            },
            _ => Message::Failure
        };
        debug!("Response {:?}", response);
        return response;
    }
}

fn rsa_openssl_from_ssh(ssh_rsa: &RsaPrivateKey) -> Rsa<Private> {
    let n = BigNum::from_slice(&ssh_rsa.n).unwrap();
    let e = BigNum::from_slice(&ssh_rsa.e).unwrap();
    let d = BigNum::from_slice(&ssh_rsa.d).unwrap();
    let qi = BigNum::from_slice(&ssh_rsa.iqmp).unwrap();
    let p = BigNum::from_slice(&ssh_rsa.p).unwrap();
    let q = BigNum::from_slice(&ssh_rsa.q).unwrap();
    let dp = &d % &(&p - &BigNum::from_u32(1).unwrap());
    let dq = &d % &(&q - &BigNum::from_u32(1).unwrap());
    
    Rsa::from_private_components(n, e, d, p, q, dp, dq, qi).unwrap()
}

fn main() -> Result<(), Box<std::error::Error>> {
    let storage = Arc::new(Mutex::new(KeyStorage::new()));
    
    env_logger::init();
    agent::start_unix("connect.sock", move |message| {
        (&storage).clone().lock().unwrap().handle_message(message)
    })?;
    Ok(())
}