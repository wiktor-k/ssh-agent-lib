use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::BigUint;
use sha1::Sha1;
#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener as Listener;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{
    message, signature, AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained,
    Credential, Extension, KeyConstraint, RemoveIdentity, SignRequest, SmartcardKey,
};
use ssh_agent_lib::Agent;
use ssh_key::{
    private::{KeypairData, PrivateKey},
    public::PublicKey,
    Algorithm, Signature,
};
#[cfg(not(windows))]
use tokio::net::UnixListener as Listener;

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
    fn identity_index_from_pubkey(identities: &[Identity], pubkey: &PublicKey) -> Option<usize> {
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
}

#[crate::async_trait]
impl Session for KeyStorage {
    async fn sign(
        &mut self,
        sign_request: SignRequest,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        let pubkey: PublicKey = sign_request.pubkey.clone().into();

        if let Some(identity) = self.identity_from_pubkey(&pubkey) {
            match identity.privkey.key_data() {
                KeypairData::Rsa(ref key) => {
                    let algorithm;

                    let private_key = rsa::RsaPrivateKey::from_components(
                        BigUint::from_bytes_be(key.public.n.as_bytes()),
                        BigUint::from_bytes_be(key.public.e.as_bytes()),
                        BigUint::from_bytes_be(key.private.d.as_bytes()),
                        vec![],
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
                    Ok(Signature::new(
                        Algorithm::new(algorithm)?,
                        signature.to_bytes().to_vec(),
                    )?)
                }
                _ => Err(From::from("Signature for key type not implemented")),
            }
        } else {
            Err(From::from("Failed to create signature: identity not found"))
        }
    }

    async fn request_identities(
        &mut self,
    ) -> Result<Vec<message::Identity>, Box<dyn std::error::Error>> {
        let mut identities = vec![];
        for identity in self.identities.lock().unwrap().iter() {
            identities.push(message::Identity {
                pubkey: identity.pubkey.key_data().clone(),
                comment: identity.comment.clone(),
            })
        }
        Ok(identities)
    }

    async fn add_identity(
        &mut self,
        identity: AddIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Credential::Key { privkey, comment } = identity.credential {
            let privkey = PrivateKey::try_from(privkey)?;
            self.identity_add(Identity {
                pubkey: PublicKey::from(&privkey),
                privkey,
                comment,
            });
            Ok(())
        } else {
            eprintln!("Unsupported key type: {:#?}", identity.credential);
            Ok(())
        }
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let AddIdentityConstrained {
            identity,
            constraints,
        } = identity;
        eprintln!("Would use these constraints: {constraints:#?}");
        for constraint in constraints {
            if let KeyConstraint::Extension(name, mut details) = constraint {
                if name == "restrict-destination-v00@openssh.com" {
                    if let Ok(destination_constraint) = details.parse::<SessionBind>() {
                        eprintln!("Destination constraint: {destination_constraint:?}");
                    }
                }
                if let Credential::Key { privkey, comment } = identity.credential.clone() {
                    let privkey = PrivateKey::try_from(privkey)?;
                    self.identity_add(Identity {
                        pubkey: PublicKey::from(&privkey),
                        privkey,
                        comment,
                    });
                }
            }
        }
        self.add_identity(identity).await
    }

    async fn remove_identity(
        &mut self,
        identity: RemoveIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pubkey: PublicKey = identity.pubkey.into();
        self.identity_remove(&pubkey)?;
        Ok(())
    }

    async fn add_smartcard_key(
        &mut self,
        key: SmartcardKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Adding smartcard key: {key:?}");

        Ok(())
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        key: AddSmartcardKeyConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Adding smartcard key with constraints: {key:?}");
        Ok(())
    }
    async fn lock(&mut self, pwd: String) -> Result<(), Box<dyn std::error::Error>> {
        println!("Locked with password: {pwd:?}");
        Ok(())
    }

    async fn unlock(&mut self, pwd: String) -> Result<(), Box<dyn std::error::Error>> {
        println!("Unlocked with password: {pwd:?}");
        Ok(())
    }

    async fn extension(
        &mut self,
        mut extension: Extension,
    ) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("Extension: {extension:?}");
        if extension.name == "session-bind@openssh.com" {
            let bind = extension.details.parse::<SessionBind>()?;
            eprintln!("Bind: {bind:?}");
        }
        Ok(())
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    #[cfg(not(windows))]
    let socket = "ssh-agent.sock";
    #[cfg(windows)]
    let socket = r"\\.\pipe\agent";

    let _ = std::fs::remove_file(socket); // remove the socket if exists

    // This is only used for integration tests on Windows:
    #[cfg(windows)]
    std::fs::File::create("server-started")?;

    KeyStorageAgent::new()
        .listen(Listener::bind(socket)?)
        .await?;
    Ok(())
}
