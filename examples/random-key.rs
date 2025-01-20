use std::ops::Deref;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha1::Sha1;
#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener as Listener;
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{signature, Identity, SignRequest};
use ssh_key::private::RsaKeypair;
use ssh_key::HashAlg;
use ssh_key::{
    private::{KeypairData, PrivateKey},
    public::PublicKey,
    Algorithm, Signature,
};
#[cfg(not(windows))]
use tokio::net::UnixListener as Listener;

#[derive(Clone)]
struct RandomKey {
    private_key: Arc<Mutex<PrivateKey>>,
}

impl RandomKey {
    pub fn new() -> Result<Self, AgentError> {
        let rsa = RsaKeypair::random(&mut rand::thread_rng(), 2048).map_err(AgentError::other)?;
        let privkey = PrivateKey::new(KeypairData::Rsa(rsa), "automatically generated RSA key")
            .map_err(AgentError::other)?;
        Ok(Self {
            private_key: Arc::new(Mutex::new(privkey)),
        })
    }
}

#[crate::async_trait]
impl Session for RandomKey {
    async fn sign(&mut self, sign_request: SignRequest) -> Result<Signature, AgentError> {
        let private_key = self.private_key.lock().unwrap();
        if PublicKey::from(private_key.deref()).key_data() != &sign_request.pubkey {
            return Err(std::io::Error::other("Key not found").into());
        }

        if let KeypairData::Rsa(ref key) = private_key.key_data() {
            let private_key: rsa::RsaPrivateKey = key.try_into().map_err(AgentError::other)?;
            let mut rng = rand::thread_rng();
            let data = &sign_request.data;

            Ok(if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    SigningKey::<Sha512>::new(private_key)
                        .sign_with_rng(&mut rng, data)
                        .to_bytes(),
                )
            } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    SigningKey::<Sha256>::new(private_key)
                        .sign_with_rng(&mut rng, data)
                        .to_bytes(),
                )
            } else {
                Signature::new(
                    Algorithm::Rsa { hash: None },
                    SigningKey::<Sha1>::new(private_key)
                        .sign_with_rng(&mut rng, data)
                        .to_bytes(),
                )
            }
            .map_err(AgentError::other)?)
        } else {
            Err(std::io::Error::other("Signature for key type not implemented").into())
        }
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let identity = self.private_key.lock().unwrap();
        Ok(vec![Identity {
            pubkey: PublicKey::from(identity.deref()).into(),
            comment: identity.comment().into(),
        }])
    }
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    env_logger::init();

    #[cfg(not(windows))]
    let socket = "ssh-agent.sock";
    #[cfg(windows)]
    let socket = r"\\.\pipe\agent";

    let _ = std::fs::remove_file(socket); // remove the socket if exists

    // This is only used for integration tests on Windows:
    #[cfg(windows)]
    std::fs::File::create("server-started")?;

    listen(Listener::bind(socket)?, RandomKey::new()?).await?;
    Ok(())
}
