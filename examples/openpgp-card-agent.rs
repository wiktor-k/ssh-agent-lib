//! OpenPGP Card SSH Agent
//!
//! Implements an SSH agent which forwards cryptographic operations to
//! an OpenPGP Card device (such as Yubikey, Nitrokey etc).
//! The PIN is stored in memory for the duration of the agent session.
//! This agent supports only ed25519 authentication subkeys.
//! To provision the token use [OpenPGP Card Tools](https://codeberg.org/openpgp-card/openpgp-card-tools/#generate-keys-on-the-card).
//! Due to the use of PC/SC the agent requires pcsclite on Linux but no other libs
//! on Windows and macOS as it will utilize built-in smartcard services.
//!
//! The typical session:
//! - starting the SSH agent: `cargo run --example openpgp-card-agent -- -H unix:///tmp/sock`
//! - listing available cards: `SSH_AUTH_SOCK=/tmp/sock ssh-add -L` (this will display the card ident used in the next step)
//! - storing PIN for one of the cards: `SSH_AUTH_SOCK=/tmp/sock ssh-add -s 0006:15422467` (the agent will validate the PIN before storing it)
//! - and that's it! You can use the agent to login to your SSH servers.

use std::{sync::Arc, time::Duration};

#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener as Listener;

#[cfg(not(windows))]
use tokio::net::UnixListener as Listener;
use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{
    algorithm::AlgorithmAttributes,
    crypto_data::{EccType, PublicKeyMaterial},
    Card, KeyType,
};
use retainer::{Cache, CacheExpiration};
use secrecy::{ExposeSecret, SecretString};
use service_binding::Binding;
use ssh_agent_lib::{
    agent::{bind, Session, Agent},
    error::AgentError,
    proto::{AddSmartcardKeyConstrained, Identity, KeyConstraint, SignRequest, SmartcardKey},
};
use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    Algorithm, Signature,
};
use testresult::TestResult;
use tokio::net::TcpListener;

struct CardAgent {
    pwds: Arc<Cache<String, SecretString>>,
}

impl CardAgent {
    pub fn new() -> Self {
        let pwds: Arc<Cache<String, SecretString>> = Arc::new(Default::default());
        let clone = Arc::clone(&pwds);
        tokio::spawn(async move { clone.monitor(4, 0.25, Duration::from_secs(3)).await });
        Self { pwds }
    }
}

#[cfg(unix)]
impl Agent<Listener> for CardAgent {
    fn new_session(&mut self, _socket: &tokio::net::UnixStream) -> impl Session {
        CardSession {
            pwds: Arc::clone(&self.pwds),
        }
    }
}

#[cfg(unix)]
impl Agent<TcpListener> for CardAgent {
    fn new_session(&mut self, _socket: &tokio::net::TcpStream) -> impl Session {
        CardSession {
            pwds: Arc::clone(&self.pwds),
        }
    }
}

#[cfg(windows)]
impl Agent<Listener> for CardAgent {
    fn new_session(
        &mut self,
        _socket: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> impl Session {
        CardSession {
            pwds: Arc::clone(&self.pwds),
        }
    }
}

struct CardSession {
    pwds: Arc<Cache<String, SecretString>>,
}

impl CardSession {
    async fn handle_sign(
        &self,
        request: SignRequest,
    ) -> Result<ssh_key::Signature, Box<dyn std::error::Error + Send + Sync>> {
        let cards = PcscBackend::cards(None).map_err(AgentError::other)?;
        for card in cards {
            let mut card = Card::new(card?)?;
            let mut tx = card.transaction()?;
            let ident = tx.application_identifier()?.ident();
            if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Authentication)? {
                if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                    if ecc.ecc_type() == EccType::EdDSA {
                        let pubkey = KeyData::Ed25519(Ed25519PublicKey(e.data().try_into()?));
                        if pubkey == request.pubkey {
                            let pin = self.pwds.get(&ident).await;
                            return if let Some(pin) = pin {
                                tx.verify_pw1_user(pin.expose_secret().as_bytes())?;
                                let signature = tx.internal_authenticate(request.data.clone())?;

                                Ok(Signature::new(Algorithm::Ed25519, signature)?)
                            } else {
                                // no pin saved, use "ssh-add -s ..."
                                Err(std::io::Error::other("no pin saved").into())
                            };
                        }
                    }
                }
            }
        }
        Err(std::io::Error::other("no applicable card found").into())
    }

    async fn handle_add_smartcard_key(
        &mut self,
        key: SmartcardKey,
        expiration: impl Into<CacheExpiration>,
    ) -> Result<(), AgentError> {
        match PcscBackend::cards(None) {
            Ok(cards) => {
                let card_pin_matches = cards
                    .flat_map(|card| {
                        let mut card = Card::new(card?)?;
                        let mut tx = card.transaction()?;
                        let ident = tx.application_identifier()?.ident();
                        if ident == key.id {
                            tx.verify_pw1_user(key.pin.as_bytes())?;
                            Ok::<_, Box<dyn std::error::Error>>(true)
                        } else {
                            Ok(false)
                        }
                    })
                    .any(|x| x);
                if card_pin_matches {
                    self.pwds.insert(key.id, key.pin.into(), expiration).await;
                    Ok(())
                } else {
                    Err(AgentError::IO(std::io::Error::other(
                        "Card/PIN combination is not valid",
                    )))
                }
            }
            Err(error) => Err(AgentError::other(error)),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for CardSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(if let Ok(cards) = PcscBackend::cards(None) {
            cards
                .flat_map(|card| {
                    let mut card = Card::new(card?)?;
                    let mut tx = card.transaction()?;
                    let ident = tx.application_identifier()?.ident();
                    if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Authentication)? {
                        if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                            if ecc.ecc_type() == EccType::EdDSA {
                                return Ok::<_, Box<dyn std::error::Error>>(Some(Identity {
                                    pubkey: KeyData::Ed25519(Ed25519PublicKey(
                                        e.data().try_into()?,
                                    )),
                                    comment: ident,
                                }));
                            }
                        }
                    }
                    Ok(None)
                })
                .flatten()
                .collect::<Vec<_>>()
        } else {
            vec![]
        })
    }

    async fn add_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        self.handle_add_smartcard_key(key, CacheExpiration::none())
            .await
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        key: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        if key.constraints.len() > 1 {
            return Err(AgentError::other(std::io::Error::other(
                "Only one lifetime constraint supported.",
            )));
        }
        let expiration_in_seconds = if let KeyConstraint::Lifetime(seconds) = key.constraints[0] {
            Duration::from_secs(seconds as u64)
        } else {
            return Err(AgentError::other(std::io::Error::other(
                "Only one lifetime constraint supported.",
            )));
        };
        self.handle_add_smartcard_key(key.key, expiration_in_seconds)
            .await
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.handle_sign(request).await.map_err(AgentError::Other)
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short = 'H', long)]
    host: Binding,
}

#[tokio::main]
async fn main() -> TestResult {
    env_logger::init();

    let args = Args::parse();
    bind(args.host.try_into()?, CardAgent::new()).await?;
    Ok(())
}
