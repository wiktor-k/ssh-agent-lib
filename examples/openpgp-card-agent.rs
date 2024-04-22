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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{
    algorithm::AlgorithmAttributes,
    crypto_data::{EccType, PublicKeyMaterial},
    Card, KeyType,
};
use service_binding::Binding;
use ssh_agent_lib::{
    agent::Session,
    error::AgentError,
    proto::{Identity, SignRequest, SmartcardKey},
    Agent,
};
use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    Algorithm, Signature,
};
use testresult::TestResult;

#[derive(Default)]
struct CardAgent {
    pwds: Arc<Mutex<HashMap<String, String>>>,
}

impl Agent for CardAgent {
    fn new_session(&mut self) -> impl Session {
        CardSession {
            pwds: Arc::clone(&self.pwds),
        }
    }
}

struct CardSession {
    pwds: Arc<Mutex<HashMap<String, String>>>,
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
                    self.pwds
                        .lock()
                        .expect("lock not to be poisoned")
                        .insert(key.id, key.pin);
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

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let cards = PcscBackend::cards(None).map_err(AgentError::other)?;
        cards
            .flat_map(|card| -> Result<_, Box<dyn std::error::Error>> {
                let mut card = Card::new(card?)?;
                let mut tx = card.transaction()?;
                let ident = tx.application_identifier()?.ident();
                if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Authentication)? {
                    if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                        if ecc.ecc_type() == EccType::EdDSA {
                            let pubkey = KeyData::Ed25519(Ed25519PublicKey(e.data().try_into()?));
                            if pubkey == request.pubkey {
                                let pwds = self.pwds.lock().expect("mutex not to be poisoned");
                                let pin = pwds.get(&ident);
                                return if let Some(pin) = pin {
                                    tx.verify_pw1_user(pin.as_bytes())?;
                                    let signature =
                                        tx.internal_authenticate(request.data.clone())?;

                                    Ok(Signature::new(Algorithm::Ed25519, signature))
                                } else {
                                    // no pin saved, use "ssh-add -s ..."
                                    Err(std::io::Error::other("no pin saved").into())
                                };
                            }
                        }
                    }
                }
                Err(std::io::Error::other("no applicable card found").into())
            })
            .flatten()
            .next()
            .ok_or(std::io::Error::other("no applicable card found").into())
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short = 'H', long)]
    host: Binding,
}

#[tokio::main]
async fn main() -> TestResult {
    let args = Args::parse();
    CardAgent::default().bind(args.host.try_into()?).await?;
    Ok(())
}
