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

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{
    ocard::algorithm::AlgorithmAttributes,
    ocard::crypto::{Cryptogram, EccType, PublicKeyMaterial},
    ocard::KeyType,
    ocard::OpenPGP,
};
use retainer::{Cache, CacheExpiration};
use secrecy::{ExposeSecret, SecretString};
use service_binding::Binding;
use ssh_agent_lib::{
    agent::{bind, Session},
    error::AgentError,
    proto::{
        extension::MessageExtension, AddSmartcardKeyConstrained, Extension, Identity,
        KeyConstraint, ProtoError, SignRequest, SmartcardKey,
    },
};
use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    Algorithm, Signature,
};
use testresult::TestResult;
mod extensions;
use extensions::{
    DecryptDeriveRequest, DecryptDeriveResponse, DecryptIdentities, RequestDecryptIdentities,
};

#[derive(Clone)]
struct CardSession {
    pwds: Arc<Cache<String, SecretString>>,
}

impl CardSession {
    pub fn new() -> Self {
        let pwds: Arc<Cache<String, SecretString>> = Arc::new(Default::default());
        let clone = Arc::clone(&pwds);
        tokio::spawn(async move { clone.monitor(4, 0.25, Duration::from_secs(3)).await });
        Self { pwds }
    }

    async fn handle_sign(
        &self,
        request: SignRequest,
    ) -> Result<ssh_key::Signature, Box<dyn std::error::Error + Send + Sync>> {
        let cards = PcscBackend::cards(None).map_err(AgentError::other)?;
        for card in cards {
            let mut card = OpenPGP::new(card?)?;
            let mut tx = card.transaction()?;
            let ident = tx.application_identifier()?.ident();
            if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Authentication)? {
                if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                    if ecc.ecc_type() == EccType::EdDSA {
                        let pubkey = KeyData::Ed25519(Ed25519PublicKey(e.data().try_into()?));
                        if pubkey == *request.pubkey.key_data() {
                            let pin = self.pwds.get(&ident).await;
                            return if let Some(pin) = pin {
                                let str = pin.expose_secret().as_bytes().to_vec();
                                tx.verify_pw1_user(str.into())?;
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
                        let mut card = OpenPGP::new(card?)?;
                        let mut tx = card.transaction()?;
                        let ident = tx.application_identifier()?.ident();
                        if ident == key.id {
                            let str = key.pin.expose_secret().as_bytes().to_vec();
                            tx.verify_pw1_user(str.into())?;

                            Ok::<_, Box<dyn std::error::Error>>(true)
                        } else {
                            Ok(false)
                        }
                    })
                    .any(|x| x);
                if card_pin_matches {
                    self.pwds.insert(key.id, key.pin, expiration).await;
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

    async fn decrypt_derive(
        &mut self,
        req: DecryptDeriveRequest,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(cards) = PcscBackend::cards(None) {
            for card in cards {
                let mut card = OpenPGP::new(card?)?;
                let mut tx = card.transaction()?;
                if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Decryption)? {
                    if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                        if ecc.ecc_type() == EccType::ECDH {
                            let pubkey = KeyData::Ed25519(Ed25519PublicKey(e.data().try_into()?));
                            if pubkey == req.pubkey {
                                let ident = tx.application_identifier()?.ident();
                                let pin = self.pwds.get(&ident).await;
                                if let Some(pin) = pin {
                                    let str = pin.expose_secret().as_bytes().to_vec();
                                    tx.verify_pw1_user(str.into())?;

                                    let data = tx.decipher(Cryptogram::ECDH(&req.data))?;
                                    return Ok(Some(data));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for CardSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(if let Ok(cards) = PcscBackend::cards(None) {
            cards
                .flat_map(|card| {
                    let mut card = OpenPGP::new(card?)?;
                    let mut tx = card.transaction()?;
                    let ident = tx.application_identifier()?.ident();
                    if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Authentication)? {
                        if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                            if ecc.ecc_type() == EccType::EdDSA {
                                return Ok::<_, Box<dyn std::error::Error>>(Some(Identity {
                                    pubkey: KeyData::Ed25519(Ed25519PublicKey(
                                        e.data().try_into()?,
                                    ))
                                    .into(),
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

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        if extension.name == RequestDecryptIdentities::NAME {
            let identities = if let Ok(cards) = PcscBackend::cards(None) {
                cards
                    .flat_map(|card| {
                        let mut card = OpenPGP::new(card?)?;
                        let mut tx = card.transaction()?;
                        let ident = tx.application_identifier()?.ident();
                        if let PublicKeyMaterial::E(e) = tx.public_key(KeyType::Decryption)? {
                            if let AlgorithmAttributes::Ecc(ecc) = e.algo() {
                                if ecc.ecc_type() == EccType::ECDH {
                                    return Ok::<_, Box<dyn std::error::Error>>(Some(Identity {
                                        pubkey: KeyData::Ed25519(Ed25519PublicKey(
                                            e.data().try_into()?,
                                        ))
                                        .into(),
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
            };

            Ok(Some(
                Extension::new_message(DecryptIdentities { identities })
                    .map_err(AgentError::other)?,
            ))
        } else if extension.name == DecryptDeriveRequest::NAME {
            let req = extension
                .parse_message::<DecryptDeriveRequest>()?
                .expect("message to be there");

            let decrypted = self.decrypt_derive(req).await.map_err(AgentError::Other)?;

            if let Some(decrypted) = decrypted {
                Ok(Some(
                    Extension::new_message(DecryptDeriveResponse { data: decrypted })
                        .map_err(AgentError::other)?,
                ))
            } else {
                Err(AgentError::from(ProtoError::UnsupportedCommand {
                    command: 27,
                }))
            }
        } else {
            Err(AgentError::from(ProtoError::UnsupportedCommand {
                command: 27,
            }))
        }
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
    bind(args.host.try_into()?, CardSession::new()).await?;
    Ok(())
}
