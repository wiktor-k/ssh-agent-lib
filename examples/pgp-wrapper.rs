//! OpenPGP wrapper for SSH keys
//!
//! Creates an OpenPGP certificate based on the SSH key and allows signing files
//! emitting OpenPGP framed packets.
//!
//! Requires that the first key in SSH is ed25519 (see `ssh-add -L`).
//!
//! Generate a key with:
//! `cargo run --example pgp-wrapper generate "John Doe <john@example.com>" > key.pgp`
//!
//! Sign data using:
//! `cargo run --example pgp-wrapper sign < Cargo.toml > Cargo.toml.sig`
//!
//! Import the certificate using GnuPG:
//! ```sh
//! $ gpg --import key.pgp
//! gpg: key A142E92C91BE3AD5: public key "John Doe <john@example.com>" imported
//! gpg: Total number processed: 1
//! gpg:               imported: 1
//! ```
//!
//! Verify the signature using GnuPG:
//! ```sh
//! $ gpg --verify Cargo.toml.sig
//! gpg: assuming signed data in 'Cargo.toml'
//! gpg: Signature made Fri May 10 11:15:53 2024 CEST
//! gpg:                using EDDSA key 4EB27E153DDC454364B36B59A142E92C91BE3AD5
//! gpg: Good signature from "John Doe <john@example.com>" [unknown]
//! gpg: WARNING: This key is not certified with a trusted signature!
//! gpg:          There is no indication that the signature belongs to the owner.
//! Primary key fingerprint: 4EB2 7E15 3DDC 4543 64B3  6B59 A142 E92C 91BE 3AD5
//! ```
//!
//! Works perfectly in conjunction with `openpgp-card-agent.rs`!

use std::cell::RefCell;

use chrono::DateTime;
use clap::Parser;
use pgp::{
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags, PublicKey, SignatureConfig, SignatureType, SignatureVersion, Subpacket,
        SubpacketData, UserId,
    },
    ser::Serialize,
    types::{KeyTrait, KeyVersion, Mpi, PublicKeyTrait, PublicParams, SecretKeyTrait, Version},
    KeyDetails, Signature,
};
use service_binding::Binding;
use ssh_agent_lib::{agent::Session, client::connect, proto::SignRequest};
use ssh_key::public::KeyData;
use tokio::runtime::Runtime;

struct WrappedKey {
    public_key: PublicKey,
    pubkey: KeyData,
    client: RefCell<Box<dyn Session>>,
}

impl WrappedKey {
    fn new(pubkey: KeyData, client: Box<dyn Session>) -> Self {
        let KeyData::Ed25519(key) = pubkey.clone() else {
            panic!("The first key was not ed25519!");
        };

        let mut key_bytes = key.0.to_vec();
        // Add prefix to mark that this MPI uses EdDSA point representation.
        // See https://datatracker.ietf.org/doc/draft-koch-eddsa-for-openpgp/
        key_bytes.insert(0, 0x40);

        let public_key = PublicKey::new(
            Version::New,
            KeyVersion::V4,
            PublicKeyAlgorithm::EdDSA,
            // use fixed date so that the fingerprint generation is deterministic
            DateTime::parse_from_rfc3339("2016-09-06T17:00:00+02:00")
                .expect("date to be valid")
                .into(),
            None,
            PublicParams::EdDSA {
                curve: ECCCurve::Ed25519,
                q: key_bytes.into(),
            },
        )
        .expect("key to be valid");

        Self {
            pubkey,
            client: RefCell::new(client),
            public_key,
        }
    }
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedKey")
    }
}

impl KeyTrait for WrappedKey {
    fn fingerprint(&self) -> Vec<u8> {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> pgp::types::KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.public_key.algorithm()
    }
}

impl PublicKeyTrait for WrappedKey {
    fn verify_signature(
        &self,
        hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
        sig: &[pgp::types::Mpi],
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: rand::prelude::CryptoRng + rand::prelude::Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> pgp::errors::Result<Vec<pgp::types::Mpi>> {
        self.public_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.to_writer_old(writer)
    }
}

impl SecretKeyTrait for WrappedKey {
    type PublicKey = PublicKey;

    type Unlocked = Self;

    fn unlock<F, G, T>(&self, _pw: F, _work: G) -> pgp::errors::Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<T>,
    {
        unimplemented!("key unlock is implemented in the ssh agent")
    }

    #[allow(clippy::await_holding_refcell_ref)]
    fn create_signature<F>(
        &self,
        _key_pw: F,
        _hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<Vec<pgp::types::Mpi>>
    where
        F: FnOnce() -> String,
    {
        let signature = Runtime::new()
            .expect("creating runtime to succeed")
            .handle()
            .block_on(async {
                let mut client = self.client.try_borrow_mut().expect("not to be shared");
                let result = client.sign(SignRequest {
                    pubkey: self.pubkey.clone(),
                    data: data.to_vec(),
                    flags: 0,
                });
                result.await
            })
            .expect("signing to succeed");

        let sig = &signature.as_bytes();

        assert_eq!(sig.len(), 64);

        Ok(vec![
            Mpi::from_raw_slice(&sig[..32]),
            Mpi::from_raw_slice(&sig[32..]),
        ])
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn public_params(&self) -> &pgp::types::PublicParams {
        self.public_key.public_params()
    }
}

#[derive(Debug, Parser)]
enum Args {
    Generate { userid: String },
    Sign,
}

fn main() -> testresult::TestResult {
    let args = Args::parse();

    let rt = Runtime::new()?;

    let (client, identities) = rt.block_on(async move {
        #[cfg(unix)]
        let mut client =
            connect(Binding::FilePath(std::env::var("SSH_AUTH_SOCK")?.into()).try_into()?)?;

        #[cfg(windows)]
        let mut client =
            connect(Binding::NamedPipe(std::env::var("SSH_AUTH_SOCK")?.into()).try_into()?)?;

        let identities = client.request_identities().await?;

        if identities.is_empty() {
            panic!("We need at least one ed25519 identity!");
        }

        Ok::<_, testresult::TestError>((client, identities))
    })?;

    let pubkey = &identities[0].pubkey;

    let signer = WrappedKey::new(pubkey.clone(), client);

    match args {
        Args::Generate { userid } => {
            let mut keyflags = KeyFlags::default();
            keyflags.set_sign(true);
            keyflags.set_certify(true);

            let composed_pk = pgp::PublicKey::new(
                signer.public_key(),
                KeyDetails::new(
                    UserId::from_str(Default::default(), &userid),
                    vec![],
                    vec![],
                    keyflags,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                ),
                vec![],
            );
            let signed_pk = composed_pk.sign(&signer, String::new)?;
            signed_pk.to_writer(&mut std::io::stdout())?;
        }
        Args::Sign => {
            let signature = SignatureConfig::new_v4(
                SignatureVersion::V4,
                SignatureType::Binary,
                signer.algorithm(),
                HashAlgorithm::SHA2_256,
                vec![
                    Subpacket::regular(SubpacketData::SignatureCreationTime(
                        std::time::SystemTime::now().into(),
                    )),
                    Subpacket::regular(SubpacketData::Issuer(signer.key_id())),
                    Subpacket::regular(SubpacketData::IssuerFingerprint(
                        KeyVersion::V4,
                        signer.fingerprint().into(),
                    )),
                ],
                vec![],
            );

            let mut hasher = signature.hash_alg.new_hasher()?;

            signature.hash_data_to_sign(&mut *hasher, std::io::stdin())?;
            let len = signature.hash_signature_data(&mut *hasher)?;
            hasher.update(&signature.trailer(len)?);

            let hash = &hasher.finish()[..];

            let signed_hash_value = [hash[0], hash[1]];
            let raw_sig = signer.create_signature(String::new, HashAlgorithm::SHA2_256, hash)?;

            let signature = Signature::from_config(signature, signed_hash_value, raw_sig);
            pgp::packet::write_packet(&mut std::io::stdout(), &signature)?;
        }
    }

    Ok(())
}
