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
//!
//! If the SSH agent implements `decrypt derive` extension this agent additionally
//! creates encryption capable subkey and supports the `decrypt` subcommand:
//!
//! ```sh
//! echo I like strawberries | gpg -er 4EB27E153DDC454364B36B59A142E92C91BE3AD5 > /tmp/encrypted.pgp
//! SSH_AUTH_SOCK=/tmp/ext-agent.sock cargo run --example pgp-wrapper -- decrypt < /tmp/encrypted.pgp
//! ...
//! I like strawberries
//! ```

use std::io::Write as _;

use chrono::DateTime;
use clap::Parser;
use pgp::{
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags, PacketTrait, PublicKey, SignatureConfig, SignatureType, SignatureVersion,
        Subpacket, SubpacketData, UserId,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, KeyTrait, KeyVersion, Mpi, PublicKeyTrait, PublicParams,
        SecretKeyTrait, Version,
    },
    Deserializable as _, Esk, KeyDetails, Message, PlainSessionKey, Signature,
};
use service_binding::Binding;
use ssh_agent_lib::{
    agent::Session,
    client::connect,
    proto::{Extension, SignRequest},
};
use ssh_key::public::KeyData;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
mod extensions;
use extensions::{
    DecryptDeriveRequest, DecryptDeriveResponse, DecryptIdentities, RequestDecryptIdentities,
};

struct WrappedKey {
    public_key: PublicKey,
    pubkey: KeyData,
    client: Mutex<Box<dyn Session>>,
}

#[derive(Clone, Copy, Debug)]
enum KeyRole {
    Signing,
    Decryption,
}

impl From<KeyRole> for PublicKeyAlgorithm {
    fn from(value: KeyRole) -> Self {
        match value {
            KeyRole::Signing => PublicKeyAlgorithm::EdDSA,
            KeyRole::Decryption => PublicKeyAlgorithm::ECDH,
        }
    }
}

fn ssh_to_pgp(pubkey: KeyData, key_role: KeyRole) -> PublicKey {
    let KeyData::Ed25519(key) = pubkey.clone() else {
        panic!("The first key was not ed25519!");
    };

    let mut key_bytes = key.0.to_vec();
    // Add prefix to mark that this MPI uses EdDSA point representation.
    // See https://datatracker.ietf.org/doc/draft-koch-eddsa-for-openpgp/
    key_bytes.insert(0, 0x40);

    let public_params = match key_role {
        KeyRole::Signing => PublicParams::EdDSA {
            curve: ECCCurve::Ed25519,
            q: key_bytes.into(),
        },
        // most common values taken from
        // https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463
        KeyRole::Decryption => PublicParams::ECDH {
            curve: ECCCurve::Curve25519,
            p: key_bytes.into(),
            hash: HashAlgorithm::SHA2_256,
            alg_sym: pgp::crypto::sym::SymmetricKeyAlgorithm::AES128,
        },
    };

    PublicKey::new(
        Version::New,
        KeyVersion::V4,
        key_role.into(),
        // use fixed date so that the fingerprint generation is deterministic
        DateTime::parse_from_rfc3339("2016-09-06T17:00:00+02:00")
            .expect("date to be valid")
            .into(),
        None,
        public_params,
    )
    .expect("key to be valid")
}

impl WrappedKey {
    fn new(pubkey: KeyData, client: Box<dyn Session>, key_role: KeyRole) -> Self {
        let public_key = ssh_to_pgp(pubkey.clone(), key_role);
        Self {
            pubkey,
            client: Mutex::new(client),
            public_key,
        }
    }

    fn decrypt(
        &self,
        mpis: &[Mpi],
    ) -> Result<(Vec<u8>, pgp::crypto::sym::SymmetricKeyAlgorithm), pgp::errors::Error> {
        if let PublicParams::ECDH {
            curve,
            alg_sym,
            hash,
            ..
        } = self.public_key().public_params()
        {
            let ciphertext = mpis[0].as_bytes();

            // encrypted and wrapped value derived from the session key
            let encrypted_session_key = mpis[2].as_bytes();

            let ciphertext = if *curve == ECCCurve::Curve25519 {
                assert_eq!(
                    ciphertext[0], 0x40,
                    "Unexpected shape of Cv25519 encrypted data"
                );

                // Strip trailing 0x40
                &ciphertext[1..]
            } else {
                unimplemented!();
            };

            let plaintext = Runtime::new()
                .expect("creating runtime to succeed")
                .handle()
                .block_on(async {
                    let mut client = self.client.lock().await;
                    let result = client.extension(
                        Extension::new_message(DecryptDeriveRequest {
                            pubkey: self.pubkey.clone(),
                            data: ciphertext.to_vec(),
                            flags: 0,
                        })
                        .expect("encoding to work"),
                    );
                    result.await
                })
                .expect("decryption to succeed")
                .expect("result not to be empty");

            let shared_secret = &plaintext
                .parse_message::<DecryptDeriveResponse>()
                .expect("decoding to succeed")
                .expect("not to be empty")
                .data[..];

            let encrypted_key_len: usize = mpis[1].first().copied().map(Into::into).unwrap_or(0);

            let decrypted_key: Vec<u8> = pgp::crypto::ecdh::derive_session_key(
                shared_secret.try_into().expect("shape to be good"),
                encrypted_session_key,
                encrypted_key_len,
                &(curve.oid(), *alg_sym, *hash),
                &self.public_key.fingerprint(),
            )?;

            // strip off the leading session key algorithm octet, and the two trailing checksum octets
            let dec_len = decrypted_key.len();
            let (sessionkey, checksum) = (
                &decrypted_key[1..dec_len - 2],
                &decrypted_key[dec_len - 2..],
            );

            // ... check the checksum, while we have it at hand
            pgp::crypto::checksum::simple(checksum, sessionkey)?;

            let session_key_algorithm = decrypted_key[0].into();
            Ok((sessionkey.to_vec(), session_key_algorithm))
        } else {
            unimplemented!();
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

    fn unlock<F, G, T>(&self, _pw: F, work: G) -> pgp::errors::Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<T>,
    {
        work(self)
    }

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
                let mut client = self.client.lock().await;
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
    Decrypt,
}

fn main() -> testresult::TestResult {
    let args = Args::parse();

    let rt = Runtime::new()?;

    let (client, identities, decrypt_ids) = rt.block_on(async move {
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

        let decrypt_ids = if let Ok(Some(identities)) = client
            .extension(Extension::new_message(RequestDecryptIdentities)?)
            .await
        {
            identities
                .parse_message::<DecryptIdentities>()?
                .map(|d| d.identities)
                .unwrap_or_default()
        } else {
            vec![]
        };

        Ok::<_, testresult::TestError>((client, identities, decrypt_ids))
    })?;

    let pubkey = &identities[0].pubkey;

    match args {
        Args::Generate { userid } => {
            let subkeys = if let Some(decryption_id) = decrypt_ids.first() {
                let mut keyflags = KeyFlags::default();
                keyflags.set_encrypt_comms(true);
                keyflags.set_encrypt_storage(true);
                let pk = ssh_to_pgp(decryption_id.pubkey.clone(), KeyRole::Decryption);
                vec![pgp::PublicSubkey::new(
                    pgp::packet::PublicSubkey::new(
                        pk.packet_version(),
                        pk.version(),
                        pk.algorithm(),
                        *pk.created_at(),
                        pk.expiration(),
                        pk.public_params().clone(),
                    )?,
                    keyflags,
                )]
            } else {
                vec![]
            };

            let signer = WrappedKey::new(pubkey.clone(), client, KeyRole::Signing);
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
                    vec![CompressionAlgorithm::Uncompressed].into(),
                    None,
                ),
                subkeys,
            );
            let signed_pk = composed_pk.sign(&signer, String::new)?;
            signed_pk.to_writer(&mut std::io::stdout())?;
        }
        Args::Sign => {
            let signer = WrappedKey::new(pubkey.clone(), client, KeyRole::Signing);
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
        Args::Decrypt => {
            let decryptor =
                WrappedKey::new(decrypt_ids[0].pubkey.clone(), client, KeyRole::Decryption);
            let message = Message::from_bytes(std::io::stdin())?;

            let Message::Encrypted { esk, edata } = message else {
                panic!("not encrypted");
            };

            let mpis = if let Esk::PublicKeyEncryptedSessionKey(ref k) = esk[0] {
                k.mpis()
            } else {
                panic!("whoops")
            };

            let (session_key, session_key_algorithm) =
                decryptor.unlock(String::new, |priv_key| priv_key.decrypt(mpis))?;

            let plain_session_key = PlainSessionKey::V4 {
                key: session_key,
                sym_alg: session_key_algorithm,
            };

            let decrypted = edata.decrypt(plain_session_key)?;

            if let Message::Literal(data) = decrypted {
                std::io::stdout().write_all(data.data())?;
            } else {
                eprintln!("decrypted: {:?}", &decrypted);
            }
        }
    }

    Ok(())
}
