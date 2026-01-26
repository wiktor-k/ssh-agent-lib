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

use std::io::BufReader;

use clap::Parser;
use pgp::{
    composed::{
        Esk, KeyDetails as ComposedKeyDetails, Message, PlainSessionKey, SignedPublicKey,
        SignedPublicSubKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags, PacketTrait, PublicKey, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData, UserId,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, EcdhPublicParams, EddsaLegacyPublicParams, EncryptionKey, EskType,
        Fingerprint, KeyDetails, KeyVersion, Mpi, Password, PkeskBytes, PublicParams,
        SignatureBytes, SigningKey, VerifyingKey,
    },
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
            KeyRole::Signing => PublicKeyAlgorithm::EdDSALegacy,
            KeyRole::Decryption => PublicKeyAlgorithm::ECDH,
        }
    }
}

fn ssh_to_pgp(pubkey: KeyData, key_role: KeyRole) -> PublicKey {
    let KeyData::Ed25519(key) = pubkey.clone() else {
        panic!("The first key was not ed25519!");
    };

    /*
    let mut key_bytes = key.0.to_vec();
    // Add prefix to mark that this MPI uses EdDSA point representation.
    // See https://datatracker.ietf.org/doc/draft-koch-eddsa-for-openpgp/
    key_bytes.insert(0, 0x40);
    */

    let public_params = match key_role {
        /*
        KeyRole::Signing => PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Unsupported {
            curve: ECCCurve::Ed25519,
            opaque: key_bytes.into(),
        }),
        */
        KeyRole::Signing => PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
            key: key.try_into().expect("invalid Ed25519 key"),
        }),
        // most common values taken from
        // https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463
        KeyRole::Decryption => PublicParams::ECDH(EcdhPublicParams::Curve25519 {
            p: key.0.into(),
            hash: HashAlgorithm::Sha256,
            alg_sym: pgp::crypto::sym::SymmetricKeyAlgorithm::AES128,
            ecdh_kdf_type: pgp::types::EcdhKdfType::Native,
        }),
    };

    PublicKey::new(
        KeyVersion::V4,
        key_role.into(),
        // use fixed date (2016-09-06T17:00:00+02:00) so that the fingerprint generation is
        // deterministic
        pgp::types::Timestamp::from_secs(1473174000),
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
        key: &PkeskBytes,
    ) -> pgp::errors::Result<(Vec<u8>, pgp::crypto::sym::SymmetricKeyAlgorithm)> {
        if let PublicParams::ECDH(params @ EcdhPublicParams::Curve25519 { hash, alg_sym, .. }) =
            self.public_key.public_params()
        {
            let PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            } = key
            else {
                unimplemented!("{key:?} not PkeskBytes::Ecdh")
            };

            let ciphertext = public_point.as_ref();

            assert_eq!(
                ciphertext[0], 0x40,
                "Unexpected shape of Cv25519 encrypted data"
            );

            // Strip leading 0x40
            let ciphertext = &ciphertext[1..];

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

            let decrypted_key = pgp::crypto::ecdh::derive_session_key(
                shared_secret,
                encrypted_session_key,
                encrypted_session_key.len(),
                params.curve(),
                *hash,
                *alg_sym,
                self.public_key.fingerprint().as_ref(),
            )?;

            // strip off the leading session key algorithm octet, and the two trailing checksum octets
            let dec_len = decrypted_key.len();
            let (sessionkey, checksum) = (
                &decrypted_key[1..dec_len - 2],
                decrypted_key[dec_len - 2..].try_into().expect("len == 2"),
            );

            // ... check the checksum, while we have it at hand
            pgp::crypto::checksum::simple(checksum, sessionkey)?;

            let session_key_algorithm = decrypted_key[0].into();
            Ok((sessionkey.to_vec(), session_key_algorithm))
        } else {
            unimplemented!("PublicParams::ECDH(EcdhPublicParams::Curve25519)");
        }
    }
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedKey")
    }
}

impl KeyDetails for WrappedKey {
    fn version(&self) -> KeyVersion {
        self.public_key.version()
    }

    fn legacy_key_id(&self) -> pgp::types::KeyId {
        self.public_key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> pgp::types::Timestamp {
        self.public_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.public_key.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

impl EncryptionKey for WrappedKey {
    fn encrypt<R: rand::CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plain: &[u8],
        typ: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        self.public_key.encrypt(rng, plain, typ)
    }
}

impl SigningKey for WrappedKey {
    fn sign(
        &self,
        _key_pw: &pgp::types::Password,
        _hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
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

        Ok(SignatureBytes::Mpis(vec![
            Mpi::from_slice(&sig[..32]),
            Mpi::from_slice(&sig[32..]),
        ]))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

impl VerifyingKey for WrappedKey {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        self.public_key.verify(hash, data, sig)
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

    let mut rng = rand::rng();
    let pubkey = &identities[0].pubkey;

    match args {
        Args::Generate { userid } => {
            let signer = WrappedKey::new(pubkey.clone(), client, KeyRole::Signing);
            let subkeys = if let Some(decryption_id) = decrypt_ids.first() {
                let mut keyflags = KeyFlags::default();
                keyflags.set_encrypt_comms(true);
                keyflags.set_encrypt_storage(true);
                let sub_pk = ssh_to_pgp(decryption_id.pubkey.clone(), KeyRole::Decryption);
                let pgp_pk = pgp::packet::PublicSubkey::new(
                    sub_pk.version(),
                    sub_pk.algorithm(),
                    sub_pk.created_at(),
                    sub_pk.expiration(),
                    sub_pk.public_params().clone(),
                )?;
                let sub_pk_sig = pgp_pk.sign(
                    &mut rng,
                    &signer,
                    &signer.public_key,
                    &Password::empty(),
                    keyflags,
                    None,
                )?;
                let signed_sub_pk = SignedPublicSubKey::new(pgp_pk, vec![sub_pk_sig]);
                vec![signed_sub_pk]
            } else {
                vec![]
            };

            let mut keyflags = KeyFlags::default();
            keyflags.set_sign(true);
            keyflags.set_certify(true);

            let composed_pk_details = ComposedKeyDetails::new(
                Some(UserId::from_str(Default::default(), &userid)?),
                vec![],
                vec![],
                keyflags,
                Default::default(),
                Default::default(),
                Default::default(),
                vec![CompressionAlgorithm::Uncompressed].into(),
                vec![].into(),
            );
            let signed_pk = SignedPublicKey::bind_with_signing_key(
                &mut rng,
                &signer,
                signer.public_key.clone(),
                composed_pk_details,
                &Password::empty(),
                subkeys,
            )?;
            signed_pk.to_writer(&mut std::io::stdout())?;
        }
        Args::Sign => {
            let signer = WrappedKey::new(pubkey.clone(), client, KeyRole::Signing);
            let signature_config = {
                let mut config =
                    SignatureConfig::from_key(&mut rng, &signer, SignatureType::Binary)?;
                config.hash_alg = HashAlgorithm::Sha256;
                config.hashed_subpackets = vec![
                    Subpacket::regular(SubpacketData::SignatureCreationTime(
                        pgp::types::Timestamp::now(),
                    ))?,
                    Subpacket::regular(SubpacketData::IssuerKeyId(signer.legacy_key_id()))?,
                    Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
                ];
                config
            };

            let mut hasher = signature_config.hash_alg.new_hasher()?;

            signature_config.hash_data_to_sign(&mut hasher, std::io::stdin())?;
            let len = signature_config.hash_signature_data(&mut hasher)?;
            hasher.update(&signature_config.trailer(len)?);

            let hash = &hasher.finalize()[..];

            let signed_hash_value = [hash[0], hash[1]];
            let raw_sig = signer.sign(&Password::empty(), signature_config.hash_alg, hash)?;

            let signature = Signature::from_config(signature_config, signed_hash_value, raw_sig)?;
            signature.to_writer_with_header(&mut std::io::stdout())?;
        }
        Args::Decrypt => {
            let decryptor =
                WrappedKey::new(decrypt_ids[0].pubkey.clone(), client, KeyRole::Decryption);
            // Make our own BufReader for Stdin, because Stdin::lock() is !Send due to its
            // MutexGuard
            let source = BufReader::new(std::io::stdin());
            let message = Message::from_bytes(source)?;

            let Message::Encrypted { ref esk, .. } = message else {
                panic!("not encrypted");
            };

            let esk_bytes = if let Esk::PublicKeyEncryptedSessionKey(ref k) = esk[0] {
                k.values()?
            } else {
                panic!("whoops")
            };

            let (session_key, session_key_algorithm) = decryptor.decrypt(esk_bytes)?;

            let plain_session_key = PlainSessionKey::V3_4 {
                key: session_key.into(),
                sym_alg: session_key_algorithm,
            };

            let mut decrypted = message.decrypt_with_session_key(plain_session_key)?;

            if let Message::Literal { ref mut reader, .. } = decrypted {
                std::io::copy(reader, &mut std::io::stdout())?;
            } else {
                eprintln!("decrypted: {:?}", &decrypted);
            }
        }
    }

    Ok(())
}
