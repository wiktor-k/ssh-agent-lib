#![cfg(not(windows))]
//! TPM-backed storage for SSH keys

use std::{fs::File, mem, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use p256::{ecdsa::signature::DigestSigner, NistP256};
use sha2::{Digest as _, Sha256};
use ssh_key::{
    public::{EcdsaPublicKey, KeyData},
    Signature,
};
use tokio::net::UnixListener as Listener;
use tss_esapi::{
    abstraction::transient::{Ecdsa, TransientKeyContextBuilder},
    TctiNameConf,
};

use ssh_agent_lib::{
    agent::{listen, Session},
    error::AgentError,
    proto::{message, Extension, SignRequest},
};

#[derive(Subcommand, Default, Debug)]
enum Command {
    /// Run the agent with the key stored in the TPM.
    #[default]
    Run,
    /// Generate a key on the TPM and store the encrypted private material in the state file.
    ///
    /// The private material is stored on a storage key of the TPM.
    GenerateKey,
}

#[derive(Debug, Parser)]
struct Args {
    /// File where the encrypted private material are to be stored
    #[arg(short, long)]
    state_file: PathBuf,

    /// Path to the listening socket of the ssh agent
    #[arg(short, long, default_value = "ssh-agent.sock")]
    agent_sock: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug)]
struct Inner {
    signer: Ecdsa<'static, NistP256>,
}

#[derive(Clone, Debug)]
struct TpmBackend {
    inner: Arc<Inner>,
}

impl TpmBackend {
    fn new(signer: Ecdsa<'static, NistP256>) -> Self {
        let inner = Inner { signer };

        Self {
            inner: Arc::new(inner),
        }
    }
}

#[crate::async_trait]
impl Session for TpmBackend {
    async fn sign(&mut self, sign_request: SignRequest) -> Result<Signature, AgentError> {
        let data = &sign_request.data;
        let inner: &Inner = &self.inner;

        let signer_key: &p256::ecdsa::VerifyingKey = inner.signer.as_ref();
        let public_key = EcdsaPublicKey::from(signer_key);

        if sign_request.pubkey == KeyData::from(public_key) {
            let mut hash = Sha256::new();
            hash.update(data);

            let signature: p256::ecdsa::Signature = inner
                .signer
                .try_sign_digest(hash)
                .map_err(AgentError::other)?;

            Ok(Signature::try_from(signature).map_err(AgentError::other)?)
        } else {
            Err(std::io::Error::other("Failed to create signature: identity not found").into())
        }
    }

    async fn request_identities(&mut self) -> Result<Vec<message::Identity>, AgentError> {
        let inner: &Inner = &self.inner;

        let signer_key: &p256::ecdsa::VerifyingKey = inner.signer.as_ref();
        let public_key = EcdsaPublicKey::from(signer_key);

        Ok(vec![message::Identity {
            pubkey: public_key.into(),
            comment: "tpm backed key".to_string(),
        }])
    }

    async fn extension(&mut self, _extension: Extension) -> Result<Option<Extension>, AgentError> {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    env_logger::init();
    let args = Args::parse();

    let _ = std::fs::remove_file(&args.agent_sock); // remove the socket if exists

    let conf = TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`");
    let mut ctx = TransientKeyContextBuilder::new()
        .with_tcti(conf)
        .build()
        .map_err(AgentError::other)?;

    match args.command {
        Command::GenerateKey => {
            let (tpm_km, _tpm_auth) = ctx
                .create_key(Ecdsa::<NistP256>::key_params_default(), 0)
                .map_err(AgentError::other)?;

            let mut f = File::create(args.state_file)?;
            postcard::to_io(&tpm_km, &mut f).map_err(AgentError::other)?;
            Ok(())
        }
        Command::Run => {
            let tpm_km = {
                let mut buf = [0; 1024];
                let mut f = File::open(args.state_file)?;
                let (out, _) = postcard::from_io((&mut f, &mut buf)).map_err(AgentError::other)?;
                out
            };

            let signer =
                Ecdsa::<NistP256>::new(&mut ctx, tpm_km, None).map_err(AgentError::other)?;

            // async_trait does not allow us to specify a lifetime for the context
            // we'll downcast the context to a 'static lifetime instead.
            // This is acceptable as the context continues to live beyond the lifetime of the server
            let signer = unsafe { mem::transmute(signer) };

            listen(Listener::bind(args.agent_sock)?, TpmBackend::new(signer)).await?;
            Ok(())
        }
    }
}
