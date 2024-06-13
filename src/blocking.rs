//! Blocking SSH agent client API.
//!
//! Blocking API is always enabled since it doesn't use additional
//! dependencies over what is in the `proto` module and Rust standard
//! library.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(unix)]
//! # fn main() -> testresult::TestResult {
//! use std::os::unix::net::UnixStream;
//!
//! use ssh_agent_lib::blocking::Client;
//!
//! let mut client = Client::new(UnixStream::connect(std::env::var("SSH_AUTH_SOCK")?)?);
//!
//! eprintln!(
//!     "Identities that this agent knows of: {:#?}",
//!     client.request_identities()?
//! );
//! # Ok(()) }
//! # #[cfg(windows)] fn main() { }
//! ```

use std::io::{Read, Write};

use byteorder::{BigEndian, ByteOrder};
use ssh_encoding::{Decode, Encode};
use ssh_key::Signature;

use crate::{
    error::AgentError,
    proto::{
        AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, Identity,
        ProtoError, RemoveIdentity, Request, Response, SignRequest, SmartcardKey,
    },
};

/// Blocking SSH agent client.
#[derive(Debug)]
pub struct Client<S: Read + Write> {
    stream: S,
}

impl<S: Read + Write> Client<S> {
    /// Construct a new SSH agent client for the given transport stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Extracts inner stream by consuming this object.
    pub fn into_inner(self) -> S {
        self.stream
    }

    fn handle(&mut self, request: Request) -> Result<Response, ProtoError> {
        // send the request
        let mut bytes = Vec::new();
        let len = request.encoded_len()? as u32;
        len.encode(&mut bytes)?;
        request.encode(&mut bytes)?;
        self.stream.write_all(&bytes)?;

        // read the response
        let mut len: [u8; 4] = [0; 4];
        self.stream.read_exact(&mut len[..])?;
        let len = BigEndian::read_u32(&len) as usize;
        bytes.resize(len, 0);
        self.stream.read_exact(&mut bytes)?;

        Response::decode(&mut &bytes[..])
    }

    /// Request a list of keys managed by this session.
    pub fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        if let Response::IdentitiesAnswer(identities) = self.handle(Request::RequestIdentities)? {
            Ok(identities)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Perform a private key signature operation.
    pub fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if let Response::SignResponse(response) = self.handle(Request::SignRequest(request))? {
            Ok(response)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Add a private key to the agent.
    pub fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddIdentity(identity))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Add a private key to the agent with a set of constraints.
    pub fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddIdConstrained(identity))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Remove private key from an agent.
    pub fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveIdentity(identity))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Remove all keys from an agent.
    pub fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveAllIdentities)? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Add a key stored on a smartcard.
    pub fn add_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddSmartcardKey(key))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Add a key stored on a smartcard with a set of constraints.
    pub fn add_smartcard_key_constrained(
        &mut self,
        key: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddSmartcardKeyConstrained(key))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Remove a smartcard key from the agent.
    pub fn remove_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveSmartcardKey(key))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Temporarily lock the agent with a password.
    pub fn lock(&mut self, key: String) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::Lock(key))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Unlock the agent with a password.
    pub fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::Unlock(key))? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    /// Invoke a custom, vendor-specific extension on the agent.
    pub fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        match self.handle(Request::Extension(extension))? {
            Response::Success => Ok(None),
            Response::ExtensionResponse(response) => Ok(Some(response)),
            _ => Err(ProtoError::UnexpectedResponse.into()),
        }
    }
}
