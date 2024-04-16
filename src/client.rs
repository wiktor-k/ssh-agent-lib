//! SSH agent client support.

use std::fmt;

use futures::{SinkExt, TryStreamExt};
use ssh_key::Signature;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{
    codec::Codec,
    error::AgentError,
    proto::{
        AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, Identity,
        ProtoError, RemoveIdentity, Request, Response, SignRequest, SmartcardKey,
    },
};

/// SSH agent client
#[derive(Debug)]
pub struct Client<Stream>
where
    Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    adapter: Framed<Stream, Codec<Response, Request>>,
}

impl<Stream> Client<Stream>
where
    Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SSH agent client wrapping a given socket.
    pub fn new(socket: Stream) -> Self {
        let adapter = Framed::new(socket, Codec::default());
        Self { adapter }
    }
}

#[async_trait::async_trait]
impl<Stream> crate::agent::Session for Client<Stream>
where
    Stream: fmt::Debug + AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        if let Response::IdentitiesAnswer(identities) =
            self.handle(Request::RequestIdentities).await?
        {
            Ok(identities)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if let Response::SignResponse(response) = self.handle(Request::SignRequest(request)).await?
        {
            Ok(response)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddIdentity(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddIdConstrained(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveIdentity(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveAllIdentities).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::AddSmartcardKey(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        key: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        if let Response::Success = self
            .handle(Request::AddSmartcardKeyConstrained(key))
            .await?
        {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::RemoveSmartcardKey(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn lock(&mut self, key: String) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::Lock(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        if let Response::Success = self.handle(Request::Unlock(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        match self.handle(Request::Extension(extension)).await? {
            Response::Success => Ok(None),
            Response::ExtensionResponse(response) => Ok(Some(response)),
            _ => Err(ProtoError::UnexpectedResponse.into()),
        }
    }

    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        self.adapter.send(message).await?;
        if let Some(response) = self.adapter.try_next().await? {
            Ok(response)
        } else {
            Err(ProtoError::IO(std::io::Error::other("server disconnected")).into())
        }
    }
}
