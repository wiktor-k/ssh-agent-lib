use std::fmt;

use futures::{SinkExt, TryStreamExt};
use ssh_key::Signature;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{
    codec::Codec,
    proto::{
        AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, Identity,
        ProtoError, RemoveIdentity, Request, Response, SignRequest, SmartcardKey,
    },
};

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
    async fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
        if let Response::IdentitiesAnswer(identities) =
            self.handle(Request::RequestIdentities).await?
        {
            Ok(identities)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn sign(
        &mut self,
        request: SignRequest,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        if let Response::SignResponse(response) = self.handle(Request::SignRequest(request)).await?
        {
            Ok(response)
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_identity(
        &mut self,
        identity: AddIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::AddIdentity(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::AddIdConstrained(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_identity(
        &mut self,
        identity: RemoveIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::RemoveIdentity(identity)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_all_identities(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::RemoveAllIdentities).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_smartcard_key(
        &mut self,
        key: SmartcardKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::AddSmartcardKey(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        key: AddSmartcardKeyConstrained,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self
            .handle(Request::AddSmartcardKeyConstrained(key))
            .await?
        {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn remove_smartcard_key(
        &mut self,
        key: SmartcardKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::RemoveSmartcardKey(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn lock(&mut self, key: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::Lock(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn unlock(&mut self, key: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::Unlock(key)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn extension(&mut self, extension: Extension) -> Result<(), Box<dyn std::error::Error>> {
        if let Response::Success = self.handle(Request::Extension(extension)).await? {
            Ok(())
        } else {
            Err(ProtoError::UnexpectedResponse.into())
        }
    }

    async fn handle(&mut self, message: Request) -> Result<Response, Box<dyn std::error::Error>> {
        self.adapter.send(message).await?;
        if let Some(response) = self.adapter.try_next().await? {
            Ok(response)
        } else {
            Err(ProtoError::IO(std::io::Error::other("server disconnected")).into())
        }
    }
}
