use std::marker::PhantomData;
use std::mem::size_of;

use byteorder::{BigEndian, ReadBytesExt};
use ssh_encoding::{Decode, Encode};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::error::AgentError;
use super::proto::ProtoError;

/// SSH framing codec.
///
/// This codec first reads an `u32` which indicates the length of the incoming
/// message. Then decodes the message using specified `Input` type.
///
/// The reverse transformation which appends the length of the encoded data
/// is also implemented for the given `Output` type.
#[derive(Debug)]
pub struct Codec<Input, Output>(PhantomData<Input>, PhantomData<Output>)
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>;

impl<Input, Output> Default for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    fn default() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<Input, Output> Decoder for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    type Item = Input;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut bytes = &src[..];

        if bytes.len() < size_of::<u32>() {
            return Ok(None);
        }

        let length = bytes.read_u32::<BigEndian>()? as usize;

        if bytes.len() < length {
            return Ok(None);
        }

        let message = Self::Item::decode(&mut bytes)?;
        src.advance(size_of::<u32>() + length);
        Ok(Some(message))
    }
}

impl<Input, Output> Encoder<Output> for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    AgentError: From<Input::Error>,
{
    type Error = AgentError;

    fn encode(&mut self, item: Output, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut bytes = Vec::new();

        let len = item.encoded_len().unwrap() as u32;
        len.encode(&mut bytes).map_err(ProtoError::SshEncoding)?;

        item.encode(&mut bytes).map_err(ProtoError::SshEncoding)?;
        dst.put(&*bytes);

        Ok(())
    }
}
