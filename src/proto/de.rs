use byteorder::{BigEndian, ReadBytesExt};
use std::io;

use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, 
    SeqAccess, VariantAccess, Visitor,
};

use super::error::{ProtoError, ProtoResult};

#[derive(Debug)]
pub struct Deserializer<R: io::Read> {
    reader: R,
}

impl<R: io::Read> Deserializer<R> {
    pub fn from_reader(reader: R) -> Self {
        Deserializer {
            reader: reader
        }
    }
    
    pub fn to_reader(self) -> R {
        self.reader
    }
    
    fn read_buf(&mut self) -> ProtoResult<Vec<u8>> {
        let len = self.reader.read_u32::<BigEndian>()?;
        let mut buf = vec![0; len as usize];
        self.reader.read_exact(&mut buf)?;
        return Ok(buf);
    }
}

pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &[u8]) -> ProtoResult<T> {
    let mut deserializer = Deserializer::from_reader(bytes);
    let result = T::deserialize(&mut deserializer)?;
    let remaining_bytes = deserializer.to_reader();
    
    if remaining_bytes.len() == 0 {
        Ok(result)
    } else {
        Err(ProtoError::Deserialization(
            format!("Buffer not depleted. Remaining bytes: {:?}", remaining_bytes)
        ))
    }
}

impl<'de, 'a, R: io::Read> de::Deserializer<'de> for &'a mut Deserializer<R> {
    type Error = ProtoError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        let mut bytes = vec![];
        self.reader.read_to_end(&mut bytes)?;
        visitor.visit_byte_buf(bytes)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_bool(self.reader.read_u8()? > 0)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_i8(self.reader.read_i8()?)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_i16(self.reader.read_i16::<BigEndian>()?)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_i32(self.reader.read_i32::<BigEndian>()?)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_i64(self.reader.read_i64::<BigEndian>()?)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_u8(self.reader.read_u8()?)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_u16(self.reader.read_u16::<BigEndian>()?)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_u32(self.reader.read_u32::<BigEndian>()?)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_u64(self.reader.read_u64::<BigEndian>()?)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_f32(self.reader.read_f32::<BigEndian>()?)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_f64(self.reader.read_f64::<BigEndian>()?)
    }

    fn deserialize_char<V: Visitor<'de>>(self, _visitor: V) -> ProtoResult<V::Value> {
        unimplemented!()
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_string(String::from_utf8(self.read_buf()?)?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_string(String::from_utf8(self.read_buf()?)?)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_byte_buf(self.read_buf()?)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_byte_buf(self.read_buf()?)
    }

    fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> ProtoResult<V::Value> {
        unimplemented!()
    }

    fn deserialize_unit<V: Visitor<'de>>(self, _visitor: V) -> ProtoResult<V::Value> {
        unimplemented!()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> ProtoResult<V::Value> {
        unimplemented!()
    }
    
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> ProtoResult<V::Value> {
        visitor.visit_newtype_struct(self)
    }
    
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        let len = self.reader.read_u32::<BigEndian>()? as usize;
        visitor.visit_seq(BinarySeq::new(len, &mut *self))
    }
    
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> ProtoResult<V::Value> {
        visitor.visit_seq(BinarySeq::new(len, &mut *self))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> ProtoResult<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> ProtoResult<V::Value> {
        unimplemented!()
    }
    
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> ProtoResult<V::Value> {
        visitor.visit_seq(BinarySeq::new(fields.len(), &mut *self))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> ProtoResult<V::Value> {
        visitor.visit_enum(BinaryEnum::new(&mut *self))
    }
    
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        self.deserialize_str(visitor)
    }
    
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> ProtoResult<V::Value> {
        self.deserialize_any(visitor)
    }
}

struct BinarySeq<'a, R: io::Read> {
    remaining: usize,
    de: &'a mut Deserializer<R>
}

impl<'a, R: io::Read> BinarySeq<'a, R> {
    fn new(remaining: usize, de: &'a mut Deserializer<R>) -> Self {
        BinarySeq {
            remaining: remaining,
            de: de
        }
    }
}

impl<'de, 'a, R: io::Read> SeqAccess<'de> for BinarySeq<'a, R> {
    type Error = ProtoError;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> ProtoResult<Option<T::Value>> {
        if self.remaining > 0 {
            self.remaining -= 1;
            seed.deserialize(&mut *self.de).map(Some)
        } else {
            Ok(None)
        }
    }
}

struct BinaryEnum<'a, R: io::Read> {
    de: &'a mut Deserializer<R>,
}

impl<'a, R: io::Read> BinaryEnum<'a, R> {
    fn new(de: &'a mut Deserializer<R>) -> Self {
        BinaryEnum {
            de: de
        }
    }
}

impl<'de, 'a, R: io::Read> EnumAccess<'de> for BinaryEnum<'a, R> {
    type Error = ProtoError;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> ProtoResult<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        let index: u8 = de::Deserialize::deserialize(&mut *self.de)?;
        let value: ProtoResult<_> = seed.deserialize(index.into_deserializer());
        Ok((value?, self))
    }
}

impl<'de, 'a, R: io::Read> VariantAccess<'de> for BinaryEnum<'a, R> {
    type Error = ProtoError;

    fn unit_variant(self) -> ProtoResult<()> {
        Ok(())
    }
    
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> ProtoResult<T::Value> {
        seed.deserialize(self.de)
    }
    
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> ProtoResult<V::Value> {
        de::Deserializer::deserialize_seq(self.de, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> ProtoResult<V::Value> {
        de::Deserializer::deserialize_map(self.de, visitor)
    }
}