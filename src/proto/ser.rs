use super::error::{ProtoError, ProtoResult};
use byteorder::{BigEndian, WriteBytesExt};
use serde::ser::{self, Serialize};
use std::io;

#[derive(Debug)]
pub struct Serializer<W: io::Write> {
    // This string starts empty and JSON is appended as values are serialized.
    writer: W,
}

impl<W: io::Write> Serializer<W> {
    pub fn from_writer(writer: W) -> Self {
        Self { writer }
    }
}

impl<'a, W: io::Write> ser::Serializer for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> ProtoResult<()> {
        unimplemented!()
    }

    fn serialize_i8(self, v: i8) -> ProtoResult<()> {
        self.writer.write_i8(v).map_err(Into::into)
    }

    fn serialize_i16(self, v: i16) -> ProtoResult<()> {
        self.writer.write_i16::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_i32(self, v: i32) -> ProtoResult<()> {
        self.writer.write_i32::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_i64(self, v: i64) -> ProtoResult<()> {
        self.writer.write_i64::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_u8(self, v: u8) -> ProtoResult<()> {
        self.writer.write_u8(v).map_err(Into::into)
    }

    fn serialize_u16(self, v: u16) -> ProtoResult<()> {
        self.writer.write_u16::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_u32(self, v: u32) -> ProtoResult<()> {
        self.writer.write_u32::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_u64(self, v: u64) -> ProtoResult<()> {
        self.writer.write_u64::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_f32(self, v: f32) -> ProtoResult<()> {
        self.writer.write_f32::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_f64(self, v: f64) -> ProtoResult<()> {
        self.writer.write_f64::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_char(self, _v: char) -> ProtoResult<()> {
        unimplemented!()
    }

    fn serialize_str(self, v: &str) -> ProtoResult<()> {
        (v.len() as u32).serialize(&mut *self)?;
        self.serialize_bytes(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> ProtoResult<()> {
        self.writer.write_all(v).map_err(Into::into)
    }

    fn serialize_none(self) -> ProtoResult<()> {
        unimplemented!()
    }

    fn serialize_some<T>(self, _value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn serialize_unit(self) -> ProtoResult<()> {
        unimplemented!()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> ProtoResult<()> {
        unimplemented!()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> ProtoResult<()> {
        (variant_index as u8).serialize(self)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut *self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        (variant_index as u8).serialize(&mut *self)?;
        value.serialize(&mut *self)
    }

    fn serialize_seq(self, len: Option<usize>) -> ProtoResult<Self::SerializeSeq> {
        if let Some(len) = len {
            (len as u32).serialize(&mut *self).map(|()| self)
        } else {
            unimplemented!()
        }
    }

    fn serialize_tuple(self, _len: usize) -> ProtoResult<Self::SerializeTuple> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> ProtoResult<Self::SerializeTupleStruct> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> ProtoResult<Self::SerializeTupleVariant> {
        (variant_index as u8).serialize(&mut *self)?;
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> ProtoResult<Self::SerializeMap> {
        unimplemented!()
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> ProtoResult<Self::SerializeStruct> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> ProtoResult<Self::SerializeStructVariant> {
        Ok(self)
    }
}

impl<'a, W: io::Write> ser::SerializeSeq for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_element<T>(&mut self, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

impl<'a, W: io::Write> ser::SerializeTuple for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_element<T>(&mut self, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

impl<'a, W: io::Write> ser::SerializeTupleStruct for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_field<T>(&mut self, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

impl<'a, W: io::Write> ser::SerializeTupleVariant for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_field<T>(&mut self, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

impl<'a, W: io::Write> ser::SerializeMap for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_key<T>(&mut self, _key: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn serialize_value<T>(&mut self, _value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn end(self) -> ProtoResult<()> {
        unimplemented!()
    }
}

impl<'a, W: io::Write> ser::SerializeStruct for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

impl<'a, W: io::Write> ser::SerializeStructVariant for &'a mut Serializer<W> {
    type Ok = ();
    type Error = ProtoError;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> ProtoResult<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> ProtoResult<()> {
        Ok(())
    }
}

pub fn to_bytes<T: Serialize>(value: &T) -> ProtoResult<Vec<u8>> {
    let mut serializer = Serializer::from_writer(Vec::new());
    value.serialize(&mut serializer)?;
    Ok(serializer.writer)
}
