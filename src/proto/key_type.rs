pub trait KeyTypeEnum {
    fn key_type(&self) -> String;
}

pub trait KeyType {
    const KEY_TYPE: &'static str;
    fn key_type(&self) -> String {
        Self::KEY_TYPE.to_string()
    }
}

macro_rules! impl_key_type_enum_ser_de {
    ($class_name:path, $(($variant_name:path, $variant_class:ty)),* ) => {
        impl KeyTypeEnum for $class_name {
            fn key_type(&self) -> String {
                match self {
                    $($variant_name(key) => key.key_type()),*
                }
            }
        }
        
        impl Serialize for $class_name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut serialize_tuple = serializer.serialize_tuple(2)?;
                
                match self {
                    $(
                        $variant_name(key) => {
                            serialize_tuple.serialize_element(&key.key_type())?;
                            serialize_tuple.serialize_element(key)?;
                        }
                    ),*
                };
                serialize_tuple.end()
            }
        }
        
        impl<'de> Deserialize<'de> for $class_name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$class_name, D::Error> {
                struct KeyVisitor;
                
                impl<'de> serde::de::Visitor<'de> for KeyVisitor {
                    type Value = $class_name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("Key with format (type, key)")
                    }

                    fn visit_seq<V: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: V
                    ) -> Result<Self::Value, V::Error> {
                        let key_type: String = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                        let key_type_str = key_type.as_str();
                        
                        $(
                            if key_type_str.starts_with(<$variant_class>::KEY_TYPE) {
                                let key: $variant_class = seq.next_element()?
                                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                                return Ok($variant_name(key))
                            }
                        )*
                        
                        return Err(Error::custom(ProtoError::UnexpectedVariant));
                    }
                }
                
                deserializer.deserialize_tuple(2, KeyVisitor)
            }
        }
    };
}