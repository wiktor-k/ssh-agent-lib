pub trait KeyTypeEnum {
    fn key_type(&self) -> String;
}

pub trait KeyType {
    const KEY_TYPE: &'static str;
    fn key_type(&self) -> String {
        Self::KEY_TYPE.to_string()
    }
}
