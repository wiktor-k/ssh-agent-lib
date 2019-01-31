#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub key_type: String,
    pub identifier: String,
    pub key: Vec<u8>
}