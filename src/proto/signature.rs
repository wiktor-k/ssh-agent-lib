pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    pub blob: Vec<u8>
}