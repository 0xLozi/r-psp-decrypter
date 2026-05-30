
// THIS IS DECRYPTION 1 
pub enum KeyType {
    U32(&'static [u32; 36]),
    U8(&'static [u8; 144]),
}

pub struct TAG_INFO {
    pub tag: u32,
    pub key: KeyType,
    pub code: u8,
    pub code_extra: u8,
}

// THIS IS DECRYPTION 2
pub struct TAG_INFO2 {
    pub tag: u32,
    pub key: &'static [u8; 16],
    pub code: u8,
    pub type_code: Option<u8>,
    pub seed: Option<&'static [u8; 144]>,
}