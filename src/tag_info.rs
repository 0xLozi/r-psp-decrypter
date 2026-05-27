
pub enum KeyType {
    U32(&'static [u32; 36]),
    U8(&'static [u8; 144]),
}

pub struct TAG_INFO {
    tag: u32,
    key: KeyType,
    code: u8,
    code_extra: u8,
}