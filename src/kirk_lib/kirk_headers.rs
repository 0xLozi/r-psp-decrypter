use crate::error_handling::errors::KirkError;
use aes::Aes128;

pub struct KirkCmd1Header {
    pub data: [u8; 0x90],
}

impl KirkCmd1Header {

    // Recibe el kirk_block de 144 recientemente desencriptado
    pub fn new(decrypted_kirk_block: &[u8]) -> Self {
        let mut data = [0u8; 0x90];

        // Copiamos los 144 bytes desencriptados a nuestra estructura
        data.copy_from_slice(&decrypted_kirk_block[0..0x90]);
        Self { data }
    }

    pub fn aes_key(&self) -> &[u8] {
        &self.data[0x00..0x10]
    }

    pub fn cmac_key(&self) -> &[u8] {
        &self.data[0x10..0x20]
    }

    // The all-important header hash for CMD10! (Offset 0x20 to 0x30)
    pub fn cmac_header_hash(&self) -> &[u8] {
        &self.data[0x20..0x30]
    }

    // The data hash for the final CMD10 check (Offset 0x30 to 0x40)
    pub fn cmac_data_hash(&self) -> &[u8] {
        &self.data[0x30..0x40]
    }

    // The 32 bytes of unused padding (Offset 0x40 to 0x60)
    pub fn unused(&self) -> &[u8] {
        &self.data[0x40..0x60]
    }

    pub fn mode(&self) -> Result<u32,KirkError> {
        return Ok(
            u32::from_le_bytes(self.data[0x60..0x64]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
            )
        );
    }

    // If you ever need the raw u8 of ecdsa_hash instead of the boolean
    pub fn ecdsa_hash_raw(&self) -> u8 {
        self.data[0x64]
    }

    pub fn is_ecdsa(&self) -> bool {
        self.data[0x64] == 1
    }

    pub fn data_size(&self) -> Result<u32, KirkError> {
        return Ok (
            u32::from_le_bytes(
                self.data[0x70..0x74]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
            )
        );
    }

    pub fn data_offset(&self) -> Result<u32, KirkError> {
        return Ok(
            u32::from_le_bytes(self.data[0x74..0x78]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
            )
        );
    }

    // Unknown padding 3 (11 bytes, from 0x65 to 0x70)
    pub fn unk3(&self) -> &[u8] {
        &self.data[0x65..0x70]
    }

    // Unknown padding 4 (8 bytes, from 0x78 to 0x80)
    pub fn unk4(&self) -> &[u8] {
        &self.data[0x78..0x80]
    }

    // Unknown padding 5 (16 bytes, finishing out the 0x90 buffer!)
    pub fn unk5(&self) -> &[u8] {
        &self.data[0x80..0x90]
    }

}

// KIRK_CMD1_ECDSA_HEADER* eheader = (KIRK_CMD1_ECDSA_HEADER*) inbuff;
pub struct KirkCmd1EcdsaHeader {
    // something like this, but first let's measure the total size of the buffer combined
    pub data: [u8; 0x90]
}

impl KirkCmd1EcdsaHeader {

    pub fn new(inbuff: &[u8]) -> Self {
        let mut data = [0u8;0x90];
        data.copy_from_slice(inbuff);
        Self { data }
    } 

    pub fn aes_key(&self) -> &[u8] {
        &self.data[0..0x10]
    }

    pub fn header_sig_r(&self) -> &[u8] {
        &self.data[0x10..0x24]
    }

    pub fn header_sig_s(&self) -> &[u8] {
        &self.data[0x24..0x38]
    }

    pub fn data_sig_r(&self) -> &[u8] {
        &self.data[0x38..0x4C]
    }

    pub fn data_sig_s(&self) -> &[u8] {
        &self.data[0x4C..0x60]
    }

    pub fn mode(&self) -> Result<u32,KirkError> {
        return Ok(
            u32::from_le_bytes(self.data[0x60..0x64]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
            )
        );
    }
    
    pub fn ecdsa_hash(&self) -> u8 {
        self.data[0x64]
    }

    // unk3 is an array of 11 bytes, so it goes from 0x65 to 0x70
    pub fn unk3(&self) -> &[u8] {
        &self.data[0x65..0x70]
    }

    pub fn data_size(&self) -> Result<u32, KirkError> {
        Ok(u32::from_le_bytes(
            self.data[0x70..0x74]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
        ))
    }

    pub fn data_offset(&self) -> Result<u32, KirkError> {
        Ok(u32::from_le_bytes(
            self.data[0x74..0x78]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
        ))
    }

    pub fn unk4(&self) -> &[u8] {
        &self.data[0x78..0x80]
    }

    // unk5 is the final 16 bytes, which leads to push us exactly to the 0x90 limit!!!!!!!!!!!!!!!!!!1
    pub fn unk5(&self) -> &[u8] {
        &self.data[0x80..0x90]
    }
}


pub struct Kirk_Aes128CBC_Header {
    data: [u8;0x14],
}
impl Kirk_Aes128CBC_Header {
    pub fn new(inbuff: &[u8]) -> Self {
        let mut data = [0u8;0x14];
        data.copy_from_slice(&inbuff[..0x14]);

        Self {
            data
        }
    }

    pub fn mode(&self) -> u32 {
        u32::from_le_bytes(self.data[0..4].try_into().unwrap())
    }

    pub fn unk_4(&self) -> u32 {
        u32::from_le_bytes(self.data[4..8].try_into().unwrap())
    }

    pub fn unk_8(&self) -> u32 {
        u32::from_le_bytes(self.data[8..0xC].try_into().unwrap())
    }

    pub fn keyseed(&self) -> u32 {
        u32::from_le_bytes(self.data[0xC..0x10].try_into().unwrap())

    }

    pub fn data_size(&self) -> u32 {
        u32::from_le_bytes(self.data[0x10..0x14].try_into().unwrap())

    }

}









// inside the original tool it says this: small struct for temporary keeping AES & CMAC key from CMD1 header
pub struct HeaderKeys {
    pub aes: [u8;16],
    pub cmac: [u8;16],
}

impl HeaderKeys {
    pub fn new(slice: &[u8;32]) -> Self {
        let aes = slice[0..16].try_into().unwrap();
        let cmac = slice[16..32].try_into().unwrap();

        Self {
            aes,
            cmac
        }
    }
}

pub struct kirk_ctx {
    pub is_kirk_initialized: u8,
    pub aes_kirk1: ,
}
impl kirk_ctx {
    pub fn new() -> Self {
        let is_kirk_initialized: u8 = 0;
        Self { is_kirk_initialized }
    }
}



pub struct KirkCtx { 
    pub is_kirk_initialized: u8,
    pub aes_kirk1: Aes128,
}

