use crate::error_handling::errors::KirkError;

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

    pub fn mode(&self) -> Result<u32,KirkError> {
        return Ok(
            u32::from_le_bytes(self.data[0x60..0x64]
                .try_into()
                .map_err(|_| KirkError::ConversionFailed)?
            )
        );
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
}