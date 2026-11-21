use crate::kirk_lib::kirk_engine::{kirk7};
use crate::error_handling::errors::{KirkError};

pub struct PrxType5 {
    data: [u8;0x150],
}

impl PrxType5 {

    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        
        // 1. tag
        data[0..0x04].copy_from_slice(&prx[0xD0..0xD4]);
        // 2. empty (0x58 bytes de ceros, ya los tiene por inicialización)
        // 3. id
        data[0x5C..0x6C].copy_from_slice(&prx[0x140..0x150]);
        // 4. sha1
        data[0x6C..0x80].copy_from_slice(&prx[0x12C..0x140]);
        // 5. kirkHeader (partido en dos)
        data[0x80..0xB0].copy_from_slice(&prx[0x80..0xB0]);
        data[0xB0..0xC0].copy_from_slice(&prx[0xC0..0xD0]);
        // 6. kirkMetadata
        data[0xC0..0xD0].copy_from_slice(&prx[0xB0..0xC0]);
        // 7. prxHeader
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }

    pub fn tag(&self) -> &[u8] {
        &self.data[0..0x04]
    }

    // data[0xC0..0xD0].copy_from_slice(&prx[0xB0..0xC0]);
    pub fn kirk_metadata(&self) -> &[u8] {
        &self.data[0xC0..0xD0]
    }


    pub fn id(&self) -> &[u8] {
        &self.data[0x5C..0x6C]
    }

    pub fn sha1(&self) -> &[u8] {
        &self.data[0x6C..0x80]
    }

    pub fn kirk_header(&self) -> &[u8] {
        &self.data[0x80..0xC0]
    }

    pub fn prx_header(&self) -> &[u8] {
        &self.data[0xD0..0x150]
    }   

    pub fn empty(&self) -> &[u8] {
        &self.data[0x04..0x5C]
    }

    pub fn decrypt_header(&mut self, key_id: i32, xor1: Option<&[u8]>, xor2: Option<&[u8]>) -> Result<(), KirkError> {
        let mut temp_data: [u8;0x50] = [0u8;0x50];
        temp_data[0..0x40].copy_from_slice(self.kirk_header());
        temp_data[0x40..0x40+0x10].copy_from_slice(&self.sha1()[0..0x10]);

        for i in 0..0x50 {
            if let Some(k1) = xor1 {
                // I do unwrap because is not None, therefore it'll never be Exception Error
                temp_data[i] ^= k1[i % 0x10];
            }

            if let Some(k2) = xor2 {
                temp_data[i] ^= k2[i%0x10];
            }
        }
        kirk7(&mut temp_data, key_id)?;

        // I FORGOT TO COPY THE RESULT BACK
        self.data[0x80..0xC0].copy_from_slice(&temp_data[0..0x40]);
        self.data[0x6C..0x7C].copy_from_slice(&temp_data[0x40..0x50]);

        // copied comment from the original source
        // second step is a XOR then decrypt id through to kirk header

        // 'id' empieza en 0x5C, lo sabemos por los getters...
        let inicio = 0x5C;
        let fin = inicio + 0x60;

        if let Some(k1) = xor1 {
            // Hace XOR sobre los 96 bytes de la memoria principal
            for i in 0..0x60 {
                self.data[inicio + i] ^= k1[i % 0x10];
            }
        }       

        // Segunda pasada del AES directo sobre la memoria principal
        kirk7(&mut self.data[inicio..fin], key_id)?;

        Ok(())
    }


    pub fn is_valid(&self, xorbuf_before_0x10: &[u8;0x10]) -> bool {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();

        hasher.update(self.tag());
        hasher.update(xorbuf_before_0x10);
        hasher.update(self.empty());
        hasher.update(self.id());
        hasher.update(self.kirk_header());
        hasher.update(self.kirk_metadata());
        hasher.update(self.prx_header());

        let hash_calculated = hasher.finalize();
        hash_calculated[..] == self.sha1()[..]
    }
}
