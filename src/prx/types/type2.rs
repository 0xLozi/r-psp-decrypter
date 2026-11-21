use sha1::{Sha1, Digest};
use crate::kirk_lib::kirk_engine::{kirk7};
use crate::error_handling::errors::{KirkError};

pub struct PrxType2 {
    data: [u8; 0x150],
}

impl PrxType2 {
    const TAG: std::ops::Range<usize>       = 0x00..0x04;
    const EMPTY: std::ops::Range<usize>     = 0x04..0x5C;
    const ID: std::ops::Range<usize>        = 0x5C..0x6C;
    const SHA1: std::ops::Range<usize>      = 0x6C..0x80;
    const KIRK_HDR: std::ops::Range<usize>  = 0x80..0xC0;
    const KIRK_META: std::ops::Range<usize> = 0xC0..0xD0;
    const PRX_HDR: std::ops::Range<usize>   = 0xD0..0x150;

    pub fn new(prx: &[u8]) -> Self {
        // Definimos el mapa de memoria estático para no tener que usar números mágicos...
        let mut data = [0u8; 0x150];

        data[Self::TAG].copy_from_slice(&prx[0xD0..0xD4]);
        data[Self::ID].copy_from_slice(&prx[0x140..0x150]);
        data[Self::SHA1].copy_from_slice(&prx[0x12C..0x140]);

        // This is the kirk header that was split into two...
        data[0x80..0xB0].copy_from_slice(&prx[0x80..0xB0]);
        data[0xB0..0xC0].copy_from_slice(&prx[0xC0..0xD0]);

        data[Self::KIRK_META].copy_from_slice(&prx[0xB0..0xC0]);
        data[Self::PRX_HDR].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }

    pub fn decrypt(&mut self, key_id: i32) -> Result<(), KirkError> {
        let start = Self::ID.start;
        let decrypt_block = &mut self.data[start .. start + 0x60];

        kirk7(decrypt_block, key_id)?;

        Ok(())
    }

    // TO-DO: Implementar esto
    pub fn is_valid(&self, xorbuf: &[u8]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(self.tag());
        hasher.update(&xorbuf[0..0x10]);
        hasher.update(self.empty());
        hasher.update(self.id());
        hasher.update(self.kirk_header());
        hasher.update(self.kirk_metadata());
        hasher.update(self.prx_header());
        let hash_calculated = hasher.finalize();

        hash_calculated[..] == self.sha1()[..]
    }

    pub fn tag(&self) -> &[u8] { &self.data[Self::TAG] }
    pub fn id(&self) -> &[u8] { &self.data[Self::ID] }
    pub fn sha1(&self) -> &[u8] { &self.data[Self::SHA1] }
    pub fn kirk_header(&self) -> &[u8] { &self.data[Self::KIRK_HDR] }
    pub fn prx_header(&self) -> &[u8] { &self.data[Self::PRX_HDR] }
    pub fn empty(&self) -> &[u8] { &self.data[Self::EMPTY] }
    pub fn kirk_metadata(&self) -> &[u8] { &self.data[Self::KIRK_META] }

}
