use crate::error_handling::errors::{KirkError};
use crate::kirk_lib::kirk_engine::{kirk7};

pub struct PrxType0 {
    data: [u8;0x150],
}

impl PrxType0 {
    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8;0x150];
        data[0..4].copy_from_slice(&prx[0xD0..0xD0+4]);
        data[4..0x18].copy_from_slice(&prx[0xD4.. 0xD4+0x14]);
        data[0x18..0x40].copy_from_slice(&prx[0xE8.. 0xE8 + 0x28]);
        data[0x40..0x80].copy_from_slice(&prx[0x110..0x110 + 0x40]);
        data[0x80..0xD0].copy_from_slice(&prx[0x80..0xD0]);
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }
    /// Devuelve los 4 bytes del Tag
    #[allow(unused)]
    pub fn tag(&self) -> &[u8] {
        &self.data[0..4]
    }

    /// Devuelve los 20 bytes del SHA-1 original
    pub fn sha1(&self) -> &[u8] {
        &self.data[4..0x18]
    }

    /// Devuelve los 40 bytes sin usar
    pub fn unused(&self) -> &[u8] {
        &self.data[0x18..0x40]
    }

    /// Devuelve el bloque de KIRK entero (Los 144 bytes unidos)
    pub fn kirk_block(&self) -> &[u8] {
        &self.data[0x40..0xD0]
    }

    /// Devuelve la cabecera final del PRX
    pub fn prx_header(&self) -> &[u8] {
        &self.data[0xD0..0x150]
    }

    pub fn decrypt_header(&mut self, xorbuf: &[u8], key_id: i32) -> Result<(), KirkError> {
        // En el Tipo 0, el bloque a desencriptar arranca en el offset 0x40 (kirk_block)
        let inicio = 0x40;
        
        // (XOR antes de desencriptar)
        for i in 0..0x70 {
            self.data[inicio + i] ^= xorbuf[i + 0x14];
        }

        // 2. La carne (KIRK7 procesa 112 bytes / 0x70)
        kirk7(&mut self.data[inicio..inicio + 0x70], key_id)?;

        // 3. Pan de abajo (XOR después de desencriptar)
        for i in 0..0x70 {
            self.data[inicio + i] ^= xorbuf[i + 0x20];
        }

        Ok(())
    }

    /// Valida matemáticamente que la llave es correcta y los datos están íntegros ANTES de desencriptar.
    pub fn is_valid(&self, xorbuf: &[u8]) -> bool {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();

        // La misma receta de licuadora que el Tipo 1
        hasher.update(&xorbuf[0..0x14]);
        hasher.update(self.unused());
        hasher.update(self.kirk_block());
        hasher.update(self.prx_header());

        let hash_calculado = hasher.finalize();

        // Comparamos el resultado con el SHA-1 original del archivo
        hash_calculado[..] == self.sha1()[..]
    }
}
