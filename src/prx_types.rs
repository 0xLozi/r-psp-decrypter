use crate::error_handling::errors::{KirkError};
use crate::kirk_lib::kirk_engine::kirk7;
use sha1::{Sha1, Digest};

/// Representa la cabecera de un archivo PRX o EBOOT de Tipo 1 (Ej: Lego Batman).
///
/// # Diseño de Memoria: 
/// En el código original de C++, la estructura estaba dividida en campos separados
/// (tag, sha1, unused, kirkBlock, entre otros...). Al desencriptar, C++ hacía un truco medio que no se puede hacer en Rust xd:
/// le pasaba el puntero del campo `sha1` al motor AES y le pedía que desencriptara tambien ese (cuando le estaba pasando el puntero id)
/// 160 bytes (0xA0) hacia adelante, desbordando el arreglo y pisando los campos vecinos.
/// 
/// En Rust, esto causaría un pánico de seguridad (Out of Bounds). Para solucionarlo de
/// forma segura, cargamos toda la cabecera en un solo bloque CONTIGUO
/// de 336 bytes (0x150). Luego usamos "slices" (referencias a rangos exactos) para
/// leer o desencriptar partes específicas sin violar la seguridad de la memoria.
pub struct PrxType1 {
    pub data: [u8; 0x150],
}

impl PrxType1 {
    /// Construye un nuevo PrxType1 a partir de los datos crudos del archivo.
    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        
        // utilizamos los offsets del C++ original:
        data[0..4].copy_from_slice(&prx[0xD0..0xD4]);       // tag
        data[4..0x18].copy_from_slice(&prx[0xD4..0xE8]);    // sha1 (20 bytes / 0x14)
        data[0x18..0x40].copy_from_slice(&prx[0xE8..0x110]); // unused (40 bytes / 0x28)
        data[0x40..0x80].copy_from_slice(&prx[0x110..0x150]);// kirkBlock parte 1 (64 bytes / 0x40)
        data[0x80..0xD0].copy_from_slice(&prx[0x80..0xD0]);  // kirkBlock parte 2
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);    // prxHeader (128 bytes / 0x80)

        Self { data }
    }

    pub fn decrypt(&mut self, key_id: i32) -> Result<(), KirkError> {
        // En C++ la firma era: kirk7(sha1+0xC, sha1+0xC, 0xA0, key);
        // Nuestro 'sha1' empieza en el offset 4.
        // 4 + 12 (0xC) = 16 (0x10).
        // Si queremos desencriptar 160 bytes (0xA0): 16 + 160 = 176 (0xB0).
        
        // Rust nos obliga a ser explicito y seguros...
        kirk7(&mut self.data[0x10..0xB0], key_id)?;
        
        Ok(())
    }

    pub fn tag(&self) -> &[u8] {
        &self.data[0..4]
    }

    pub fn sha1(&self) -> &[u8] {
        &self.data[4..0x18]
    }

    /// Returns 40 unused bytes
    pub fn unused(&self) -> &[u8] {
        &self.data[0x18..0x40]
    }

    /// Returns KIRK block (144 bytes united)
    pub fn kirk_block(&self) -> &[u8] {
        &self.data[0x40..0xD0]
    }

    /// Devuelve la cabecera final del PRX
    pub fn prx_header(&self) -> &[u8] {
        &self.data[0xD0..0x150]
    }    

    pub fn is_valid(&self, xorbuf: &[u8]) -> bool {
        let mut hasher = Sha1::new();

        hasher.update(&xorbuf[0..0x14]);
        hasher.update(self.unused());
        hasher.update(self.kirk_block());
        hasher.update(self.prx_header());

        let hash_calculado = hasher.finalize();

        hash_calculado[..] == self.sha1()[..]
    }

}