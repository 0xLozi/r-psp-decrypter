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

    // SHA_CTX ctx;
    // SHAInit(&ctx);
    // SHAUpdate(&ctx, xorbuf.data(), 0x14);
    // SHAUpdate(&ctx, type1.unused, sizeof(type1.unused));
    // SHAUpdate(&ctx, type1.kirkBlock, sizeof(type1.kirkBlock));
    // SHAUpdate(&ctx, type1.prxHeader, sizeof(type1.prxHeader));

    pub fn is_valid(&self, xorbuf: &[u8]) -> bool {
        let mut hasher = Sha1::new();

        hasher.update(&xorbuf[0..0x14]);
        hasher.update(self.unused());
        hasher.update(self.kirk_block());
        hasher.update(self.prx_header());

        let hash_calculated = hasher.finalize();

        hash_calculated[..] == self.sha1()[..]
    }

}

pub struct PrxType2 {
    pub data: [u8; 0x150],
}

impl PrxType2 {
    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        // tag: Offset 0xD0 (C++: prx+0xD0)
        data[0..0x04].copy_from_slice(&prx[0xD0..0xD4]);
        
        // id: Offset 0x140 (C++: prx+0x140)
        data[0x5C..0x6C].copy_from_slice(&prx[0x140..0x150]);
        
        // sha1: Offset 0x12C (C++: prx+0x12C)
        data[0x6C..0x80].copy_from_slice(&prx[0x12C..0x140]);
        
        // kirkHeader: Este venía partido al medio en el C++ original
        // Primera parte (tamaño 0x30 / 48 bytes)
        data[0x80..0xB0].copy_from_slice(&prx[0x80..0xB0]);
        // Segunda parte (tamaño 0x10 / 16 bytes)
        data[0xB0..0xC0].copy_from_slice(&prx[0xC0..0xD0]);
        
        // kirkMetadata: Offset 0xB0 (C++: prx+0xB0)
        data[0xC0..0xD0].copy_from_slice(&prx[0xB0..0xC0]);
        
        // prxHeader: Offset 0 (C++: prx)
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }

    pub fn decrypt(&mut self, key_id: i32) -> Result<(), KirkError> {
        // En C++ la firma era: kirk7(id, id, 0x60, key);
        // Sabemos por nuestra tabla que 'id' empieza en el byte 0x5C.
        // Si queremos desencriptar 96 bytes (0x60): 0x5C + 0x60 = 0xBC.
        
        kirk7(&mut self.data[0x5C..0xBC], key_id)?;
        
        Ok(())
    }

    pub fn tag(&self) -> &[u8] {
        &self.data[0..0x04]
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
}


pub struct PrxType0 {
    data: [u8;0x150],
}
    // Code from C
    // memcpy(tag, prx+0xD0, sizeof(tag));
    // memcpy(sha1, prx+0xD4, sizeof(sha1));
    // memcpy(unused, prx+0xE8, sizeof(unused));
    // memcpy(kirkBlock, prx+0x110, 0x40); // key data
    // memcpy(kirkBlock+0x40, prx+0x80, sizeof(kirkBlock)-0x40);
    // memcpy(prxHeader, prx, sizeof(prxHeader));
	// u8 tag[4];
	// u8 sha1[0x14];
	// u8 unused[0x28];
	// u8 kirkBlock[0x90];
	// u8 prxHeader[0x80];


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
}




use crate::keys_service;
use crate::tag_info::{KeyType, TAG_INFO, TAG_INFO2};

#[cfg(test)]
mod tests {
    use super::*; // Importamos PrxType1 y demas
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_lego_batman_type1_valido() {
        let ruta_eboot = "/home/snake/Downloads/lego_batman_game/PSP_GAME/SYSDIR/EBOOT.BIN";
        
        let mut file = File::open(ruta_eboot)
            .expect("No se pudo abrir el EBOOT! Revisá la ruta.");
        
        // We read the entire file into de mem (this is a test, so it doesn't matter if it waste RAM)
        let mut eboot_data = Vec::new();
        file.read_to_end(&mut eboot_data).unwrap();


        // We create our own structure 
        let mut type1 = PrxType1::new(&eboot_data);

        let tag_bytes: [u8; 4] = type1.tag().try_into().expect("El Tag no tiene 4 bytes");
        let tag = u32::from_le_bytes(tag_bytes); // Esto será 0xC0CB167C automáticamente

        let key_eboot = keys_service::get_tag_info(tag)
            .expect("El Tag de este juego no está en la base de datos de keys_service!");

        let key_id = key_eboot.code as i32;
       
        let mut xorbuf = [0u8; 144];

        match &key_eboot.key {
            KeyType::U8(key_array) => {
                xorbuf.copy_from_slice(*key_array);
            }
            KeyType::U32(key_array) => {
                for (i, &word) in key_array.iter().enumerate() {
                    let start = i * 4;
                    let end = start + 4;
                    xorbuf[start..end].copy_from_slice(&word.to_le_bytes());
                }
            }
        }

        // Decrypt
        type1.decrypt(key_id).expect("El motor AES falló...");

        let es_valido = type1.is_valid(&xorbuf);

        assert!(es_valido, "El hash SHA-1 no coincide... La desencriptación falló!!!");
    }
}