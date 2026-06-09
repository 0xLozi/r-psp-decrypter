use crate::error_handling::errors::{KirkError, PspError};
use crate::kirk_lib::kirk_engine::{kirk7, kirk_cmd1_decrypt};
use sha1::{Sha1, Digest};
use crate::keys_service::{get_tag_info, get_tag_info_2};
use crate::kirk_lib::kirk_headers::KirkCmd1Header;

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

    pub fn decrypt_header(&mut self, key_id: i32) -> Result<(), KirkError> {
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

struct PrxType5 {
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

}

struct PrxType6 {
    data: [u8;0x150],
}

impl PrxType6 {
    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        
        // tag
        data[0..0x04].copy_from_slice(&prx[0xD0..0xD4]);
        
        // empty (0x38 bytes de ceros)
        // Ya se encuentran llenos gracias a que inicié el arreglo con todos ceros...

        // C++: memcpy(ecdsaSignatureTail, prx+0x10C, sizeof(ecdsaSignatureTail));
        data[0x3C..0x5C].copy_from_slice(&prx[0x10C..0x12C]);

        // 4. id (0x5C, igual que en el Tipo 5 y Tipo 2)
        data[0x5C..0x6C].copy_from_slice(&prx[0x140..0x150]);
        
        // 5. sha1
        // u8 sha1[0x14];
        data[0x6C..0x80].copy_from_slice(&prx[0x12C..0x140]);
        
        // kirkHeader (Según el código se encuentra partido en dos: "kirk header is split between 0x80->0xB0 and 0xC0->0xD0")
        data[0x80..0xB0].copy_from_slice(&prx[0x80..0xB0]);
        data[0xB0..0xC0].copy_from_slice(&prx[0xC0..0xD0]);
        
        // kirkMetadata
        data[0xC0..0xD0].copy_from_slice(&prx[0xB0..0xC0]);
        
        // prxHeader
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }


    // GETTERRRRRRRRRRRRRRRRRRS
    pub fn tag(&self) -> &[u8] {
        &self.data[0..0x04]
    }

    // getter del nuevo campo
    pub fn ecdsa_signature_tail(&self) -> &[u8] {
        &self.data[0x3C..0x5C]
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

    // DECRYPT
    pub fn decrypt_header(&mut self, key_id: i32) -> Result<(), KirkError> {
        // kirk7(id, id, 0x60, key);
        let inicio = 0x5C;
        let fin = inicio + 0x60;
        
        kirk7(&mut self.data[inicio..fin], key_id)?;
        
        Ok(())
    }
}


pub fn psp_decrypt_type0(inbuf: &mut [u8]) -> Result<usize, PspError> {

    let decrypt_size = u32::from_le_bytes(
        inbuf[0xB0..0xB4]
        .try_into().map_err(|_| PspError::SizeError)?
    );
    println!("Tamaño a desencriptar: {} bytes", decrypt_size);

    let tag = u32::from_le_bytes(
        inbuf[0xD0..0xD0+4]
        .try_into().map_err(|_| PspError::PointerError)?
    );

    let key_info = get_tag_info(tag).ok_or(PspError::TagNotFound)?;
    let key_id = key_info.code as u32;
    
    let mut xorbuf = [0u8; 0x90];

    // Now we gotta copy the key the safest way
    match key_info.key { 
        KeyType::U8(k) => { 
            xorbuf.copy_from_slice(k); 
        } 
        KeyType::U32(k1) => { 
            for (i, &word) in k1.iter().enumerate() { 
                let start = i*4; 
                xorbuf[start..start+4].copy_from_slice(&word.to_le_bytes()); 
            } 
        }
    }

    let mut type0 = PrxType0::new(inbuf);

    if !type0.is_valid(&xorbuf) {
        return Err(PspError::ValidationFailed);
    }

    // Con esto conseguimos el preciado kirk header desencriptado
    type0.decrypt_header(&xorbuf, key_id as i32)
    .map_err(|_| PspError::HeaderDecryptionFailed)?;

    let kirk_cmd = KirkCmd1Header::new(type0.kirk_block());

    if kirk_cmd.mode().map_err(|_| PspError::ValidationFailed)? != 1 {
        return Err(PspError::InvalidMode)
    }

    let size = kirk_cmd.data_size().map_err(|_| PspError::ValidationFailed)? as usize;
    let psp_header_size = 0x150;
    let payload = &mut inbuf[psp_header_size..psp_header_size+size];

    // TODO: Payload (KIRK_CMD1)
    kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
    .map_err(|_| PspError::DecryptionFailed)?;

    Ok(size)

}

pub fn psp_decrypt_type1(inbuf: &mut [u8]) -> Result<usize, PspError> {
    let decrypt_size = u32::from_le_bytes(
        inbuf[0xB0..0xB4]
        .try_into().map_err(|_| PspError::SizeError)?
    );
    println!("Tamaño a desencriptar: {} bytes", decrypt_size);

    let tag = u32::from_le_bytes(
        inbuf[0xD0..0xD0+4]
        .try_into().map_err(|_| PspError::PointerError)?
    );

    let key_info = get_tag_info(tag).ok_or(PspError::TagNotFound)?;
    let key_id = key_info.code as i32;
    
    let mut xorbuf = [0u8; 0x90];

    match key_info.key { 
        KeyType::U8(k) => { 
            xorbuf.copy_from_slice(k); 
        } 
        KeyType::U32(k1) => { 
            for (i, &word) in k1.iter().enumerate() { 
                let start = i*4; 
                xorbuf[start..start+4].copy_from_slice(&word.to_le_bytes()); 
            } 
        }
    }

    let mut type1 = PrxType1::new(inbuf);
	type1.decrypt(key_id).map_err(|_| PspError::DecryptionFailed)?;


    if !type1.is_valid(&xorbuf) {
		println!("La desencriptación exterior no es valida (SHA-1 ha fallado..)");
        return Err(PspError::ValidationFailed);
    } 

	let mut final_kirk_block = [0u8; 0x90];

	final_kirk_block.copy_from_slice(type1.kirk_block());

	decrypt_kirk_header_type_0(&mut final_kirk_block, type1.kirk_block(), &xorbuf, key_id)
	.map_err(|_| PspError::DecryptionFailed)?;

	let kirk_cmd = KirkCmd1Header::new(&final_kirk_block);

    if kirk_cmd.mode().map_err(|_| PspError::ValidationFailed)? != 1 {
        return Err(PspError::InvalidMode)
    }

	Ok(92486)

    // let size = kirk_cmd.data_size().map_err(|_| PspError::ValidationFailed)? as usize;
	// let real_size = decrypt_size as usize;


	// let mut fake_header = [0u8;0x80];
	// fake_header.copy_from_slice(type1.prx_header());
	// inbuf[0xD0..0x150].copy_from_slice(&fake_header);


    // let payload = &mut inbuf[0xD0..];

    // // Payload (KIRK_CMD1)
    // kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
    // .map_err(|_| PspError::DecryptionFailed)?;

	// inbuf.copy_within(0xD0 .. 0xD0 + real_size, 0x150);

    // Ok(real_size)

}


pub fn decrypt_kirk_header(outbuf: &mut [u8], inbuf: &[u8], xorbuf: &[u8], key_id: i32) -> Result<(), KirkError>{
    for i in (0..0x40) {
        outbuf[i] = inbuf[i] ^ xorbuf[i];
    }

    kirk7(&mut outbuf[0..0x40], key_id)?;

    for i in 0..0x40 {
        outbuf[i] ^= xorbuf[0x40+i];
    }

    Ok(())
}

pub fn decrypt_kirk_header_type_0(outbuf: &mut [u8], inbuf: &[u8], xorbuf: &[u8], key_id: i32) -> Result<(), KirkError> {
    for i in (0..0x70) {
        outbuf[i] = inbuf[i] ^ xorbuf[i+0x14];
    }

    kirk7(outbuf, key_id);

    for i in (0..0x70) { 
        outbuf[i] ^= xorbuf[0x20+i];
    }

    Ok(())
}

// 144 bytes just to make it clear
pub fn expanded_seed(seed: &[u8; 16], key: i32, bonus_seed: Option<&[u8;16]>) -> Result<[u8; 0x90], KirkError> {
    let mut expanded_seed = [0u8; 0x90];

    // Lógica para la expansión de la seed
    // Vamos saltando de 16 a 16, comenzando desde el principio
    // En C++, hacían un for (auto i = 0u; i < expandedSeed.size(); i += 0x10)
    for i in (0..0x90).step_by(0x10) {
        expanded_seed[i..i+0x10].copy_from_slice(seed);
        // Despues modificamos el primer byte de este bloque para que actúe como contador
        expanded_seed[i] = (i / 0x10) as u8;
    }

    // TODO: Implementar kirk7. 
    // En C++ sería: kirk7(expandedSeed.data(), expandedSeed.data(), expandedSeed.size(), key);
    // En Rust sería algo parecido a esto:
    kirk7(&mut expanded_seed, key)?;

    if let Some(bonus) = bonus_seed {
        // Recorremos los 144 bytes de la semilla ya expandida y encriptada
        for i in 0..0x90 {
            // Hacemos un XOR (^=) entre el byte actual y el byte correspondiente del bonus.
            // Como el bonus solo tiene 16 bytes, usamos el módulo (%) para que repita del 0 al 15
            expanded_seed[i] ^= bonus[i % 0x10];
        }
    }
    // Retornamos el arreglo estático
    Ok(expanded_seed)
}


// ESTA VA A SER LA ÚNICA FUNCIÓN PÚBLICA. 
// TO-DO: FINALIZADA LA FUNCIÓN. PONER TODO EL PRIVADO
pub fn decrypt_prx(inbuf: &mut [u8]) -> Result<usize, PspError>{
    let tag = u32::from_le_bytes(
        inbuf[0xD0..0xD0+4]
        .try_into().map_err(|_| PspError::PointerError)?
    );

    println!("Tag detectado: 0x{:08X}", tag);

    psp_decrypt_type0(inbuf)
	.or(
		psp_decrypt_type1(inbuf)
	)
}

fn check_decryption_succeed(eboot_data: &[u8]) -> bool {
	let psp_header_size = 0x150;
	let magic_bytes = &eboot_data[psp_header_size .. psp_header_size + 4];
	
	let is_elf = magic_bytes == [0x7F, 0x45, 0x4C, 0x46]; // .ELF
	let is_psp = magic_bytes == [0x7E, 0x50, 0x53, 0x50]; // ~PSP

	is_elf || is_psp

}

use crate::tag_info::{KeyType, TAG_INFO, TAG_INFO2};
#[cfg(test)]
mod tests {
    use super::*; // Importamos PrxType1 y demas
    use std::fs::File;
use std::io::{Read, Write};

    #[test]
   fn test_router_decryption_type0_succeeds() -> Result<(), PspError> {
        let ruta_eboot = "/home/snake/Downloads/lumine/lumines/lumines_game/PSP_GAME/SYSDIR/EBOOT.BIN";
        
        let mut file = File::open(ruta_eboot)
            .expect("No se pudo abrir el EBOOT de Lumines.");
        
        let mut eboot_data = Vec::new();
        file.read_to_end(&mut eboot_data).unwrap();

		psp_decrypt_type0(&mut eboot_data)?;

		assert!(
			check_decryption_succeed(&eboot_data),
			"El enrutador falló silenciosamente."
		);

        Ok(())
   } 

   #[test]
   fn test_router_decryption_type1_succeeds() -> Result<(), PspError> {
		let ruta_eboot = "/home/snake/Downloads/lego_batman_game/PSP_GAME/SYSDIR/EBOOT.BIN";
		let mut file = File::open(ruta_eboot).expect("No se pudo abrir el archivo...");

		let mut eboot_data = Vec::new();
		file.read_to_end(&mut eboot_data).expect("No se pudo pasar los bytes del archivo al vector...");

		psp_decrypt_type1(&mut eboot_data)?;

		assert!(
			check_decryption_succeed(&eboot_data),
			"El enrutador falló silenciosamente."
		);

		Ok(())
   }
}

