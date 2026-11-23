use crate::error_handling::errors::{KirkError, PspError};
use crate::kirk_lib::kirk_engine::{kirk7, kirk_cmd1_decrypt};
use crate::kirk_lib::kirk_headers::KirkCmd1Header;
use crate::keys::{get_tag_info, get_tag_info_2};
use super::types;

fn psp_decrypt_type0(inbuf: &mut [u8], outbuf: &mut Option<&mut [u8]>) -> Result<usize, PspError> {
    // PspError has a #[from] variant for TryFromSliceError,
    // so `?` converts the error automatically.
    let decrypt_size = read_u32_le(inbuf, 0xB0)?;
    println!("Size to decrypt: {} bytes", decrypt_size);
    let tag = read_u32_le(inbuf, 0xD0)?;

    let key_info = get_tag_info(tag)?;
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

    let mut type0 = types::PrxType0::new(inbuf);

    if !type0.is_valid(&xorbuf) {
        return Err(PspError::ValidationFailed);
    }

    // With this we get the unencrypted kirk header
    type0.decrypt_header(&xorbuf, key_id as i32)
    .map_err(|_| PspError::HeaderDecryptionFailed)?;

    let kirk_cmd = KirkCmd1Header::new(type0.kirk_block());

    if kirk_cmd.mode().map_err(|_| PspError::ValidationFailed)? != 1 {
        return Err(PspError::InvalidMode)
    }

    let size = kirk_cmd.data_size().map_err(|_| PspError::ValidationFailed)? as usize;
    let psp_header_size = 0x150;

    // Here I'm making sure that the buffer is big enough to hold both the header and the claimed payload
    if inbuf.len() < psp_header_size + size {
        return Err(PspError::CorruptedFile);
    }

    let payload = &mut inbuf[psp_header_size..psp_header_size+size];

    kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
    .map_err(|_| PspError::DecryptionFailed)?;

    if let Some(out) = outbuf {
        if out.len() < size {
            return Err(PspError::SizeError);
        }

        out[..size].copy_from_slice(payload);
    }

    Ok(size)

}

fn psp_decrypt_type1(inbuf: &mut [u8], outbuf: &mut Option<&mut [u8]>) -> Result<usize, PspError> {
    let decrypt_size = read_u32_le(inbuf, 0xB0)?;
    println!("Size to decrypt: {} bytes", decrypt_size);
    let tag = read_u32_le(inbuf, 0xD0)?;


    // Now we obtain the tag_info from keys.rs
    let key_info = get_tag_info(tag)?;
    let key_id = key_info.code as i32;
    
    // We initialize each data with 0 
    let mut xorbuf = [0u8; 0x90];


    // Depending on the type-key, we need no make some additional steps in order to get the required key
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

    // Now we initialize the type1 struct
    let mut type1 = types::PrxType1::new(inbuf);

    // And then decrypt
	type1.decrypt(key_id)
    .map_err(|_| PspError::DecryptionFailed)?;

    // After decryption, we validate. If we do this step before the external decryption, it'll fail
    if !type1.is_valid(&xorbuf) {
        println!("The external decryption isn't valid (SHA-1 failed)");
        return Err(PspError::ValidationFailed);
    } 

    // We need to copy the slice in order to decrypt the header type 0
    let mut final_kirk_block = [0u8;0x90];

    // We copy the slice
	final_kirk_block.copy_from_slice(type1.kirk_block());

    // And we decrypt it
	decrypt_kirk_header_type_0(&mut final_kirk_block, type1.kirk_block(), &xorbuf, key_id)
	.map_err(|_| PspError::DecryptionFailed)?;


    // Then we create the KIRKCMDHEADER
	let kirk_cmd = KirkCmd1Header::new(&final_kirk_block);

    if kirk_cmd.mode().map_err(|_| PspError::ValidationFailed)? != 1 {
        return Err(PspError::InvalidMode)
    }

	// Something is weird... AES is a cipher by blocks, but &mut inbuf[0xD0..]
	// decrypt_size = 4.109.852 bytes..... 0xD0 .. 4.109.852 is 4.109.984
	// Difference = 132 bytes
	// could it be excsda signature?
	let real_size = decrypt_size as usize;
    let padded_size: usize;

    if real_size % 16 == 0 {
        padded_size = real_size;
    } else {
        padded_size = real_size + (16 - (real_size % 16 ));
    }

    // Next we copy the fake header that was at the first offset and we copy that into 0xD0, in order to paste the remaining steps for the decryption
    let mut fake_header = [0u8; 0x80];
    fake_header.copy_from_slice(type1.prx_header());
    inbuf[0xD0..0x150].copy_from_slice(&fake_header);

    // Sobreescribimos los primeros 80 bytes de la cabecera falsa
    // con el sobrante del bloque Kirk desencriptado.
    inbuf[0xD0..0x120].copy_from_slice(&final_kirk_block[0x20..0x70]);

    if inbuf.len() < 0xD0 + padded_size {
        return Err(PspError::CorruptedFile);
    }
    let payload = &mut inbuf[0xD0 .. 0xD0 + padded_size];

    kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
        .map_err(|_| PspError::DecryptionFailed)?;

    if let Some(out) = outbuf {
        if out.len() < real_size {
            return Err(PspError::SizeError);
        }

        out[..real_size].copy_from_slice(&payload[..real_size]);
    }

    Ok(real_size)
}


fn psp_decrypt_type2(inbuf: &mut [u8], outbuf: &mut Option<&mut [u8]>) -> Result<usize, PspError> {
    // First we have to search into get_tag_2
    // Tag offset is the same as type 1
    let tag_offset = read_u32_le(inbuf, 0xD0)?;
    // Then we search the tag we receive inside TAG_INFO2
    let tag = get_tag_info_2(tag_offset)?;

    // The same procedure as the other types: expand seed
    let key_id = tag.code as i32;
    let key_info = tag.key;

    let mut xorbuf = expanded_seed(key_info, key_id, None)
    .map_err(|_| PspError::DecryptionFailed)?;

    let mut type2 = types::PrxType2::new(inbuf);
    type2.decrypt(key_id).map_err(|_| PspError::DecryptionFailed)?;

    let valid = type2.is_valid(&xorbuf);

    if valid {
        println!("The decryption is valid");
    } else {
        return Err(PspError::DecryptionFailed)?;
    } 

    let mut kirk_header= [0u8;0x40]; // Like, the size of kirk_header

    // Idk why they do this,sony is kinda weird but I trust the bytes!!!
    let xorbuff_after_10 = &xorbuf[0x10..];

    decrypt_kirk_header(&mut kirk_header, type2.kirk_header(), xorbuff_after_10, key_id).map_err(|_| PspError::DecryptionFailed)?;

    let mut final_kirk_header = [0u8; 0x90];
    final_kirk_header[0x00..0x40].copy_from_slice(&kirk_header);
    final_kirk_header[0x60..0x70].copy_from_slice(type2.kirk_metadata());

    // Caso escencial por parte de Sony (Type 2): Para ofuscar el archivo, eliminaron el byte del modo.
    // Forzamos 'mode = 1' en el offset 0x70 porque nuestra estructura 
    // KirkCmd1Header es estricta y necesita este interruptor explícito 
    // para saber que debe encender el motor de desencriptado AES-128-CBC.
    final_kirk_header[0x70] = 1;

    let mut kirk_cmd = KirkCmd1Header::new(&final_kirk_header);

    // I already did this at line 615. Thus I don't have to validate what i already this before...
    // if kirk_cmd.mode().map_err(|_| PspError::ValidationFailed)? != 1 {
    //     // Como el C++ lo forzaba a 1, si aca no es 1, algo salio mal en el rompecabezas....
    //     return Err(PspError::InvalidMode);
    // }

    let decrypt_size = u32::from_le_bytes(
        inbuf[0xB0..0xB0+4].try_into().map_err(|_| PspError::DecryptionFailed)?
    );
    let real_size = decrypt_size as usize;

    // El motor AES procesa datos UNICAMENTE en bloques exactos de 16 bytes.
    // Sony no uso un padding estandar (como PKCS#7) que se pueda auto-recortar, 
    // sino que rellenó el final del archivo original con basura aleatoria.
    // Acá calculamos el múltiplo de 16 más cercano hacia arriba. Si le pasamos
    // un bloque incompleto a nuestra librería (que usa NoPadding), explota. 
    // Le pasamos el tamaño rellenado para que desencripte todo sin chistar, 
    // y más abajo ignoramos la basura usando el 'real_size'.
    // Por si las moscas a 16 bytes para el motor AES
    let padded_size = if real_size % 16 == 0 {
        real_size
    } else {
        real_size + (16 - (real_size % 16))
    };

    inbuf[0xD0..0x150].copy_from_slice(type2.prx_header());

    // Despues tenemos que pisar los primeros 80 bytes de la parte desencriptada
    inbuf[0xD0..0x120].copy_from_slice(&final_kirk_header[0x20..0x70]);

    // Creación del payload
    let payload = &mut inbuf[0xD0 .. 0xD0 + padded_size];

    // Momento de la verdad...
    kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
        .map_err(|_| PspError::DecryptionFailed)?;

    if let Some(out) = outbuf {
        if out.len() < real_size {
            return Err(PspError::SizeError);
        }

        out[..real_size].copy_from_slice(payload);
    }

    Ok(real_size)   
}


fn psp_decrypt_type5(inbuf: &mut [u8], outbuf: &mut Option<&mut [u8]>, external_seed: &[u8;16]) -> Result<usize, PspError> {
    let tag_offset = read_u32_le(inbuf, 0xD0)?;
    let decrypt_size = read_u32_le(inbuf, 0xB0)?;
    let tag = get_tag_info_2(tag_offset)?;
    
    // Acá usamos la semilla EXTERNA en lugar de tag.seed
    let mut xorbuff = expanded_seed(
        tag.key, 
        tag.code as i32,
        Some(external_seed), // Le inyectamos la llave que robamos del PSAR
    ).map_err(|_| PspError::DecryptionFailed)?;

    let mut type5 = types::PrxType5::new(inbuf);
    
    // Desencriptamos el header usando la semilla externa.
    // Type 5 usa internamente el comando KIRK_CMD5, no el CMD1.
    type5.decrypt_header(tag.code as i32, Some(tag.key), Some(external_seed))
        .map_err(|_| PspError::DecryptionFailed)?;

    let xorbuff_before_0x10 = &xorbuff[0..0x10]
    .try_into()
    .map_err(|_| PspError::SizeError)?;

    // Once we validate
    let valid = type5.is_valid(&xorbuff_before_0x10);

    if !(valid) {
        return Err(PspError::DecryptionFailed);
    }

    let mut final_kirk_header = [0u8;0x90];
    
    final_kirk_header[0x60..0x70].copy_from_slice(type5.kirk_metadata());

    let xorbuff_after_10 = &xorbuff[0x10..0x20];

    decrypt_kirk_header(
        &mut final_kirk_header[0x00..0x40], 
        type5.kirk_header(), 
        xorbuff_after_10, 
        tag.code as i32
    ).map_err(|_| PspError::DecryptionFailed)?;

    final_kirk_header[0x70] = 1;

    let kirk_cmd = KirkCmd1Header::new(&final_kirk_header);

    let real_size = decrypt_size as usize;
    let padded_size = if real_size % 16 == 0 {
        real_size
    } else {
        real_size + (16 - (real_size % 16))
    };

    inbuf[0x40..0xD0].copy_from_slice(&final_kirk_header);
    inbuf[0xD0..0x150].copy_from_slice(type5.prx_header());

    let payload = &mut inbuf[0xD0 .. 0xD0 + padded_size];

    kirk_cmd1_decrypt(kirk_cmd.aes_key(), kirk_cmd.cmac_key(), payload)
        .map_err(|_| PspError::DecryptionFailed)?;

    if let Some(out) = outbuf {
        if out.len() < real_size {
            return Err(PspError::SizeError);
        }

        out[..real_size].copy_from_slice(payload);
    }

    Ok(real_size)   
}

fn decrypt_kirk_header(outbuf: &mut [u8], inbuf: &[u8], xorbuf: &[u8], key_id: i32) -> Result<(), KirkError>{
    for i in 0..0x40 {
        outbuf[i] = inbuf[i] ^ xorbuf[i];
    }

    kirk7(&mut outbuf[0..0x40], key_id)?;

    for i in 0..0x40 {
        outbuf[i] ^= xorbuf[0x40+i];
    }

    Ok(())
}

fn decrypt_kirk_header_type_0(outbuf: &mut [u8], inbuf: &[u8], xorbuf: &[u8], key_id: i32) -> Result<(), KirkError> {
    for i in 0..0x70 {
        outbuf[i] = inbuf[i] ^ xorbuf[i+0x14];
    }

    kirk7(outbuf, key_id)?;

    for i in 0..0x70 { 
        outbuf[i] ^= xorbuf[0x20+i];
    }

    Ok(())
}

// 144 bytes just to make it clear
fn expanded_seed(seed: &[u8; 16], key: i32, bonus_seed: Option<&[u8;16]>) -> Result<[u8; 0x90], KirkError> {
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


// This is going to be the only public function
pub fn decrypt_prx(inbuf: &mut [u8], outbuf: &mut Option<&mut [u8]>, seed: &mut Option<&[u8; 16]>) -> Result<usize, PspError>{
    let tag = u32::from_le_bytes(
        inbuf[0xD0..0xD0+4]
        .try_into().map_err(|_| PspError::PointerError)?
    );

    println!("Tag detectado: 0x{:08X}", tag);
    // fix this
    psp_decrypt_type0(&mut *inbuf, outbuf)
        .or_else(|_| psp_decrypt_type1(&mut *inbuf, outbuf))
        .or_else(|_| psp_decrypt_type2(&mut *inbuf, outbuf))
        .or_else(|_| {
            // If it makes it all the way down here, it demands the seed
            let actual_seed = seed.ok_or(PspError::MissingSeed)?;
            psp_decrypt_type5(&mut *inbuf, outbuf, actual_seed)
        })
}


fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, PspError> {
    let bytes: [u8; 4] = buf
        .get(offset..offset + 4)
        .ok_or(PspError::SizeError)?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}



use crate::tag_info::{KeyType, TAG_INFO, TAG_INFO2};
#[cfg(test)]
mod tests {
    use super::*; // Importamos PrxType1 y demas
    use std::fs::File;
    use std::io::{Read, Write};

    // also fix this, same thing, arguments issue
    #[test]
   fn test_router_decryption_type0_succeeds() -> Result<(), PspError> {
        let ruta_eboot = "/home/snake/Downloads/lumine/lumines/lumines_game/PSP_GAME/SYSDIR/EBOOT.BIN";
        
        let mut file = File::open(ruta_eboot)
            .expect("No se pudo abrir el EBOOT de Lumines.");
        
        let mut eboot_data = Vec::new();
        file.read_to_end(&mut eboot_data).unwrap();

		//psp_decrypt_type0(&mut eboot_data)?;

		let psp_header_size = 0x150;
		let magic_bytes = &eboot_data[psp_header_size .. psp_header_size + 4];
		
		let elf = [0x7F, 0x45, 0x4C, 0x46]; // .ELF
		let is_psp = magic_bytes == [0x7E, 0x50, 0x53, 0x50]; // ~PSP


        // This is for searching inside the ".ELF" extension. This is because we don't know at compile time where it would be
        let offset_elf= (0..eboot_data.len() - 4)
        .find(|&i| eboot_data[i..i+4] == elf);


        assert!(
            offset_elf.is_some(),
            "The router failed"
        );


        Ok(())
   } 

   // fix this (wrong arguments while calling each function)
   #[test]
   fn test_router_decryption_type1_succeeds() -> Result<(), PspError> {
		let ruta_eboot = "/home/snake/Downloads/lego_batman_game/PSP_GAME/SYSDIR/EBOOT.BIN";
		let mut file = File::open(ruta_eboot).expect("No se pudo abrir el archivo...");

		let mut eboot_data = Vec::new();
		file.read_to_end(&mut eboot_data).expect("No se pudo pasar los bytes del archivo al vector...");

		//psp_decrypt_type1(&mut eboot_data)?;

		let elf = [0x7F, 0x45, 0x4C, 0x46]; // .ELF

        // This is for searching inside the ".ELF" extension. This is because we don't know at compile time where it would be
        let offset_elf= (0..eboot_data.len() - 4)
        .find(|&i| eboot_data[i..i+4] == elf);


        assert!(
            offset_elf.is_some(),
            "The router failed"
        );

		Ok(())
   }

   #[test]
   fn test_decryption_type2_succeeds() -> Result<(), PspError> {
        let ruta_eboot = "/home/snake/Downloads/games_for_decryption/god_of_war/PSP_GAME/SYSDIR/EBOOT.BIN";

		let mut file = File::open(ruta_eboot).expect("No se pudo abrir el archivo...");

		let mut eboot_data = Vec::new();
		file.read_to_end(&mut eboot_data).expect("No se pudo pasar los bytes del archivo al vector...");

        //psp_decrypt_type2(&mut eboot_data)?;

		let elf = [0x7F, 0x45, 0x4C, 0x46]; // .ELF

        // This is for searching inside the ".ELF" extension. This is because we don't know at compile time where it would be
        let offset_elf= (0..eboot_data.len() - 4)
        .find(|&i| eboot_data[i..i+4] == elf);


        assert!(
            offset_elf.is_some(),
            "The router failed"
        );

        Ok(())
   }
}

