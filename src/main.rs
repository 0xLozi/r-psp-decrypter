use clap::Parser;
use std::fs;
mod keys;
mod tag_info;
mod keys_service;
mod kirk_lib;
mod error_handling;
mod prx_types;
use error_handling::errors::PspError;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use prx_types::decrypt_prx;


fn main() -> Result<(), PspError>{
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Error: Faltan argumentos.");
        eprintln!("Uso: {} <ruta_al_archivo_EBOOT.BIN>", args[0]);
        return Err(PspError::DecryptionFailed);
    }

    let ruta_entrada = &args[1];
    let ruta_salida = format!("{}.dec", ruta_entrada);
    println!("Opening file: {}", ruta_entrada);

    // Now we read the file
    let mut file = match File::open(ruta_entrada) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("No se pudo abrir el archivo {}", e);
            return Err(PspError::DecryptionFailed);
        }
    };

    let mut eboot_data = Vec::new();

    if let Err(e) = file.read_to_end(&mut eboot_data) {
        eprintln!("Error al leer el archivo: {}", e);
        return Err(PspError::DecryptionFailed);
    }

    if eboot_data.len() < 4 {
        eprintln!("El archivo es demasiado pequeño.");
        return Err(PspError::DecryptionFailed);
    }

    let magic = &eboot_data[0..4];

    if magic == b"~PSP" {
        // THIS MEANS is a normal game. Thus it'll be type 1 or type 2 , etc.
        println!("~PSP header detected. Decrypting game...");

        match decrypt_prx(&mut eboot_data, None) {
            Ok(_) => {
                let offset_elf = (0..eboot_data.len() - 4)
                    .find(|&i| eboot_data[i..i + 4] == [0x7F, 0x45, 0x4C, 0x46])
                    .expect("No se encontró la cabecera ELF");
                
                let pure_elf = &eboot_data[offset_elf..];

                let mut out_file = File::create(&ruta_salida)
                .map_err(|_| PspError::FileCreationFailed)?;

                out_file
                    .write_all(pure_elf)
                    .map_err(|_| PspError::FileCreationFailed)?;

                println!("Exito!!! Archivo guardado en: {}", ruta_salida);

            }
            Err(e) => {
                eprintln!("Decryption failed... {:?}", e);
            }
        }

    } else if magic == b"\x00PBP" {
        // This means it's an official update or a container
        println!("PBP header detected. decyrption mode (Type 5).");

        let psar_offset = u32::from_le_bytes(eboot_data[0x24..0x28].try_into().unwrap()) as usize;

        // Extract the seed from PSAR
        // let external_seed = extract_seed_psar(&eboot_data[psar_offset..]);

        // Extract the decrypted prx inside PSAR
        // let mut internal_prx = extract_prx_psar(&eboot_data[psar_offset..]);

        // send fro decryption sending the seed
        // match decrypt_prx(&mut prx_interno, Some(&external_seed)) { ... }

        println!("PBP/PSAR implementation pending...");
    } else {
        eprintln!("File format not supported. Magic: {:?}", magic);
        return Err(PspError::DecryptionFailed);
    }

    Ok(())

}
