mod keys;
mod tag_info;
mod keys_service;
mod kirk_lib;
mod error_handling;
mod prx_types;
use error_handling::errors::PspError;
use std::fs::File;
use std::io::{Read, Write};
use prx_types::decrypt_prx;
use crate::kirk_lib::kirk_engine::kirk7;
mod common;



const SIZE_A: usize = 0x110;

pub struct PsarContext {
    decrypted: bool,
    overhead: usize,
    psar_version: u8,
    i_base: usize,
    table_mode: u32,
    g_tables: [Vec<u8>; 13]
}

impl PsarContext {
    pub fn new() -> Self {
        Self {
            decrypted: false,
            overhead: 0,
            psar_version: 1,
            i_base: 0, // I think it's ok like that
            table_mode: 0,
            g_tables: std::array::from_fn(|_| Vec::new()),
        }
    }
}




fn main() -> Result<(), PspError>{
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Error: Faltan argumentos.");
        eprintln!("Uso: {} <ruta_al_archivo_EBOOT.BIN>", args[0]);
        return Err(PspError::DecryptionFailed);
    }
    
    println!("This is a test");

    let entry_route = &args[1];
    let exit_route = format!("{}.dec", entry_route);
    println!("Opening file: {}", entry_route);

    // Now we read the file
    let mut file = match File::open(entry_route) {
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

        let mut outbuf = None;
        let mut seed = None;

        match decrypt_prx(&mut eboot_data, &mut outbuf, &mut seed) {
            Ok(_) => {
                let offset_elf = (0..eboot_data.len() - 4)
                    .find(|&i| eboot_data[i..i + 4] == [0x7F, 0x45, 0x4C, 0x46])
                    .expect("No se encontró la cabecera ELF");
                
                let pure_elf = &eboot_data[offset_elf..];

                let mut out_file = File::create(&exit_route)
                .map_err(|_| PspError::FileCreationFailed)?;

                out_file
                    .write_all(pure_elf)
                    .map_err(|_| PspError::FileCreationFailed)?;

                println!("Success. File saved at {}", exit_route);

            }
            Err(e) => {
                eprintln!("Decryption failed... {:?}", e);
            }
        }

    } else if magic == b"\x00PBP" {
        eprintln!("PBP firmware/update decryption is not implemented yet... It's too long!!!!")
    } else {
        eprintln!("File format not supported. Magic: {:?}", magic);
        return Err(PspError::DecryptionFailed);
    }

    Ok(())

}

