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

    match decrypt_prx(&mut eboot_data) {
        Ok(decrypted_size) => {
            // If everything worked well, then we save the pure .ELF
            let psp_header_size = 0x150;
            let pure_elf = &eboot_data[psp_header_size..psp_header_size+decrypted_size];

            let mut out_file = File::create(&ruta_salida).map_err(|_| PspError::FileCreationFailed)?;

            out_file.write_all(pure_elf).map_err(|_| PspError::FileCreationFailed)?;

            println!("Exito!!! Archivo guardado en: {}", ruta_salida);
        }
        Err(e) => {
            eprintln!("Falló la desencriptación: {:?}", e);
        }
    }

    Ok(())

}
