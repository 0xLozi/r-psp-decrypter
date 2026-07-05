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
mod psar_decrypter;

const SIZE_A: usize = 0x110;

pub struct PsarContext {
    decrypted: bool,
    overhead: usize,
    psar_version: u8,
    i_base: usize,
    table_mode: u32
}

impl PsarContext {
    pub fn new() -> Self {
        Self {
            decrypted: false,
            overhead: 0,
            psar_version: 1,
            i_base: 0, // I think it's ok like that
            table_mode: 0
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

        match decrypt_prx(&mut eboot_data, None) {
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
        let mut ctx = PsarContext::new();

        // This means it's an official update or a container
        println!("PBP header detected. decryption mode (Type 5).");

        let psar_offset = u32::from_le_bytes(
            eboot_data[0x24..0x28].try_into().map_err(|_| PspError::DecryptionFailed)?
        ) as usize;

        let psar_data = &eboot_data[psar_offset..];

        // We read de signature in order to see if we are positioned correctly
        if &psar_data[0..4] != b"PSAR" {
            eprintln!("Error: Couldn't find PSAR vault at offset 0x{:X}", psar_offset);
            return Err(PspError::DecryptionFailed);
        }

        // inside Imhex, the size is 1 byte. Therefore the representation is uint8_t
        ctx.psar_version = psar_data[4];

        println!("Psar Found lmaooo");

        println!(
            "Psar: {}",
            std::str::from_utf8(&psar_data[0..4]).unwrap()
        );


        // The PSAR header contains different versions
        // Versions from 6.60 usually contains an extended header
        // The total size of PSAR shows off at 0x1C
        
        // But what matters for the key math usually appears in an information block 
        // from 0x20 to 0x200 depending on the exact type

        // We have to generate the seed based of the header
        // let external_seed = generate_seed_psar(&psar_data_header);

        // Extract the first PRX
        // let prx_buffer = extract_prx_from_psar(&psar_data, index);

        // Send it to out Engine
        // let size = psp_decrypt::decrypt_prx(&mut prx_buffer, Some(&externar_seed))?;
        psar_decrypter::psp_decrypt_psar(psar_data, ".", &mut ctx)?;
        println!("We need to implement the PSAR mathematitian tool, but the route is ready");
    } else {
        eprintln!("File format not supported. Magic: {:?}", magic);
        return Err(PspError::DecryptionFailed);
    }

    Ok(())

}

