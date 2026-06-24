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
use crate::kirk_lib::kirk_engine::kirk7;


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

        // inside Imhex, the size is 2 bytes. Therefore the representation is uint16_t
        let psar_version = u8::from_le_bytes(
            psar_data[4..6]
                .try_into()
                .map_err(|_| PspError::DecryptionFailed)?
        );

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
        println!("We need to implement the PSAR mathematitian tool, but the route is ready");
        let mut buffer_result = [0u8; 0x130];
        demangle_psar_header(&psar_data, &mut buffer_result, psar_version)?;
    } else {
        eprintln!("File format not supported. Magic: {:?}", magic);
        return Err(PspError::DecryptionFailed);
    }

    Ok(())

}
    // int i;
    // if (psarVersion == 5) for ( i = 0; i < 0x130; ++i ) { buffer[20+i] ^= K1[i & 0xF]; }
    // u32* pl = (u32*)buffer; // first 20 bytes
    // pl[0] = 5;
    // pl[1] = pl[2] = 0;
    // pl[3] = 0x55;
    // pl[4] = 0x130;

// for 1.50 and later, they mangled the plaintext parts of the header
fn demangle_psar_header(pIn: &[u8], pOut: &mut [u8], psar_version: u8) -> Result<(), PspError> {
    let mut buffer = [0u8;20+0x130]; // or 0x34

    // Defining the keys just in case the version == 5
    let k1: [u8; 16] = [
        0xD8, 0x69, 0xB8, 0x95, 0x33, 0x6B, 0x63, 0x34, 
        0x98, 0xB9, 0xFC, 0x3C, 0xB7, 0x26, 0x2B, 0xD7
    ];

    let k2: [u8; 16] = [
        0x0D, 0xA0, 0x90, 0x84, 0xAF, 0x9E, 0xB6, 0xE2, 
        0xD2, 0x94, 0xF2, 0xAA, 0xEF, 0x99, 0x68, 0x71
    ];

    // Security first!!
    // inside the tool: it's 20, but 0x14 is the hexadecimal value
    if pIn.len() < 0x130 || pOut.len() < 0x130 {
        eprintln!("Error: Chunk too small to demangle");
        return Err(PspError::SizeError);
    }

    // Copy encrypted payload into our working buffer
    buffer[20..(20+0x130)].copy_from_slice(&pIn[..0x130]);

    if psar_version == 5 { 
        for i in 0..0x130 { 
            buffer[20+i] ^= k1[i & 0xF]; 
        } 
    }

    let raw_ptr = buffer.as_mut_ptr();

    // Opening the gates of abyss hahahaah
    unsafe {
        let pl = std::slice::from_raw_parts_mut(raw_ptr as *mut u32, 5);
        // And then we write this exactly as C++ code!!!
        pl[0] = 5;
        pl[1] = 0; pl[2] = 0;
        // This is so risky
        pl[3] = 0x55;
        pl[4] = 0x130;
    }
    // We are missing Hardware Decryption
    // sceUtilsBufferCopyWithRange(buffer, 20+0x130, buffer, 20+0x130, 0x7);

    // TODO: Call the kirk engine here
    execute_kirk_cmd7(&mut buffer)?;

        
    if psar_version == 5 {
        for i in 0..0x130 {
            buffer[i] ^= k2[i % 16];
        }
    }

    pOut[..0x130].copy_from_slice(&buffer[..0x130]);

    Ok(())
}

fn execute_kirk_cmd7(buffer: &mut[u8]) -> Result<(), PspError> {
    // twelve because 4 times 3 = 12
    // Safely builds the 32-bit ID from 4 bytes, avoiding pointer-casting UB and Alignment Faults.
    let key_id = i32::from_le_bytes(buffer[12..16].try_into().map_err(|_| PspError::InvalidHeader)?);
    kirk7(&mut buffer[20..(20+0x130)], key_id)
            .map_err(|_| PspError::DecryptionFailed)?;
    
    buffer.copy_within(20..(20+0x130), 0);
    Ok(())
}