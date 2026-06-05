use clap::Parser;
use std::fs;
mod keys;
mod tag_info;
mod keys_service;
mod headers;
mod kirk_lib;
mod error_handling;
mod prx_types;
use error_handling::errors::PspError;


/// Desencriptador de EBOOT.BIN (PRX) para PSP
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Config {
    /// Archivo de entrada (ej: EBOOT.BIN)
    input_file: String,

    /// Archivo de salida (opcional). Si no se pone, usará [input_file].dec
    #[arg(short = 'o', long = "outfile")]
    output_file: Option<String>,
}

fn main() -> Result<(), PspError>{
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Uso: {} <archivo>", args[0]);
        std::process::exit(1);
    }

    let in_data = fs::read(&args[1])?;

    // Momento de validación
    if in_data.len() < 0x30 {
        return Err(PspError::InvalidHeader);
    }

    let magic_number = u32::from_le_bytes(in_data[0..4].try_into()?);
    const PSP_MAGIC: u32 = 0x5053507E;


    if magic_number == PSP_MAGIC {
        println!("Magic number correcto (~PSP)! iniciando desencriptado PRX...");
        // TODAVIA FALTA IMPLEMENTARLO, POR ESO LO DEJO ASÍ
        // let out_data = prx_decrypt::decrypt_prx(&in_data)?; 
        
        let out_filename = "decrypted.bin";
        
        // fs::write(out_filename, &out_data)?;
        println!("Guardado con éxito en: {}", out_filename);
    } else {
        return Err(PspError::InvalidMagicNumber(magic_number));
    }

    Ok(())
}
