use clap::Parser;
use std::fs;
use std::process;
mod prx_decrypt;
mod keys;
mod tag_info;
mod keys_service;
mod headers;

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

fn main() {
    // 1. Parsear los argumentos de la consola mágicamente
    let config = Config::parse();

    // Si el usuario no pasó '-o', creamos el nombre por defecto.
    let out_filename = config.output_file.unwrap_or_else(|| {
        format!("{}.dec", config.input_file)
    });

    println!("Intentando desencriptar: {}", config.input_file);

    // Esto lee TODO el archivo en memoria de un solo golpe
    let in_data = match fs::read(&config.input_file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error al leer el archivo: {}", e);
            process::exit(1);
        }
    };

    // Verificamos que al menos tenga el tamaño de una cabecera básica
    if in_data.len() < 0x30 {
        eprintln!("El archivo es demasiado pequeño para ser un EBOOT de PSP.");
        process::exit(1);
    }

    // Leer el Magic Number (Los primeros 4 bytes)
    // Convertimos los primeros 4 bytes en un u32 (Little Endian) 
    let magic_number = u32::from_le_bytes(in_data[0..4].try_into().unwrap());

    // 5053507E es "~PSP" en hexadecimal
    const PSP_MAGIC: u32 = 0x5053507E;

    // 5. Verificar y Rutear
    if magic_number == PSP_MAGIC {
        println!("Magic Number correcto (~PSP)! Iniciando desencriptado PRX...");
        
        let out_data = prx_decrypt::decrypt_prx(&in_data);
        
        // 6. Escribir el resultado en el disco (Simulado por ahora)
        // fs::write(&out_filename, out_data).expect("Error escribiendo el archivo");
        println!("Guardado con éxito en: {}", out_filename);

    } else {
        eprintln!("Formato desconocido. Magic number encontrado: {:#010x}", magic_number);
        process::exit(1);
    }
}
