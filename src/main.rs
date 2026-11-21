mod keys;
mod tag_info;
mod keys_service;
mod kirk_lib;
mod error_handling;
mod prx_types;
use error_handling::errors::PspError;
use std::fs::File;
use std::intrinsics::offset;
use std::io::{Read, Write};
use prx_types::decrypt_prx;
mod common;


fn main() -> Result<(), PspError>{
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <file_route_EBOOT.BIN>", args[0]);
        return Err(PspError::MissingArguments);
    }

    let entry_route = &args[1];
    let exit_route = format!("{}.dec", entry_route);
    println!("Opening file: {}", entry_route);

    // Now we read the file
    let mut file = File::open(entry_route)?;

    // we don't know at compile time it's size...
    let mut eboot_data = Vec::new();
    file.read_to_end(&mut eboot_data)?;

    if eboot_data.len() < 4 {
        eprintln!("The filesize is too small");
        return Err(PspError::DecryptionFailed);
    }

    let magic = &eboot_data[0..4];

    if magic == b"~PSP" {
        // THIS MEANS is a normal game. Thus it'll be type 1 or type 2, etc.
        println!("~PSP header detected. Decrypting game...");

        let mut outbuf = None;
        let mut seed = None;

        decrypt_prx(&mut eboot_data, &mut outbuf, &mut seed)?;
        let pure_elf = &eboot_data[find_offset_elf(&eboot_data)?..];
        let mut out_file = File::create(&exit_route)?;

        out_file.write_all(pure_elf)?;
        println!("Success. File saved at {}", exit_route);

    } else if magic == b"\x00PBP" {
        eprintln!("PBP firmware/update decryption is not implemented yet... It's too long!!!!")
    } else {
        eprintln!("File format not supported. Magic: {:?}", magic);
        return Err(PspError::DecryptionFailed);
    }

    Ok(())

}

// this scans the decrypted buffer for the ELF magic, which is (`0x7F 'E' 'L' 'F'`)
// And then return its starting byte offset
// - `.windows(4)` slides a view of 4 bytes, one byte at a time (`[0..4]`, `[1..5]`, `[2..6]`, ...),
// doing nothing safely if `eboot_data.len() < 4`.
// - .position(...) it stops at the first matching window and then returns it's index (Option<usize>), which matches the exact starting offset of the ELF header inside eboot_data
fn find_offset_elf(eboot_data: &[u8]) -> Result<usize, PspError>{
    eboot_data
        .windows(4)
        .position(|window| window == b"\x7FELF")
        .ok_or(PspError::InvalidHeader)
}

