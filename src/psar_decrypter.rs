use std::fs;
use std::path::Path;
use std::io::{self, Read};
use crate::common::write_file;

use crate::{PsarContext, PspError, SIZE_A};
use crate::prx_types::decrypt_prx;
use crate::kirk7;
use crate::psp_decrypt_lib::{psp_decrypt_table, psp_decompress};

const DATA_SIZE: usize = 3000000;
use flate2::bufread::ZlibDecoder;
use atoi::atoi;
// use std::sync::Mutex;

// This is for c-style byte representation
// What it does the crate-page is this: A dynamically-sized view of a C string.
use std::ffi::CStr;

// std::array<std::vector<char>, 13> g_tables;
// THIS IS WRONG, BELOW
// static G_TABLES: Mutex<[Vec<u8>; 13]> = Mutex::new([const { Vec::new() }; 13]);
// I don't really need it in single-threader nor multi-threaded


static G_TABLE_FILENAMES: &[(&str, u8)] = &[
    ("com:00000", 0),
    ("01g:00000", 1),
    ("02g:00000", 2),
    ("00001", 1),
    ("00002", 2),
    ("00003", 3),
    ("00004", 4),
    ("00005", 5),
    ("00006", 6),
    ("00007", 7),
    ("00008", 8),
    ("00009", 9),
    ("00011", 11),
    ("00012", 12),
];

pub fn psp_decrypt_psar(data_psar: &[u8], out_dir: &str, ctx: &mut PsarContext, extract_only: bool) -> Result<(), PspError> {
    // kirk_init: but not neccessary
    let magic: [u8; 4] = data_psar[..4]
        .try_into()
        .map_err(|_| PspError::TooShort)?;

    if &magic != b"PSAR" {
        eprintln!("Invalid PSAR magic");
        return Err(PspError::ValidationFailed);
    }

    // Creation of 2 custom buffers
    let mut data_1: [u8; DATA_SIZE] = [0u8; DATA_SIZE];
    let mut data_2: [u8; DATA_SIZE] = [0u8; DATA_SIZE];

    println!("PSAR Version: {}", ctx.psar_version);

    // init psp
    psp_psar_init(data_psar, &mut data_1, &mut data_2, ctx)?;


    // I do "try_into()" because I know that this'll work
    let int_version = get_version(&data_1[0x10..0x14].try_into().unwrap())?;
    println!("{}", int_version);
    

    // Check PBP_NOTES.md section {### table_modes} In order to understand why we do this
    if int_version >= 380 && int_version < 400 {
        ctx.table_mode = 1;
    } else if int_version >= 400 && int_version < 500 {
        ctx.table_mode = 2;
    } else if int_version >= 500 && int_version < 600 {
        ctx.table_mode = 3;
    } else if int_version >= 610 && int_version < 630 && ctx.psar_version == 5 {
        ctx.table_mode = 5;
    } else if int_version >= 600 && int_version < 700 {
        ctx.table_mode = 4;
    } else {
        ctx.table_mode = 0;
    }

    println!("Table mode: {}", ctx.table_mode);

    // We don't have that option yet, so we skip that
    // if (infoOnly) {
    //     println("only info lmao")
    //     return urmom
    // }

    // Then we create the folders (explanation at PBP_notes.md section ### creating folders in psar decryption)
    // Just in case I map the error so it's compatible to the PspError Result, even though the compiler didn't trigger anything, just in case
    setup_extraction_folders(out_dir).map_err(|_| PspError::FolderCreationFailed)?;

    // I'm not decided wether use a "loop" or a "while-loop". I still don't know which one's better, so Imma just leave it like there
    loop {
        // Creation of vars
        let mut log_str: String = String::new();
        let mut name = [0u8; 128];

        let mut cb_expanded: usize = 0;
        let mut pos = 0u32;
        let mut sign_check: bool = false;
        let mut result_name: [u8;128] = [0u8;128];

        // put cb_expanded as mutable, I don't know yet if this decision is right. I'm just making hypothesis
        let res = psp_psar_get_next_file(
            data_psar, 
            &mut data_1,
            &mut data_2, 
            &mut name, 
            &mut cb_expanded, 
            &mut pos, 
            &mut sign_check,
            ctx
        )?;

        // DEBUG THINGS (AFTER FINISHING VERIFICATION, DELETE THIS)
        // Here is safe the usage of unwrap();
        let name_size = name.iter().position(|&b| b == 0).unwrap_or(name.len());

        let debug_name = std::str::from_utf8(&name[..name_size]).unwrap_or("UNKNOWN");
        println!("Extracted chunk: {}", debug_name);
        // DEBUG THINGS (AFTER FINISHING VERIFICATION, DELETE THIS)


        // This'll mimic if res < 0
        if res == false {
            break;
        }

        if is_5_d_num(&name) {
            let name_as_int = atoi::<u32>(&name)
            .unwrap_or(0);
            
            if name_as_int >= 100 || (name_as_int >= 10 && int_version < 660) {
                let mut found: bool = false;

                for table in &mut ctx.g_tables {
                    if table.len() > 0 {
                        found = find_table_path(table, table.len(), &name, &mut result_name);
                        name = result_name;
                        if found {
                            break;
                        }
                    }
                }

                if !found {
                    let cstr = CStr::from_bytes_until_nul(&name)
                    .map_err(|_| PspError::StringRepresentation)?;

                    println!("Part 1 Error: can't find path of {}", cstr.to_string_lossy());
                    continue;
                }
            }
        }
        else if &name[..4] == b"com:" && ctx.g_tables[0].len() > 0 {
            let mut result_name: [u8;128] = [0u8;128];

            if !(find_table_path(&ctx.g_tables[0], ctx.g_tables[0].len(), &name[4..], &mut result_name)) {
                let c_str = CStr::from_bytes_until_nul(&result_name).unwrap();
                println!("Part 2 Error: cannot find path of {}", c_str.to_str().unwrap());
                continue; // lmao
            }
        }
        // I got really stuck at this: Should I do this with result_name or not? since in the original decryption tool it does an in-place overwrite. I don't have to explain why this is highly dangerous. So I'm just skeptical about this for now
        else if &name[..4] == b"01g:" && ctx.g_tables[1].len() > 0 {
            if !(find_table_path(&ctx.g_tables[1], ctx.g_tables[1].len(), &name[4..], &mut result_name)) {
                let c_str = CStr::from_bytes_until_nul(&result_name).unwrap();
                println!("Error: 01g cannot find path of {}", c_str.to_str().unwrap());
                continue; // lmao
            }
        }
        else if &name[..4] == b"02g:" && ctx.g_tables[2].len() > 0 {
            if !(find_table_path(&ctx.g_tables[2], ctx.g_tables[2].len(), &name[4..], &mut result_name)) {
                let c_str = CStr::from_bytes_until_nul(&result_name).unwrap();
                println!("Error: 02g cannot find path of {}", c_str.to_str().unwrap());
                continue; // lmao
            }
        }

        let sz_file_base: &[u8] = 
        if let Some(index) = name.iter().rposition(|&b| b == b'/') {
            &name[index+1..]
        } else {
            b"err.err"
        };

        let mut sz_data_path = String::new();
        let mut found = 0;

        // Moved out of the switch statement since it was repeated
        let end = name.iter().position(|&b| b == 0).unwrap();
        let suffix = std::str::from_utf8(&name[8..end]).unwrap();

        let name_str = CStr::
            from_bytes_until_nul(&name)
            .map_err(|_| PspError::StringRepresentation)?
            .to_str()
            .unwrap();

        if &name[..8] == b"flash0:/" {
            // to_owned since out_dir is &str
            sz_data_path = out_dir.to_owned() + "/F0/" + suffix;
            std::fs::create_dir_all(&sz_data_path)?;
            found = 1;
        } else if &name[..8] == b"flash1:/" {
            sz_data_path = out_dir.to_owned() + "/F1/" + suffix;
            found = 1;
            std::fs::create_dir_all(&sz_data_path)?;
        } else {
            for table_name in G_TABLE_FILENAMES {
                if name_str == table_name.0 {
                    let size = psp_decrypt_table(&mut data_2, &mut data_1, cb_expanded, ctx.psar_version, ctx.table_mode);
                    let index: usize = table_name.1 as usize;
                    ctx.g_tables[index].resize(size, 0);
                    ctx.g_tables[index].copy_from_slice(&data_2[..size]);

                    sz_data_path = {
                        if table_name.1 == 0 {
                            format!("{}/PSARDUMPER/common_files_table.bin", out_dir)
                        } else {
                            // sprintf(modelNum, "%05d", tableName.second);
                            format!("{}/PSARDUMPER/{:05}_files_table, ",out_dir, table_name.1)
                        }
                    };
                    found = 1;
                    break;
                }
            }
        }

        if found == 0 {
            let filename = name_str.rsplit('/').next().unwrap_or(name_str);
            sz_data_path = out_dir.to_owned() + "/PSARDUMPER/" + filename;
        }

        println!("{sz_data_path}");
        println!("{found}");

        // I can't do cb_expanded... And this is why:
        // First: decrypt_prx in this context it doesn't do an in-place decryption... It stores the result in data_1. And if I call decrypt_prx, I might replace data from data_2 that can be useful in the near future. However now that I think of it: I can copy data_2 into data_1 and only send data_1 while doing decrypt_prx... Let's try that
        if cb_expanded > 0 {
            log_str += "expanded";

            // If we don't decrypt modules, or for non-encrypted models
            if extract_only || data_2[..4] == *b"~PSP" {
                // Here we check if the ipl file is not a kirk1, which means it needs predecryption
                if !extract_only && 
                    name.starts_with(b"ipl:") && 
                    u32::from_le_bytes(data_2[0x60..0x60+4].try_into().unwrap()) != 1u32 && 
                    u32::from_le_bytes(data_2[0x60..0x60+4].try_into().unwrap()) != 0x10001 
                {
                    data_1 = data_2;

                    let mut key_array = [0u8;16];
                    let usize_bytes = cb_expanded.to_le_bytes();
                    key_array[..usize_bytes.len()].copy_from_slice(&usize_bytes);
                    cb_expanded = decrypt_prx(&mut data_1, Some(&key_array))?;

                    if cb_expanded <= 0 {
                        log_str += ", pre-decrypt failed";
                    } else {
                        log_str += ", pre-decrypt good hehe";
                        // memcpy(data2, data1, cbExpanded);
                        data_2[..cb_expanded].copy_from_slice(&data_1);
                    }
                }

                if write_file(&sz_data_path, &data_2, cb_expanded).is_err() {
                    println!("Cannot write {}", sz_data_path);
                    break;
                }
                log_str.push_str(", saved");

                // let's make a slight patch for testing
                let pb_to_save = data_2.clone();

                if check_extract_reboot (
                    &name, 
                    // before it was &data_2
                    &pb_to_save, 
                    cb_expanded.try_into().unwrap(), 
                    &mut data_1, 
                    &mut data_2, 
                    out_dir, 
                    extract_only, 
                    &mut log_str
                ) < 0 {
                    log_str.push_str(", error extracting/decrypting reboot.bin");
                }
            }

            // For encrypted ~PSP Modules, or ME images, if decrypting is not disabled
            if data_2[..4] == *b"~PSP" || name[..b"flash0:/kd/resource/me".len()] == *b"flash0:/kd/resource/me" && !extract_only{
                // I don't understand why i did this in the first place...
                // data_1.copy_from_slice(&data_2);
                // let mut seed = [0u8;16];
                // let cb_bytes = (cb_expanded as u32).to_le_bytes();
                // seed[..4].copy_from_slice(&cb_bytes);
               

                data_1.copy_from_slice(&data_2);

                let cb_decrypted: usize = decrypt_prx_out_place(&mut data_1, Some(&seed)).unwrap();


                if cb_decrypted > 0 {
                    let mut pb_to_save: &mut [u8] = &mut data_1;
                    let cb_to_save: u32 = cb_decrypted as u32;







                    log_str += ", decrypted";
                    let end_ptr: &[u8];
                    let cb_remain = 0;

                    if data_1[0] == 0x1F && data_1[1] == 0x8B || data_1[..4] == *b"23LZ" || data_1[..4] == *b"KL4E" {

                        let cb_exp = psp_decompress (
                            &data_1, 
                            cb_to_save as u32, 
                            &mut data_2, 
                            3000000, 
                            &mut log_str, 
                            // None since I don't really need an endpointer for safety purposes and because I already make sure that the decompression is made entirely without remainders
                            None,
                        );
                        // I don't really need this
                        // cb_remain = data_1 + cb_to_save - end_ptr;

                        if cb_exp > 0 {
                            log_str += ",expanded";
                            pb_to_save = &data_2;
                            cb_to_save = cb_exp as usize;
                        } else {
                            log_str.push_str(", error decompressing");
                        }
                    }
                }

                if write_file(&sz_data_path, pb_to_save, cb_to_save).unwrap() != cb_expanded {
                    println!("Cannot write {}", sz_data_path);
                    break;
                }
                log_str += ", saved!!!";

    // fn check_extract_reboot(name: &[u8], pb_to_save: &[u8], cb_to_save: u32, data_1: &mut [u8], data_2: &mut [u8], out_dir: &str, extract_only: bool, log_str: &mut String) -> i32 {
                // Fix this
                if check_extract_reboot(
                    &name, 
                    pb_to_save, 
                    cb_to_save as u32, 
                    &mut data_1, 
                    &mut data_2, 
                    out_dir, 
                    extract_only, 
                    &mut log_str
                ) < 0 {
                    log_str.push_str(",error extracting/decrypting reboot.bin"); 
                }
                
                // if check_extract_reboot(&name, pb_to_save, cb_to_save, &mut data_1, &mut data_2, out_dir, extract_only, &mut log_str) < 0 {
                //     log_str += ", error extracting/decrypting reboot.bin"
                // }

                // I don't think I need it this...
                // if (cbRemain > 0) {
                //     u8 *endPtr2;
                //     logStr += "Has part2";
                //     int cbExp = pspDecompress(endPtr, cbRemain, data2, 3000000, logStr, &endPtr2);
                //     if (cbExp > 0) {
                //         logStr += ",decompressed,saved!";
                //         if (endPtr + cbRemain - endPtr2 != 0) {
                //             logStr += "Error: garbage at end.";
                //         }
                //         if (WriteFile((szDataPath + ".2").c_str(), data2, cbExp) != cbExp)
                //         {
                //             printf("Error writing %s.\n", (szDataPath + ".2").c_str());
                //         }
                //     } else {
                //         logStr += ",error decompressing!";
                //     }
                // }
            }
            else {
                let tag_str = u32::from_le_bytes(data_2[0xD0..0xD0+4].try_into().unwrap());
                let tag_str_formatted = format!("{:08}", tag_str);
                log_str += &(", error during decryption [tag ".to_owned() + &tag_str_formatted + "].");
            }
        }
        //testing
        else if (5 > 0) {

        }
    }

    Ok(())
}

fn psp_psar_init(data_psar: &[u8], data_out: &mut [u8], data_out_2: &mut [u8], ctx: &mut PsarContext) -> Result<usize, PspError> {
    let data_psar_magic: &[u8] = &[0x50, 0x53, 0x41, 0x52]; // this means "PSAR" in hex
    let header: &[u8] = &data_psar[0..4];

    if data_psar_magic == header {
        println!("It's a PSAR file!!!");
    } else {
        println!("It's not a PSAR file!!!");
        return Err(PspError::DecryptionFailed)?
    }

    // 3.5X M33, and 3.60 unofficial psar's
    if data_psar.len() < 0x24 {
        return Err(PspError::TooShort);
    }

    // This is for checking if it was decrypted or not
    let layout_marker =
        u32::from_le_bytes(data_psar[0x20..0x24].try_into().unwrap());
    ctx.decrypted = layout_marker == 0x2C333333;

    ctx.overhead = {
        if ctx.decrypted { 0 } else { 0x150 }
    };

    // //oldschool = (dataPSAR[4] == 1); /* bogus update */
    // psarVersion = dataPSAR[4];
    // This is the original code. ImHex with the script from https://gist.github.com/playday3008/0c8ba916ba3b1c4f52654db6e3f85109 we can clearly see that the lo is 2 bytes size. But since I'm sticking to the decryption tool, I think I might use 1 byte then
    // ctx.psar_version = u16::from_le_bytes(data_psar[4..6].try_into().unwrap());
    ctx.psar_version = data_psar[4];
    
    let mut cb_out = decode_block(&data_psar[0x10..], ctx.overhead + SIZE_A, data_out, ctx)?;

    if cb_out <= 0 {
        return Err(PspError::TagNotFound);
    }

    if cb_out != SIZE_A
    {
        return Err(PspError::DecryptionFailed);
    }

    ctx.i_base = 0x10+ctx.overhead+SIZE_A;
    // i_base points to the next block to decode (0x10 aligned)

    if ctx.decrypted {
        cb_out = decode_block(
            &data_psar[0x10+ctx.overhead+SIZE_A..], 
            data_out[0x90] as usize, 
            data_out_2, 
            ctx, 
        )?;

        if cb_out <= 0 {
            return Err(PspError::DecryptionFailed);
        }

        ctx.i_base += ctx.overhead+cb_out;
        return Ok(0);
    }

    // ANALYZE THE ENTIRE THING HERE
    if ctx.psar_version != 1 {
        // Analyze this because I THINK IS WRONG... OR NOT
       cb_out = decode_block(
            &data_psar[0x10+ctx.overhead+SIZE_A..], 
            ctx.overhead+144, 
            data_out_2, ctx
        )?;
        println!("{}",cb_out);
        if cb_out <= 0 {
            // cb_out = decode_block(p_in, cb_in, p_out, ctx)
            // if (cb_out <= 0) {
            //     return Err(PspError::DecryptionFailed);
            // }
        }
        
    }

    // random number
    Ok(219358712)
}


// let cb_out = decode_block(
// &data_psar[0x10..], 
// ctx.overhead + SIZE_A, 
// data_out)?;
fn decode_block(
    p_in: &[u8],
    cb_in: usize,
    p_out: &mut [u8],
    ctx: &PsarContext,
) -> Result<usize, PspError> {

    if ctx.decrypted {
        p_out[..cb_in].copy_from_slice(&p_in[..cb_in]);
        return Ok(cb_in)
    }

    // memcpy(pOut, pIn, cbIn + 0x10); // copy a little more for $10 page alignment
    // The same would be
    // Check dev_notes/notes.md to get a deep summary about why whe add 0x10 to the equation
    p_out[..cb_in + 0x10].copy_from_slice(&p_in[..cb_in+0x10]);


    // If psar_version != 1 we have to demanlge the inside 130 bytes...
    if ctx.psar_version != 1 {
        demangle_psar_header(&p_in[0x20..], &mut p_out[0x20..], ctx)?;
    }

        
    // Technically we ain't sending the seed, look at this. I WAS HITTING A WALL SINCE I THOUGH I WAS SENDING A SEED, BUT COULDN'T FIND WHERE
    // cbOut = pspDecryptPRX(pOut, pOut, cbIn);
    let cb_out = decrypt_prx(&mut p_out[..cb_in], None)?;

    Ok(cb_out)
}

// for 1.50 and later, they mangled the plaintext parts of the header
fn demangle_psar_header(p_in: &[u8], p_out: &mut [u8], ctx: &PsarContext) -> Result<(), PspError> {
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
    if p_in.len() < 0x130 || p_out.len() < 0x130 {
        eprintln!("Error: Chunk too small to demangle");
        return Err(PspError::SizeError);
    }

    // Copy encrypted payload into our working buffer
    buffer[20..(20+0x130)].copy_from_slice(&p_in[..0x130]);

    if ctx.psar_version == 5 { 
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
        
    if ctx.psar_version == 5 {
        for i in 0..0x130 {
            buffer[i] ^= k2[i % 16];
        }
    }

    p_out[..0x130].copy_from_slice(&buffer[..0x130]);

    Ok(())
}

fn execute_kirk_cmd7(buffer: &mut[u8]) -> Result<(), PspError> {
    // twelve because 4 times 3 = 12
    // Safely builds the 32-bit ID from 4 bytes, avoiding pointer-casting UB and Alignment Faults.
    let key_id = i32::from_le_bytes (
        buffer[12..16]
        .try_into()
        .map_err(|_| PspError::InvalidHeader)?
    );

    kirk7(&mut buffer[20..(20+0x130)], key_id)
            .map_err(|_| PspError::DecryptionFailed)?;
    
    buffer.copy_within(20..(20+0x130), 0);
    Ok(())
}


// let int_version = get_version(&data_1[0x10..0x14]);
// Explanation at PBP_notes.md
fn get_version(version_bytes: &[u8;4]) -> Result<u32, PspError> {
    let version_str = std::str::from_utf8(version_bytes)
    .map_err(|_| PspError::DecryptionFailed)?;

    println!("Firmware version: {}", version_str);

    // nth(1) means give me the second character in this string.
    // I can convert this into a Vec<char> and then compare it easily... but it's redundant since I'm allocating memory for something that isn't significant
    if version_str.chars().nth(1) != Some('.') || version_str.len() != 4 {
        eprintln!("Invalid version!?");
        return Err(PspError::ValidationFailed);
    }

    // Now let's convert it into integer!!!
    let int_version: u32 = version_str
        .replace(".", "")
        .parse()
        .map_err(|_| PspError::DecryptionFailed)?;


    Ok(int_version)
}

fn setup_extraction_folders(outdir: &str) -> io::Result<()> {
    // 1. Create a Path object out of the user's output directory
    let base_path = Path::new(outdir);

    // 2. create_dir_all acts like `mkdir -p` in Linux
    fs::create_dir_all(base_path)?;

    fs::create_dir_all(base_path.join("F0"))?;
    fs::create_dir_all(base_path.join("F1"))?;
    fs::create_dir_all(base_path.join("PSARDUMPER"))?;

    println!("Safe-room environment folders created successfully!");

    Ok(())
}


fn psp_psar_get_next_file(data_psar: &[u8], data_out: &mut [u8;3000000], data_out_2: &mut [u8;3000000], name: &mut [u8;128], ret_size: &mut usize, pos: &mut u32, sign_check: &mut bool, ctx: &mut PsarContext) -> Result<bool, PspError> {
    let mut cb_out: usize;

    // C++ Version:
    // if (iBase >= (cbFile-OVERHEAD)) { return 0; }

    // Rust Version:
    // data_psar.len() IS the cbFile (the total size of the PSAR)
    if ctx.i_base >= (data_psar.len() - ctx.overhead) {
        // We reached the end of the file, so we return false
        return Ok(false); 
    }

    cb_out = decode_block(
        &data_psar[ctx.i_base..], 
        ctx.overhead + SIZE_A,
        data_out, 
        ctx
    )?;

    if cb_out <= 0 {
        return Err(PspError::DecryptionFailed)
    }

    // Still don't know why if cb_out != 0x110 then the decryption failed... Now I'm trying to figure it out why
    // What I discover is: Sony designed the PSAR format so that every single file's shipping is eactly 272 bytes long without exceptions!!!
    // So if cb_out == 272 then the decoding was a success and we didn't lose any sort-of data
    if cb_out != SIZE_A {
        return Err(PspError::DecryptionFailed)
    }

    // string copy again?? sheeesh...
    // strcpy(name, (const char*)&dataOut[4]);
    // u32* pl = (u32*)&dataOut[0x100];
    // *signcheck = (dataOut[0x10F] == 2);
    // Something is really weird: when they call pspgetnextfile in the original C code, it sends garbage data, since they only declare the array without any sort of data. Thus it just sends garbage data... But why?????????????/
    // char name[128]; And then right after that:
    // int res = pspPSARGetNextFile(dataPSAR, size, data1, data2, name, &cbExpanded, &pos, &signcheck);
    // ????? WHY???
    // search through this array and find the exact index of the C-style Stop Sign (0)...
    let name_size = data_out[4..].iter().position(|&b| b == 0).unwrap_or(0);

    // And then since we know exactly where the text stops, we copy
    name[..name_size].copy_from_slice(&data_out[4..4 + name_size]);

    // Design decision: use bool instead of int *signcheck
    *sign_check = data_out[0x10F] == 2;


    // rewriting the comments from the original tool
    // pl[0] is 0
    // pl[1] is the PSAR chunk size (including OVERHEAD)
    // pl[2] is true file size (TypeA=272=SIZE_A, TypeB=size then expanded) Ok this is very important, I should write it down
    // pl[3] is flags or version? Lozi: Wait so they don't know exactly where pl[3] stores? really interesting...

    // u32* pl = (u32*)&dataOut[0x100];
    // *signcheck = (dataOut[0x10F] == 2);
    // This is so risky, because it changes the memory stride.. Therefore I might use another way of doing this thing...

    // u32 means 4 * 8, then we gotta convert it that range into u32_from_little_endian bytes!!!
    // if (pl[0] != 0)
    // {
    //     return -1;
    // }
    // pl[0] != 0 check
    let pl_0 = u32::from_le_bytes(data_out[0x100..0x104].try_into().unwrap());
    if pl_0 != 0 {
        return Err(PspError::InvalidHeader); 
    }

    ctx.i_base += ctx.overhead + SIZE_A;

    let cb_data_chunk: u32 = u32::from_le_bytes(data_out[0x104..0x108].try_into().unwrap());
    let mut cb_expanded: u32 = u32::from_le_bytes(data_out[0x108..0x108+4].try_into().unwrap());

    if cb_expanded > 0 {
        cb_out = decode_block(
            &data_psar[ctx.i_base..], 
            cb_data_chunk as usize, 
            data_out, 
            ctx
        )?;

        // Explaining why this at PBP_notes.md section (439 line of code explanation)
        if cb_out > 10 && data_out[0] == 0x78 && data_out[1] == 0x9C {
            println!("Moneda Billete");
            // Explanation about ZlibDecoder at PBP_NOTES.md section ZLibDecoder
            let mut decoder = ZlibDecoder::new(&data_out[..cb_out]);
            // read_exact keeps calling read() internally until it has filled exactly cb_expanded bytes OR returns an error
            decoder.read_exact(&mut data_out_2[..cb_expanded as usize])?;
            *ret_size = cb_expanded as usize;
        } else {
            ctx.i_base -= ctx.overhead + SIZE_A;
            // Up to this point I think I have to make a refactoring of error headers... I'm using this one too many and it can lead to missunderstanding
            return Err(PspError::DecryptionFailed);
        }
    } else if cb_expanded == 0 {
        *ret_size = 0;
    }
    else {
        return Err(PspError::DecryptionFailed);
    }

    ctx.i_base += cb_data_chunk as usize;
    *pos = ctx.i_base as u32;

    Ok(true) // if it returns true, it means that there are more files!!!
}


// I don't think is neccessary to return a PspError
fn is_5_d_num(name: &[u8; 128]) -> bool {
    let real_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());

    if real_len != 5 {
        return false;
    }

    for character in &name[..real_len] {
        if *character < b'0' || *character > b'9' {
            return false;
        }
    }
    true
}

// found = find_table_path(table, table.len(), name, result_name);
fn find_table_path(
    table: &[u8],
    len: usize,
    name: &[u8],
    result_name: &mut [u8],
) -> bool {

    if table.len() >= 5 {
        for i in 0..(table.len() - 5) {
            if name[..5] == table[i..i+5] {
                // declaring my iterators outside the loop
                let mut j = 0;
                let mut k = 0;
                
                // This loop I think I've made the translation perfectly. But I'm somewhat skeptical about that statement. So maybe this is subject of changes in the future when I start doing the tests.
                loop {
                    // SAFETY FIRST: Stop if we somehow reach the end of the table or result array early
                    if i + j + 6 >= table.len() || k >= result_name.len() {
                        break;
                    }

                    if table[i+j+6] < 0x20 {
                        result_name[k] = 0;
                        break;
                    }

                    if table[i + 5] == b'|' 
                        && &table[i+6..i+11] == b"flash" 
                        && j == 6 
                    {
                        result_name[6] = b':';
                        result_name[7] = b'/';
                        k += 1;
                    }
                    else if table[i+5] == b'|' 
                        && &table[i+6..i+9] == b"ipl"
                        && j == 3 
                    {
                        result_name[3] = b':';
                        result_name[4] = b'/';
                        k += 1;
                    }
                    else {
                        result_name[k] = table[i+j+6];
                    }
                    j += 1;
                    k += 1;
                }
                return true;
            }
        }
    }
    false
}


// just in case I use size since i don't know which size inside the fat pointer uses. Technically it must be input, but since the original tool does weird things such as in-data extraction and some sort. I prefer being cautious
fn find_reboot(input: &[u8], output: &mut [u8]) -> i32 {
    // making sure it doesn't do undefined behavior. Therefore I don't need "size" parameter just like C does.
    if input.len() < 0x30 {
        return -1
    }
    let mut size = -1;

    //
    for i in 0..input.len() - 0x30 {
        // I'm gonna use the len() tbh, since size isn't an usize...
        // de-reference since it's a static reference, therefore If I want this to be comparable, I have to use "*"
        if input[i..i+4] == *b"~PSP" {
            // size = *(u32 *)&input[i+0x2C]; I have  aproblema with this: I can just make this an u32 and send a range, but I don't know If "size" is gonna go PAST those bytes, therefore it's risky to do that. However just to make a "patch" I'm gonna use u32::from_le_bytes even though we aren't considering more bytes. Because of what I'm currenlty seing In imhex. This is just an hypothesis
            size = i32::from_le_bytes(input[i+0x2C.. i+0x2C + 4].try_into().unwrap());
            // memcpy(output, input+i, size); input means the start of input + displacement of i
            output[..size as usize].copy_from_slice(&input[i..size as usize]);
            return size;
        }
    }
    size
}

// don't need loadexec_data_size since load_exec_data is a fat pointer, therefore it contains the size inside
fn extract_reboot(load_exec_data: &[u8], reboot: &[u8], reboot_name: &[u8], data_1: &mut [u8], data_2: &mut [u8], extract_only: bool, log_str: &mut String) -> i32 {
    data_1[..load_exec_data.len()].copy_from_slice(load_exec_data);

    if &load_exec_data.len() <= &(0 as usize) {
        return -1;
    }

    // let name_reboot = CStr::from_bytes_until_nul(reboot_name).unwrap();
    // let name_str = name_reboot.to_str().unwrap_or("UNKNOWN");
    // yeah, I like this way better
    let Ok(name_reboot) = CStr::from_bytes_until_nul(reboot_name) else {
        return -1;
    };

    let Ok(name_str) = name_reboot.to_str() else {
        return -1;
    };
    
    *log_str += " Extracting "; 
    *log_str += name_str;

    let s = find_reboot(data_1, data_2);
    if s <= 0 {
        // unsecure but IM STRONGLY SURE THAT THIS IS CORRECT.... I think
        let name_cstr = CStr::from_bytes_until_nul(reboot_name).unwrap();
        println!("Cannot find {} inside loadexec. \n", name_cstr.to_str().unwrap());
    }

    let Ok(reboot_cstr) = CStr::from_bytes_until_nul(&reboot) else {
        return -1;
    };
    let reboot_str = reboot_cstr.to_str().unwrap();

    if extract_only {
        if write_file(reboot_str, data_2, s as usize).unwrap() != s as usize {
            println!("Cannot write {reboot_str}");
            return -1;
        }

        return 0;
    }

    // lets see if this works
    data_1.copy_from_slice(data_2);
    let s_usize: usize = decrypt_prx(data_1, None).unwrap();

    if s_usize <= 0 {
        // println!("Cannot decrypt {} \n", name_reboot);
        return -1;
    }
    log_str.push_str(", decrypted");

    let _ = write_file(reboot_str, data_1, s as usize);

    let s = psp_decompress(
        data_1, 
        DATA_SIZE as u32, 
        data_2, 
        DATA_SIZE as u32, 
        log_str,
        None
    );
    if s <= 0 {
        println!("Cannot decompress {reboot_str}, {s:08X}");
    }

    if write_file(reboot_str, data_2, s as usize).unwrap() != s as usize {
        println!("Cannot write {reboot_str}. \n");
        return -1;
    }

    *log_str += ", done.";

    0
}

// THIS IS INCOMPLETED SINCE I HAVEN'T WRITTEN EXTRACT_REBOOT FUNCTION YET!!!
fn check_extract_reboot(name: &[u8], pb_to_save: &[u8], cb_to_save: u32, data_1: &mut [u8], data_2: &mut [u8], out_dir: &str, extract_only: bool, log_str: &mut String) -> i32 {
    if name == b"flash0:/kd/loadexec.prx" {
        // return extract_reboot(pb_to_save, (out_dir + "/PSARDUMPER/reboot.bin"),"reboot.bin".as_bytes(),data_1, data_2, extract_only, log_str);
    } else if name == b"flash0:/kd/loadexec_" {
        if name.len() == b"flash0:/kd/loadexec_00g.prx".len() {
            let mut filename : &[u8] = b"reboot_00g.bin";
            // filename[b"reboot_".len()] = name[b"flash0:/kd/loadexec_".len()];
            // filename[b"reboot_".len() + 1] = name["flash0:/kd/loadexec_".len() + 1];
            // return extract_reboot(pb_to_save, (out_dir + "/PSARDUMPER/" + filename), filename, data_1, data_2, extract_only, log_str);
        }
        return -1
    }
    0
}



#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_block_fast_path() {
        // First. We setup a fake context that says the file is already decrypted.
        let mut ctx = PsarContext::new();
        ctx.decrypted = true;

        // 2. Setup our inputs and outputs
        let input_data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut output_buffer: [u8; 10] = [0; 10]; // Slightly larger buffer

        // 3. Call the function
        let result = decode_block(&input_data, 4, &mut output_buffer, &ctx);

        // 4. Assertions
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4); // Should return cb_in (4)
        assert_eq!(&output_buffer[..4], &[0xDE, 0xAD, 0xBE, 0xEF]); // Data should be perfectly copied
    }

}


