// This suppresses standard Rust warnings for C-style naming conventions
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::{error_handling::errors::PspError, prx_types::decrypt_prx};
use aes::cipher::BlockDecryptMut;
use clap::Error;
use des::Des;
use cbc::Decryptor;
use des::cipher::block_padding::NoPadding;
use crate::common::gunzip;
use std::{ffi::c_void};

// The des crate automatically includes the cipher rulebook
// This gives Decryptor the ability to use .new()
use des::cipher::KeyIvInit;


// This built-in Rust macro tells the compiler: 
// "Go to the secret OUT_DIR, find 'bindings.rs', and paste all its code right here!"
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


//// THIS IS DES TABLE DECRYPTION /// 
struct TableKeys {
    key: [u8; 8],
    iv: [u8; 8],
}

// static TABLE_KEYS: [TableKeys; 6] = [
//     {{ 0x95, 0x62, 0x0B, 0x49, 0xB7, 0x30, 0xE5, 0xC7 }, { 0x9E, 0xA4, 0x33, 0x81, 0x86, 0x0C, 0x52, 0x85 }},
//     {{ 0x5A, 0x7B, 0x3D, 0x9D, 0x45, 0xC9, 0xDC, 0x95 }, { 0xB2, 0xFE, 0xD9, 0x79, 0x8A, 0x02, 0xB1, 0x87 }},
//     {{ 0x4C, 0xCE, 0x49, 0x5B, 0x6F, 0x20, 0x58, 0x5A }, { 0x81, 0x08, 0xC1, 0xF2, 0x35, 0x98, 0x69, 0xB0 }},
//     {{ 0x73, 0xF4, 0x52, 0x62, 0x62, 0x0B, 0xF1, 0x5A }, { 0x6D, 0x52, 0x1B, 0xA3, 0xC2, 0x36, 0xF9, 0x2B }},
//     {{ 0xA6, 0x64, 0xC8, 0xF8, 0xFD, 0x9D, 0x44, 0x98 }, { 0xDB, 0x4E, 0x79, 0x41, 0xF5, 0x97, 0x30, 0xAD }},
//     {{ 0xD7, 0xBD, 0x74, 0x81, 0x3D, 0x64, 0x26, 0xE7 }, { 0xA6, 0x83, 0x0C, 0x2F, 0x63, 0x0B, 0x96, 0x29 }},
// };

static TABLE_KEYS: [TableKeys; 6] = [
    TableKeys {
        key: [0x95, 0x62, 0x0B, 0x49, 0xB7, 0x30, 0xE5, 0xC7],
        iv:  [0x9E, 0xA4, 0x33, 0x81, 0x86, 0x0C, 0x52, 0x85],
    },
    TableKeys {
        key: [0x5A, 0x7B, 0x3D, 0x9D, 0x45, 0xC9, 0xDC, 0x95],
        iv:  [0xB2, 0xFE, 0xD9, 0x79, 0x8A, 0x02, 0xB1, 0x87],
    },
    TableKeys {
        key: [0x4C, 0xCE, 0x49, 0x5B, 0x6F, 0x20, 0x58, 0x5A],
        iv:  [0x81, 0x08, 0xC1, 0xF2, 0x35, 0x98, 0x69, 0xB0],
    },
    TableKeys {
        key: [0x73, 0xF4, 0x52, 0x62, 0x62, 0x0B, 0xF1, 0x5A],
        iv:  [0x6D, 0x52, 0x1B, 0xA3, 0xC2, 0x36, 0xF9, 0x2B],
    },
    TableKeys {
        key: [0xA6, 0x64, 0xC8, 0xF8, 0xFD, 0x9D, 0x44, 0x98],
        iv:  [0xDB, 0x4E, 0x79, 0x41, 0xF5, 0x97, 0x30, 0xAD],
    },
    TableKeys {
        key: [0xD7, 0xBD, 0x74, 0x81, 0x3D, 0x64, 0x26, 0xE7],
        iv:  [0xA6, 0x83, 0x0C, 0x2F, 0x63, 0x0B, 0x96, 0x29],
    },
];





pub fn psp_decrypt_table(
    buf1: &mut [u8], 
    buf2: &mut [u8], 
    size: usize, 
    psar_version: u8, 
    mode: u32
) -> usize {
    let mut ret_size: usize = 0;

    if buf1 != buf2 {
        buf2[..size].copy_from_slice(buf1);
    }

    decrypt_t(buf2, size, mode as usize);

    if psar_version == 4 { 
        buf1[..size].copy_from_slice(buf2);
    } else {
        ret_size = decrypt_prx(buf2, None).unwrap_or(0);
    }

    ret_size
}

fn decrypt_t(buf2: &mut [u8], size: usize, mode: usize) {
    let key = TABLE_KEYS[mode].key;
    let iv = TABLE_KEYS[mode].iv;
    let decryptor: Decryptor<Des> = Decryptor::new(&key.into(), &iv.into());

    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf2[..size])
        .expect("Decryption failed: Buffer size must be a multiple of 8!!!!!");
}


////// DECOMPRESSIOOOOOOOOOOOON /////
// Here inbuff_end was a &&[u8], but since it's an immutable pointer, I can't change where the decompression stopped and that stuff because of lifetime issues. Therefore I'm gonna change this and change inbuf_end into an i32
pub fn psp_decompress(inbuf: &[u8], in_size: u32, outbuf: &mut [u8], out_capacity: u32, log_str: &mut String, inbuf_end: Option<&mut u32>) -> i32 {
    let mut ret_size: i32 = 0; // idk

    if inbuf.len() < 2 {
        return -1;
    }
    // WHY WE SKIP MANUAL BUFFER TRACKING (cb_remain / inbufEnd / realSize):
    if inbuf[0] == 0x1F  && inbuf[1] == 0x8B {
        // retsize = gunzip(inbuf, insize, outbuf, outcapacity, &realSize);
        // I don't know if This implementation is correct. So Im gonna write it as how I think it is
        //In the original c++ tool, gunzip acted as a memory pipe. The dev had to manually calculate exactly how many compressed bytes were consumed and uptadte pointers so th eamin loop would know exactly where the next file chunk started
        // In Rust, we bypass this manual pointer math
        // By passing a byte slice into gzDecoder, we take advantage of Rust 'Read' trait. The decode treats the slice as a continuous data system. So as it decodes
        let mut real_size: u32 = 0;
        // inside common.h we have this s32 gunzip(u8 *inBuf, u32 inSize, u8 *outBuf, u32 outSize, u32 *realInSize = NULL, bool noHeader = false); Therefore since inside the original tool doesn't specify no_header, we send "false"
        ret_size = gunzip(inbuf, in_size as usize, outbuf, out_capacity as usize, Some(&mut real_size), false);

        if let Some(end) = inbuf_end {
            *end = real_size;
        }

        *log_str += ", gzip";
    } else if inbuf[..4] == *b"2RLZ" {

        let in_end_ptr: *mut c_void = std::ptr::null_mut();

        ret_size = unsafe {
            LZRDecompress (
                outbuf.as_mut_ptr() as *mut c_void,
                out_capacity,
                // this is wrong...
                inbuf[4..].as_ptr() as *mut c_void,
                in_end_ptr,
            )
        };

        *log_str += ",lzrc";
    } else if inbuf[..4] == *b"KL4E"{
        let mut in_end_ptr: *mut c_void = std::ptr::null_mut();
        ret_size = unsafe {
            decompress_kle (
                outbuf.as_mut_ptr(),
                out_capacity as i32,
                inbuf[4..].as_ptr() as *mut u8,
                &mut in_end_ptr,
                1,
            )
        };
        *log_str += "kl4e,"
    } else if inbuf[..4] == *b"KL3E" {
        let mut in_end_ptr: *mut c_void = std::ptr::null_mut();
        ret_size = unsafe {
            decompress_kle (
                outbuf.as_mut_ptr(), 
                out_capacity as i32, 
                inbuf[4..].as_ptr() as *mut u8, 
                &mut in_end_ptr, 
                0
            )
        };
        *log_str += "kl3e,";
    } else {
        ret_size = -1;
    }

    ret_size
}


//// HERE IS FOR IPL DECRYTPION ////
pub fn decrypt_ipl(in_data: &[u8], in_data_size: usize, version: u32, filename: &[u8], outdir: &mut String, pre_ipl: &[u8], pre_ipl_size: usize, verbose: bool, keep_all: bool, log_str: &mut String) -> i32 {
    // Ok so the easy way to create a dynamically-sized Vec with a specific initial length is to use the vec! macro!!!!
    let tmp_data = vec![0u8;in_data_size];

    // kirk_init()
    let cb1: i32 = psp_decrypt_ipl1(in_data, tmp_data, in_data_size, &mut log_str);

    if cb1 > 0 {
        println!("Something");
    }

    32
}

// Here the IPL Decryption
pub fn psp_decrypt_ipl1(pb_in: &[u8], pb_out: &[u8], cb_in: u32, log_str: &mut [u8]) -> i32 {
    let cb_out: u32 = 0;
    let xor_key_idx = -1;

    while cb_in >= 0x1000 {
        if pb_in[0x62] == 1 {
            let mut dec_data = [0u8;0x1000];

            dec_data.copy_from_slice(&pb_in[..0x1000]);

            dec_data[0x62] = 0;
            
            if xor_key_idx == -1 {
                for i in 0..0x7E0 {
                    // inside the original one, they send an u32 pointer casted, therefore it jumps 4 bytes per 4, not 1: u32 pointer to be precise. But this is highly risky, therefore I'm dealing with a solution to this manner
                    // let's see the options:
                    // 1. Create an u32 mutable pointer pointing into dec_data and pray that'll work
                    // 2. Do a conversion of the original descamble and convert it into an u8 function instead of a u32 one.
                    // First, let's see if inside pspdecyrpt_lib.cpp they use more than 1 time this specific function... Ok it seems that this function is used in many occasions. Therefore point "2" is not possible.
                    
                    // Ok I'm about to change descramble and use u8 instead of fdoing memory reinterpretation. This Explanation inside
                    descramble_03g(&mut dec_data, i); 

                }
            }

        }

    }
    1
}

// xor keys & original descrambling code thanks to Davee and Proxima's awesome work! //
// I think this is gonna be used for ONLY READING PURPOSES
const xorkeys: [u32;68] = [
    0x61A0C918, 0x45695E82, 0x9CAFD36E, 0xFA499B0F,
    0x7E84B6E2, 0x91324D29, 0xB3522009, 0xA8BC0FAF,
    0x48C3C1C5, 0xE4C2A9DC, 0x00012ED1, 0x57D9327C,
    0xAFB8E4EF, 0x72489A15, 0xC6208D85, 0x06021249,
    0x41BE16DB, 0x2BD98F2F, 0xD194BEEB, 0xD1A6E669,
    0xC0AC336B, 0x88FF3544, 0x5E018640, 0x34318761,
    0x5974E1D2, 0x1E55581B, 0x6F28379E, 0xA90E2587,
    0x091CB883, 0xBDC2088A, 0x7E76219C, 0x9C4BEE1B,
    0xDD322601, 0xBB477339, 0x6678CF47, 0xF3C1209B,
    0x5A96E435, 0x908896FA, 0x5B2D962A, 0x7FEC378C,
    0xE3A3B3AE, 0x8B902D93, 0xD0DF32EF, 0x6484D261,
    0x0A84A153, 0x7EB16575, 0xB10E53DD, 0x1B222753,
    0x58DD63D0, 0x8E8B8D48, 0x755B32C2, 0xA63DFFF7,
    0x97CABF7C, 0x33BDC660, 0x64522286, 0x403F3698,
    0x3406C651, 0x9F4B8FB9, 0xE284F475, 0xB9189A13,
    0x12C6F917, 0x5DE6B7ED, 0xDB674F88, 0x06DDB96E,
    0x2B2165A6, 0x0F920D3F, 0x732B3475, 0x1908D613
];


// Idea: Use Result return, and then add a conditional that checks if data.len() is higher than 16 and other conditionals that can fulfill the needs of the Rust compiler at a compile time and then I can be completely sure that this function will return something good or bad. or an error and then I can just catch that that error correctly. 
// Architecture Design in "design_architectures.md" section `descramble function`
fn descramble_03g(data: &mut [u8], i: u32) -> Result<(), PspError> {
    if data.len() < 16 {
        return Err(PspError::SizeError);
    }

    // Ok so if since id_x in order to use it as an index I have to use usize type, if the result of the math operation doesn't fit into xorkeys, it can panic. so I have to also deal with it
    // but unwrap here is not ox
    let id_x = ((i >> 5) & 0x3F) as usize;
    let rot: u32 = i & 0x1F;
    let mut x1 = xorkeys[id_x];
    let mut x2 = xorkeys[id_x+1];
    let mut x3 = xorkeys[id_x+2];
    let mut x4 = xorkeys[id_x+3];

    // x1 = (x1 >> rot) | (x1 << (0x20-rot));
    // x2 = ((x2 >> rot) | (x2 << (0x20-rot))).reverse_bits();
    // x3 = (x3 >> rot) | (x3 << (0x20-rot)) ^ x4;
    // x4 = (x4 >> rot) | (x4 << (0x20-rot));

    // "equal to" since rotate_right returns Self and it sends a self rather than a &mut self 
    x1 = x1.rotate_right(rot);
    x2 = x2.rotate_right(rot).reverse_bits();
    x3 = x3.rotate_right(rot) ^ x4;
    x4 = x4.rotate_right(rot);

    let keys = [x1, x2, x3, x4];

    // .zip() acts as like clean package-maker: it grabs items from both collections 
    // and then hands them to the loop perfectly paired, so we don't need 'i' indexes!!!!
    // we use chunks with size 4 since that's what the original tool does: copy using 4 bytes length
    for (chunk, &key) in data[0..16].chunks_exact_mut(4).zip(keys.iter()) {
        // First we convert the chunk into an u32
        // we can do unwrap since this is mathematically correct thanks to the range we are using
        let mut res = u32::from_le_bytes(chunk.try_into().unwrap());
        res ^= key;
        chunk.copy_from_slice(&res.to_le_bytes());
    }

    // let mut res_1 = u32::from_le_bytes(data[0..4].try_into().unwrap());
    // res_1 ^= x1;

    // let mut res_2 = u32::from_le_bytes(data[4..4+4].try_into().unwrap());
    // res_2 ^= x2;

    // let mut res_3 = u32::from_le_bytes(data[8..8+4].try_into().unwrap());
    // res_3 ^= x3;

    // let mut res_4 = u32::from_le_bytes(data[12..12+4].try_into().unwrap());
    // res_4 ^= x4;

    // data[0..4].copy_from_slice(&res_1.to_le_bytes()); 
    // data[4..8].copy_from_slice(&res_2.to_le_bytes());
    // data[8..12].copy_from_slice(&res_3.to_le_bytes());
    // data[12..16].copy_from_slice(&res_4.to_le_bytes());
    Ok(())
}
