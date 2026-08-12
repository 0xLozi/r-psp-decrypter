use std::fs::File;
use std::io::{Read, Write};
use zlib_rs::{Deflate, Inflate, InflateFlush, Status};

use flate2::bufread::{GzDecoder, ZlibDecoder};

pub fn write_file(file_name: &str, buf: &[u8]) -> std::io::Result<usize> {
    let mut file = File::create(file_name)?;
    // Explanation of why write_all() at reverse_engineering_notes.md
    file.write_all(buf)?;
    Ok(buf.len())
}

// The old C caller may provide a buffer which his physical size is larger than the amount of data that this particular decompression operation is supposed to consume. So just in case I also add in_size and out_size as a parameter rather than using the fat_pointer size that is beign store inside him
pub fn gunzip(inbuf: &[u8], in_size: usize, outbuf: &mut [u8], out_size: usize, real_in_size: Option<&mut u32>, no_header: bool) -> i32 {
    // inflateInit() implicitly uses MAX_WBITS = 15 -> normal ZLIB Wrapper
    // inflateInit2() uses MAX_WBITS = 15 PLUS 16 = 31 -> GZLIP wrapper because 16 goes to GZIP wrapper and 15 goes to the deflate data windowbits
    if !no_header && (inbuf[0] != 0x1f || inbuf[1] != 0x8b) {
        println!("Invalid gzip\n");
        return -1;
    }

    let mut inflater = {
        if !no_header {
            Inflate::new(true, 16+15)
        } else {
            // In z-lib c++, when you don't specify window bits, it automatically defaults to 15
            Inflate::new(true, 15)
        }
    };

    let ret = inflater.decompress(&inbuf[..in_size], &mut outbuf[..out_size], InflateFlush::NoFlush);

    match ret {
        Ok(Status::Ok | Status::StreamEnd) => {
            //continue
        }
        Ok(Status::BufError) | Err(_) => {
            return -1;
        }
    }

    if let Some(real_value) = real_in_size {
        *real_value = inflater.total_in() as u32;
    }
    return inflater.total_out() as i32;
}