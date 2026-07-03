use crate::{PsarContext, PspError, SIZE_A};
use crate::prx_types::decrypt_prx;
use crate::kirk7;
const DATA_SIZE: usize = 3000000;


pub fn psp_decrypt_psar(data_psar: &[u8], out_dir: &[u8], ctx: &mut PsarContext) -> Result<(), PspError> {
    // kirk_init: but not neccessary
    let magic: [u8; 4] = data_psar[..4]
        .try_into()
        .map_err(|_| PspError::TooShort)?;

    if &magic != b"PSAR" {
        eprintln!("Invalid PSAR magic");
        return Err(PspError::ValidationFailed);
    }

    let mut data_1: [u8; DATA_SIZE] = [0u8; DATA_SIZE];
    let mut data_2: [u8; DATA_SIZE] = [0u8; DATA_SIZE];

    println!("PSAR Version: {}", ctx.psar_version);

    psp_psar_init(data_psar, &mut data_1, &mut data_2, ctx)?;

    // char version[10];
    // strncpy(version, GetVersion((char *)data1+0x10), 10);
    // version[9] = '\0';
    // printf("Firmware version %s.\n", version);
    // if (version[1] != '.' || strlen(version) != 4) {
    //     printf("Invalid version!?\n");
    //     return 1;
    // }
    // int intVersion = (version[0] - '0') * 100 + (version[2] - '0') * 10 + version[3] - '0';
    // int table_mode;

    




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