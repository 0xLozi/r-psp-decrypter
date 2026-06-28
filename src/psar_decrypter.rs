use crate::{PsarContext, PspError, SIZE_A};

const DATA_SIZE: usize = 3000000;


pub fn psp_decrypt_psar(data_psar: &[u8], out_dir: &[u8], mut ctx: PsarContext) -> Result<(), PspError> {
    // kirk_init: but not neccessary
    let magic: [u8; 4] = data_psar[..4]
        .try_into()
        .map_err(|_| PspError::TooShort)?;

    if &magic != b"PSAR" {
        eprintln!("Invalid PSAR magic");
        return Err(PspError::ValidationFailed);
    }

    let data_1: [u8; DATA_SIZE] = [0u8; DATA_SIZE];
    let data_2: [u8; DATA_SIZE] = [0u8; DATA_SIZE];

    println!("PSAR Version: {}", ctx.psar_version);

    psp_psar_init(data_psar, &data_1, &data_2, ctx)?;
    


    // int res = pspPSARInit(dataPSAR, data1, data2);
    // if (res < 0)
    // {
    //     printf("pspPSARInit failed with error 0x%08X!.\n", res);
    // }




    Ok(())
}



fn psp_psar_init(data_psar: &[u8], data_out: &[u8], data_out_2: &[u8], mut ctx: PsarContext) -> Result<(), PspError> {
    let data_psar_magic: &[u8] = &[0x50, 0x53, 0x41, 0x52]; // this means "PSAR" in hex
    let header: &[u8] = &data_psar[0..4];

    if data_psar_magic == header {
        println!("It's a PSAR file!!!");
    } else {
        println!("It's not a PSAR file!!!");
        return Err(PspError::DecryptionFailed)?
    }


    // 3.5X M33, and 3.60 unofficial psar's
    ctx.decrypted = {
        if data_psar.len() < 0x24 {
            return Err(PspError::TooShort);
        };

        let magic_value = u32::from_le_bytes(
            data_psar[0x20..0x24].try_into().unwrap() // Here "unwrap" it's ok since we know it's exactly 4 bytes
        );

        magic_value == 0x2C333333
    };

    if ctx.decrypted {
        println!("True");
    }

    ctx.overhead = {
        if ctx.decrypted { 0 } else { 0x150 }
    };

    println!("{}", ctx.overhead);

    ctx.psar_version = u16::from_le_bytes(data_psar[4..6].try_into().unwrap());
    println!("{}", ctx.psar_version);
    
    let cb_out = decode_block(&data_psar[0x10..], ctx.overhead + SIZE_A, data_out)?;


    // uncomment after doing the ctx
    // let cb_out = decode_block(&data_psar[0x10..], overhead + SIZE_A, data_out);


    Ok(())
}

fn decode_block(p_in: &[u8], cb_in: usize, p_out: &[u8], ctx: PsarContext) -> Result<(), PspError> {
    if ctx.decrypted {
        if (p_in)

    }



    Ok(())
}