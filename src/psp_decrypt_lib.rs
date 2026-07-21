use crate::prx_types::decrypt_prx;


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

    decrypt_t(buf2, size, mode);

    if psar_version == 4 { 
        buf1[..size].copy_from_slice(buf2);
    } else {
        ret_size = decrypt_prx(buf2, None).unwrap_or(0);
    }

    ret_size
}

fn decrypt_t(buf2: &mut [u8], size: usize,) {
    // DES_key_schedule schedule;
    // What does that even mean? 💀 Maybe a struct inside the file? mhhm, a timer?
    // I think is being imported with another library, since it's not a custom struct.. Let's research about it
    // des_key_sched(3) - Linux man page
    // #include <openssl/des.h> gotcha!!!, is the fourth import inside pspdecrypt_lib.cpp






}