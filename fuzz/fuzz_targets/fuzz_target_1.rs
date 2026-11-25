#![no_main]
use r_psp_decrypter::prx::decrypt_prx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut inbuf = data.to_vec();
    let _ = decrypt_prx(&mut inbuf, &mut None, &mut None);
});
