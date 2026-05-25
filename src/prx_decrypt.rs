

pub fn decrypt_prx(binario_eboot: &[u8]) {
    // Primero agarra el tag (el cual se encuentra un el offset 0xD0)
    let bytes_tag_offset: [u8; 4] = binario_eboot[0xD0 .. 0xD0 + 4]
    .try_into()
    .unwrap();

    let tag: u32 = u32::from_le_bytes(bytes_tag_offset);


    
    
    
}