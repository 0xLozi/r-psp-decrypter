use std::array::TryFromSliceError;


enum PspError {
    SliceError(TryFromSliceError),
    InvalidHeader,
    Io(std::io::Error),
}





















pub fn decrypt_prx(binario_eboot: &[u8]) {
    // Primero agarra el tag (el cual se encuentra un el offset 0xD0)
    let bytes_tag_offset: [u8; 4] = binario_eboot[0xD0 .. 0xD0 + 4]
    .try_into()
    .unwrap();

    let tag: u32 = u32::from_le_bytes(bytes_tag_offset);

    // como no sabemos el PRX type pues toca desencriptarlo de manera brute-force
    let resultado = pspDecryptTipo0(&binario_eboot);

}




pub fn pspDecryptTipo0(binario_eboot: &[u8]) { 
    // el size a desencriptar para los de tipo 0 se encuentra en 0xB0
    let offset_size_slice = &binario_eboot[0xB0 .. 0xB0 + 4];
    let arreglo_fijo: [u8;4] = offset_size_slice.try_into().unwrap();
    let decrypt_size = u32::from_le_bytes(arreglo_fijo);

    

    // const auto pti = GetTagInfo((u32)*(u32_le *)&inbuf[0xD0]);

	// if (!pti)
	// {
	// 	return -1;
	// }

    // const info_tag = get_tag_info(binario_eboot[0xD0]);






}