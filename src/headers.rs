use crate::kirk_lib::kirk_engine::kirk7;

// 144 bytes just to make it clear
pub fn expanded_seed(seed: &[u8; 16], key: i32, bonus_seed: Option<&[u8;16]>) -> [u8; 0x90] {
    let mut expanded_seed = [0u8; 0x90];

    // Lógica para la expansión de la seed
    // Vamos saltando de 16 a 16, comenzando desde el principio
    // En C++, hacían un for (auto i = 0u; i < expandedSeed.size(); i += 0x10)
    for i in (0..0x90).step_by(0x10) {
        expanded_seed[i..i+0x10].copy_from_slice(seed);
        // Despues modificamos el primer byte de este bloque para que actúe como contador
        expanded_seed[i] = (i / 0x10) as u8;
    }

    // TODO: Implementar kirk7. 
    // En C++ sería: kirk7(expandedSeed.data(), expandedSeed.data(), expandedSeed.size(), key);
    // En Rust sería algo parecido a esto:
    kirk7(&mut expanded_seed, key);
    if let Some(bonus) = bonus_seed {
        // Recorremos los 144 bytes de la semilla ya expandida y encriptada
        for i in 0..0x90 {
            // Hacemos un XOR (^=) entre el byte actual y el byte correspondiente del bonus.
            // Como el bonus solo tiene 16 bytes, usamos el módulo (%) para que repita del 0 al 15
            expanded_seed[i] ^= bonus[i % 0x10];
        }
    }
    // Retornamos el arreglo estático
    expanded_seed
}


pub fn decrypt_kirk_header(
    outbuf: &mut [u8; 0x40], 
    inbuf: &[u8; 0x40],      
    xorbuf: &[u8],           
    key_id: i32,
) {
    for i in 0..0x40 {
        outbuf[i] = inbuf[i] ^ xorbuf[i];
    }

    // (Como outbuf es un arreglo de 64, Rust lo convierte a un slice automáticamente para kirk7)
    kirk7(outbuf, key_id);

    // XOR con los siguientes 64 bytes (64 a 127)
    // Usamos i + 0x40 para reemplazar el peligroso *xorbuf++ de C++, demasiado viejo esa práctica pero mejor este enfoque para más seguridad
    for i in 0..0x40 {
        outbuf[i] = outbuf[i] ^ xorbuf[i + 0x40]; //Hacemos +0x40 para así realizar XOR al resto del slice, ya que hicimos de 0 a 0x40 pues ahora tenemos que hacer para adelante
    }    
}


#[cfg(test)]
mod tests {
    use super::*; // Con esto importamos todo lo que se encuentra dentro del archivo

    #[test] // Esta etiqueta lo que hace es convertir la funcion de abajo en un caso de prueba
    fn test_decrypt_kirk_header_no_crash() {
        let mut outbuf = [0u8; 0x40]; // empty box
        let inbuf = [0xAA; 0x40];     // 64 bytes of encrypted header
        let xorbuf = [0xBB; 144];     // 144 bytes of expanded seed
        let key_id = 1;

        decrypt_kirk_header(&mut outbuf, &inbuf, &xorbuf, key_id);

        assert_ne!(outbuf, [0u8; 0x40], "Error! El outbuf no se modificó en absoluto");
    }

}