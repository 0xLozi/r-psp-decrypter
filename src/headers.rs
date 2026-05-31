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




#[derive(Debug)]
pub struct PrxType0 {
    tag: u32, 
}


impl PrxType0 {
    pub fn recortar() {
        println!("prueba")
    }
}


