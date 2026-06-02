use thiserror::Error;

#[derive(Error, Debug)]
pub enum PspError {
    #[error("El archivo es demasiado pequeño para ser un PRX válido")]
    InvalidHeader,
    
    #[error("Magic number inválido: 0x{0:X}")]
    InvalidMagicNumber(u32),
    
    #[error("Error de I/O: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Error al convertir slice: {0}")]
    SliceConversion(#[from] std::array::TryFromSliceError),
}


#[derive(Error, Debug)]
pub enum KirkError {
    /// Ocurre cuando el key_type no existe en el KEYVAULT
    #[error("El keytype no existe en el KEYVAULT")]
    InvalidKeyId,

    /// Ocurre cuando el bloque de memoria no es múltiplo de 16 para AES
    #[error("El bloque de memoria no es múltiplo de 16 para AES")]
    DecryptionFailed,
}