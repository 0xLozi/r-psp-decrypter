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

    #[error("Error al intentar leer el size del archivo...")]
    SizeError,

    #[error("Error al referenciar un puntero")]
    PointerError,

    #[error("Error al encontrar el Tag o Tag invalido")]
    TagNotFound,

    #[error("La validación ha sido un fracaso...")]
    ValidationFailed,

    #[error("Header decryption failed...")]
    HeaderDecryptionFailed,

    #[error("This is an invalid mode")]
    InvalidMode,

    #[error("La desencriptación falló")]
    DecryptionFailed,

    #[error("No se pudo crear el archivo")]
    FileCreationFailed,

    #[error("You need a seed in order to decrypt type 5")]
    MissingSeed,

    #[error("Alignment Fault...")]
    AlignmentFault,

    #[error("File size len() too low...")]
    TooShort
}


#[derive(Error, Debug)]
pub enum KirkError {
    /// Ocurre cuando el key_type no existe en el KEYVAULT
    #[error("El keytype no existe en el KEYVAULT")]
    InvalidKeyId,

    /// Ocurre cuando el bloque de memoria no es múltiplo de 16 para AES
    #[error("El bloque de memoria no es múltiplo de 16 para AES")]
    DecryptionFailed,

    #[error("The conversion failed...")]
    ConversionFailed,
}