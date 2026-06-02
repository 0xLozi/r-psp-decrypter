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