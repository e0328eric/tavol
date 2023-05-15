use thiserror::Error;

#[derive(Debug, Error)]
pub enum TavolErr {
    #[error("IO error occures")]
    IoErr,
    #[error("Aes error occures")]
    AesErr,
}

pub type Result<T> = error_stack::Result<T, TavolErr>;
