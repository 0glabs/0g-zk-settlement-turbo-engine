use std::fmt;

pub enum AppError {
    Io(std::io::Error),
    Circom(String),
    Groth16(String),
    InvalidInput(String),
    UninitializedState,
}

impl fmt::Debug for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "IO Error: {:?}", err),
            AppError::Circom(err) => write!(f, "Circom Error: {}", err),
            AppError::Groth16(err) => write!(f, "Groth16 Error: {}", err),
            AppError::InvalidInput(err) => write!(f, "Invalid Input: {}", err),
            AppError::UninitializedState => write!(f, "Uninitialized State"),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err)
    }
}
