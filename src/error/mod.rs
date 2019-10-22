pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Display, Clone)]
pub enum Error {
    Service(String),
    Authentication(String),
    IOError(String),
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Service(format!("IO Failure -> {}", e))
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Self::Service(format!("Config parse failure -> {}", e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Service(format!("Data parse failure -> {}", e))
    }
}

impl From<sled::Error> for Error {
    fn from(e: sled::Error) -> Self {
        Self::IOError(format!("Failed database operation -> {}", e))
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for Error {
    fn from(e: hmac::crypto_mac::InvalidKeyLength) -> Self {
        Self::Authentication(format!("Signing failed -> {}", e))
    }
}

impl From<hmac::crypto_mac::MacError> for Error {
    fn from(e: hmac::crypto_mac::MacError) -> Self {
        Self::Authentication(format!("Signing failed -> {}", e))
    }
}
