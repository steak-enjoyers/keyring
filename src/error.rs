#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error(transparent)]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error(transparent)]
    Bip32(#[from] bip32::Error),

    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),

    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),

    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Jose(#[from] josekit::JoseError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Failed to stringify keyring path")]
    StringifyPathFailed,

    #[error("Incorrect keyring password")]
    IncorrectPassword,

    #[error("Passwords do not match")]
    MismatchedPassword,

    #[error("Key `{name}` not found")]
    KeyNotFound {
        name: String,
    },

    #[error("Key `{name} already exists`")]
    KeyAlreadyExists {
        name: String,
    },

    #[error("Malformed JWT payload: {reason}")]
    MalformedPayload {
        reason: String,
    },
}

impl KeyringError {
    pub fn key_not_found(name: impl ToString) -> Self {
        Self::KeyNotFound {
            name: name.to_string(),
        }
    }

    pub fn key_already_exists(name: impl ToString) -> Self {
        Self::KeyAlreadyExists {
            name: name.to_string(),
        }
    }

    pub fn malformed_payload(reason: impl ToString) -> Self {
        Self::MalformedPayload {
            reason: reason.to_string(),
        }
    }
}
