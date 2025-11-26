use num_bigint::ParseBigIntError;
use std::error::Error as StdError;
use std::fmt;
use std::string::FromUtf16Error;

#[derive(Debug)]
pub enum RSAError {
    ParseComponent {
        component: &'static str,
        value: String,
        source: ParseBigIntError,
    },
    InvalidCipherBlock {
        value: String,
        radix: u32,
        source: ParseBigIntError,
    },
    MissingPrivateExponent,
    Utf16(FromUtf16Error),
}

impl fmt::Display for RSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RSAError::ParseComponent {
                component, value, ..
            } => write!(f, "failed to parse {component} from '{value}'"),
            RSAError::InvalidCipherBlock { value, radix, .. } => {
                write!(f, "failed to parse cipher block '{value}' in base {radix}")
            }
            RSAError::MissingPrivateExponent => {
                write!(f, "missing private exponent; decryption is not available")
            }
            RSAError::Utf16(err) => err.fmt(f),
        }
    }
}

impl StdError for RSAError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            RSAError::ParseComponent { source, .. } => Some(source),
            RSAError::InvalidCipherBlock { source, .. } => Some(source),
            RSAError::MissingPrivateExponent => None,
            RSAError::Utf16(err) => Some(err),
        }
    }
}
