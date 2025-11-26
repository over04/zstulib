use crate::error::rsa::RSAError;
use num_bigint::BigUint;
use num_traits::{Num, Zero};

pub struct RSAKeyPair {
    e: BigUint,
    d: Option<BigUint>,
    m: BigUint,
    chunk_size: usize,
    radix: usize,
}

impl RSAKeyPair {
    pub fn new(
        encryption_exponent: &str,
        decryption_exponent: &str,
        modulus: &str,
    ) -> Result<Self, RSAError> {
        let e = parse_hex_component("encryption exponent", encryption_exponent)?;
        let d = if decryption_exponent.trim().is_empty() {
            None
        } else {
            Some(parse_hex_component(
                "decryption exponent",
                decryption_exponent,
            )?)
        };
        let m = parse_hex_component("modulus", modulus)?;
        let digits = if m.is_zero() {
            0
        } else {
            ((m.bits() - 1) / 16 + 1) as usize
        };
        let chunk_size = digits.saturating_sub(1) * 2;
        Ok(Self {
            e,
            d,
            m,
            chunk_size,
            radix: 16,
        })
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn radix(&self) -> usize {
        self.radix
    }

    pub fn encryption_exponent(&self) -> &BigUint {
        &self.e
    }

    pub fn decryption_exponent(&self) -> Option<&BigUint> {
        self.d.as_ref()
    }

    pub fn modulus(&self) -> &BigUint {
        &self.m
    }

    pub fn encrypt_block(&self, block: &BigUint) -> BigUint {
        block.modpow(&self.e, &self.m)
    }

    pub fn decrypt_block(&self, block: &BigUint) -> Result<BigUint, RSAError> {
        match &self.d {
            Some(d) => Ok(block.modpow(d, &self.m)),
            None => Err(RSAError::MissingPrivateExponent),
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, RSAError> {
        let chunk_size = self.chunk_size();
        if chunk_size == 0 {
            return Ok(String::new());
        }
        let mut data: Vec<u16> = plaintext.encode_utf16().collect();
        while data.len() % chunk_size != 0 {
            data.push(0);
        }

        let mut blocks = Vec::new();
        for chunk in data.chunks(chunk_size) {
            let block = chunk_to_biguint(chunk);
            let crypt = self.encrypt_block(&block);
            let text = match self.radix {
                16 => biguint_to_hex(&crypt),
                radix => crypt.to_str_radix(radix as u32),
            };
            blocks.push(text);
        }
        Ok(blocks.join(" "))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, RSAError> {
        let mut code_units: Vec<u16> = Vec::new();
        for block in ciphertext.split_whitespace() {
            let value = parse_cipher_block(block, self.radix as u32)?;
            let decrypted = self.decrypt_block(&value)?;
            for word in biguint_to_words(&decrypted) {
                code_units.push((word & 0x00FF) as u16);
                code_units.push((word >> 8) as u16);
            }
        }
        while code_units.last() == Some(&0) {
            code_units.pop();
        }
        if code_units.is_empty() {
            return Ok(String::new());
        }
        String::from_utf16(&code_units).map_err(RSAError::Utf16)
    }
}

fn chunk_to_biguint(chunk: &[u16]) -> BigUint {
    let mut value = BigUint::zero();
    for (index, pair) in chunk.chunks(2).enumerate() {
        let low = pair[0] as u32;
        let high = if pair.len() > 1 { pair[1] as u32 } else { 0 };
        let word = low | (high << 8);
        let shift = 16 * index;
        value += BigUint::from(word) << shift;
    }
    value
}

fn biguint_to_words(value: &BigUint) -> Vec<u16> {
    if value.is_zero() {
        return vec![0];
    }
    let bytes = value.to_bytes_le();
    let mut words = Vec::with_capacity((bytes.len() + 1) / 2);
    for chunk in bytes.chunks(2) {
        let low = chunk[0] as u16;
        let high = if chunk.len() > 1 {
            (chunk[1] as u16) << 8
        } else {
            0
        };
        words.push(low | high);
    }
    words
}

fn biguint_to_hex(value: &BigUint) -> String {
    if value.is_zero() {
        return "0000".to_string();
    }
    biguint_to_words(value)
        .into_iter()
        .rev()
        .map(|word| format!("{:04x}", word))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encrypt_decrypt_round_trip() {
        let key = RSAKeyPair::new("11", "115f1", "12977").unwrap();
        let plaintext = "RustRSA";
        let cipher = key.encrypt(plaintext).unwrap();
        assert!(!cipher.is_empty());
        let recovered = key.decrypt(&cipher).unwrap();
        assert_eq!(recovered, plaintext);
    }
}

fn parse_hex_component(name: &'static str, value: &str) -> Result<BigUint, RSAError> {
    BigUint::from_str_radix(value, 16).map_err(|source| RSAError::ParseComponent {
        component: name,
        value: value.to_string(),
        source,
    })
}

fn parse_cipher_block(value: &str, radix: u32) -> Result<BigUint, RSAError> {
    BigUint::from_str_radix(value, radix).map_err(|source| RSAError::InvalidCipherBlock {
        value: value.to_string(),
        radix,
        source,
    })
}
