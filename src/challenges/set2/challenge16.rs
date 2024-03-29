//! CBC bitflipping attacks
//! <https://cryptopals.com/sets/2/challenges/16>

use crate::aes::{Aes128Cbc, AesEncryption, AES_BLOCK_SIZE};
use crate::oracle::EncryptionOracle;
use crate::padding::Pkcs7Padding;
use crate::utils::{generate_random_bytes, UnicodeUtils};

#[derive(Clone)]
struct EncryptionOracle16 {
    key: Vec<u8>,
}

impl EncryptionOracle for EncryptionOracle16 {
    fn encryption_oracle(&self, plain_buffer: &[u8]) -> Vec<u8> {
        let input_str = plain_buffer.to_str();

        let head = "comment1=cooking%20MCs;userdata=";
        let tail = ";comment2=%20like%20a%20pound%20of%20bacon";

        let mut plain_text = head.to_owned();
        plain_text += &input_str.replace(';', "%3b").replace('=', "%3d");
        plain_text += tail;

        Aes128Cbc::encrypt(
            plain_text.with_padding(AES_BLOCK_SIZE).as_bytes(),
            &self.key,
            None,
        )
    }
}

impl EncryptionOracle16 {
    pub fn new() -> Self {
        Self {
            key: generate_random_bytes(Some(AES_BLOCK_SIZE)),
        }
    }

    fn check_for_admin(&self, cipher_buffer: &[u8]) -> bool {
        let plain_buffer = Aes128Cbc::decrypt(cipher_buffer, &self.key, None);
        let plain_text = plain_buffer.without_padding().to_string();

        plain_text.contains(";admin=true;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::Oracle;

    #[test]
    fn test_challenge16_no_admin_found() {
        let oracle = EncryptionOracle16::new();
        let cipher_buffer = oracle.encryption_oracle(";admin=true;".as_bytes());
        assert!(!oracle.check_for_admin(&cipher_buffer));
    }

    #[test]
    fn test_challenge16() {
        let encryption_oracle = Box::new(EncryptionOracle16::new());
        let oracle = Oracle::new(encryption_oracle.clone());

        let mut attack_buffer = vec![]; //vec![0; AES_BLOCK_SIZE];
        attack_buffer.extend_from_slice("AadminAtrueA".as_bytes());

        let mut cipher_buffer = oracle.encryption_oracle(&attack_buffer);

        let offset = 16;
        cipher_buffer[offset] ^= b'A' ^ b';';
        cipher_buffer[offset + 6] ^= b'A' ^ b'=';
        cipher_buffer[offset + 11] ^= b'A' ^ b';';

        assert!(encryption_oracle.check_for_admin(&cipher_buffer));

        println!("HEJ: {:?}", oracle.detect_prefix_size());
        // To improve this solution, calculate the offset 32 instead of assuming it
    }
}
