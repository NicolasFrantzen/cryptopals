//! CBC bitflipping attacks
//! <https://cryptopals.com/sets/1/challenges/16>

use crate::oracle::EncryptionOracle;
use crate::utils::{UnicodeUtils, generate_random_bytes};
use crate::aes::{AesEncryption, Aes128Cbc, AES_BLOCK_SIZE};
use crate::padding::Pkcs7Padding;


struct EncryptionOracle16
{
    key: Vec<u8>,
}


impl EncryptionOracle for EncryptionOracle16
{
    fn encryption_oracle(&self, plain_buffer: &[u8]) -> Vec<u8>
    {
        let input_str = plain_buffer.to_str();

        let head = "comment1=cooking%20MCs;userdata=";
        let tail = ";comment2=%20like%20a%20pound%20of%20bacon";

        let mut plain_text = head.to_owned();
        plain_text += &input_str.replace(';', "%3b").replace('=', "%3d");
        plain_text += tail;


        Aes128Cbc::encrypt(plain_text.with_padding(AES_BLOCK_SIZE).as_bytes(), &self.key)
    }
}


impl EncryptionOracle16
{
    pub fn new() -> Self
    {
        Self {
            key: generate_random_bytes(Some(AES_BLOCK_SIZE)),
        }
    }


    fn check_for_admin(&self, cipher_buffer: &[u8]) -> bool
    {
        let plain_buffer = Aes128Cbc::decrypt(cipher_buffer, &self.key);
        let plain_text = plain_buffer.without_padding().to_string();
        println!("pb: {:?}", &plain_buffer[32..]);
        println!("pt: {:?}", plain_text);

        plain_text.contains(";admin=true;")
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge16_no_admin_found()
    {
        let oracle = EncryptionOracle16::new();
        let cipher_buffer = oracle.encryption_oracle(";admin=true;".as_bytes());
        assert!(!oracle.check_for_admin(&cipher_buffer));
    }

    #[test]
    fn test_challenge16()
    {
        let oracle = EncryptionOracle16::new();
        let mut attack_buffer = vec![]; //vec![0; AES_BLOCK_SIZE];
        attack_buffer.extend_from_slice("AadminAtrueA".as_bytes());

        let mut cipher_buffer = oracle.encryption_oracle(&attack_buffer);

        let offset = 16;
        cipher_buffer[offset] = cipher_buffer[offset] ^ (b'A' ^ b';');
        cipher_buffer[offset+6] = cipher_buffer[offset+6] ^ (b'A' ^ b'=');
        cipher_buffer[offset+11] = cipher_buffer[offset+11] ^ (b'A' ^ b';');

        assert!(oracle.check_for_admin(&cipher_buffer));

        // To improve this solution, calculate the offset 32 instead of assuming it
    }
}
