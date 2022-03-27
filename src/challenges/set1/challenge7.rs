//! AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/7>

use crate::utils::UnicodeToString;

use openssl::{symm, symm::Cipher};

use std::fs::read_to_string;

pub trait Aes128EcbT
{
    fn decrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>;
    fn encrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>;
}


impl Aes128EcbT for [u8]
{
    fn decrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>
    {
        decrypt_aes_128_ecb(self, key)
    }

    fn encrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>
    {
        encrypt_aes_128_ecb(self, key)
    }
}


pub fn decrypt_aes_128_ecb(cipher_buffer: &[u8], key: &[u8]) -> Vec<u8>
{
    let cipher = Cipher::aes_128_ecb();
    let plain_text = symm::decrypt(cipher, key, None, cipher_buffer).unwrap();

    plain_text
}


fn decrypt_ecb_base64_from_file(file: &str, key: &str) -> String
{
    let cipher_text = read_to_string(file).expect("Unable to read file.");
    let cipher_buffer: Vec<_> = cipher_text.split('\n')
        .flat_map(|l| base64::decode(l).expect("Not valid base64."))
        .collect();

    decrypt_aes_128_ecb(&cipher_buffer, key.as_bytes()).to_string()
}


pub fn encrypt_aes_128_ecb(plain_text: &[u8], key: &[u8]) -> Vec<u8>
{
    let cipher = Cipher::aes_128_ecb();
    let cipher_text = symm::encrypt(cipher, key, None, plain_text).unwrap();

    cipher_text
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge7()
    {
        let plain_text = decrypt_ecb_base64_from_file("data/7.txt", "YELLOW SUBMARINE");
        assert_eq!(&plain_text[0..33], "I'm back and I'm ringin' the bell");
    }

    #[test]
    fn test_challenge7_encrypt()
    {
        let plain_text = "HALLO LEGO!!".as_bytes();
        let key = "YELLOW SUBMARINE".as_bytes();
        assert_eq!(decrypt_aes_128_ecb(&encrypt_aes_128_ecb(plain_text, key), key), plain_text);
    }
}
