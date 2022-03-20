//! AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/7>

use openssl::{symm, symm::Cipher};

use std::fs::read_to_string;

pub fn decrypt_ecb(cipher_buffer: &[u8], key: &str) -> String
{
    let cipher = Cipher::aes_128_ecb();
    let plain_text = symm::decrypt(cipher, key.as_bytes(), None, cipher_buffer).unwrap();

    String::from_utf8_lossy(&plain_text).to_string()
}


fn decrypt_ecb_base64_from_file(file: &str, key: &str) -> String
{
    let cipher_text = read_to_string(file).expect("Unable to read file.");
    let cipher_buffer: Vec<_> = cipher_text.split('\n')
        .flat_map(|l| base64::decode(l).expect("Not valid base64."))
        .collect();

        decrypt_ecb(&cipher_buffer, key)
}


pub fn encrypt_ecb(plain_text: &str, key: &str) -> Vec<u8>
{
    let cipher = Cipher::aes_128_ecb();
    let cipher_text = symm::encrypt(cipher, key.as_bytes(), None, plain_text.as_bytes()).unwrap();

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
        let plain_text = "HALLO LEGO!!";
        let key = "YELLOW SUBMARINE";
        assert_eq!(decrypt_ecb(&encrypt_ecb(plain_text, key), key), plain_text);
    }
}
