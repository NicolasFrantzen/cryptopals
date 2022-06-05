//! Implement CBC mode
//! <https://cryptopals.com/sets/1/challenges/10>

use crate::challenges::{set1::challenge5::RepeatingKeyXor};
use crate::padding::Pkcs7Padding;

use openssl::{symm, symm::Cipher};


pub trait Aes128CbcT
{
    fn decrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>;
    fn encrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>;
}


impl Aes128CbcT for [u8]
{
    fn decrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>
    {
        decrypt_aes_128_cbc(self, key)
    }

    fn encrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>
    {
        encrypt_aes_128_cbc(self, key)
    }
}


fn decrypt_aes_128_cbc(cipher_buffer: &[u8], key: &[u8]) -> Vec<u8>
{
    let cipher = Cipher::aes_128_ecb();
    let block_size = cipher.block_size();

    let mut full_plain_buffer: Vec<u8> = vec![];

    let mut previous_block: &[u8] = &vec![0; block_size]; // Initialization vector

    for block in cipher_buffer.chunks(block_size)
    {
        let mut padding = symm::encrypt(cipher, key, None, &[16_u8; 16]).unwrap();
        padding.truncate(block_size);

        let mut block_cipher = block.to_vec();
        block_cipher.extend_from_slice(&padding);

        let plain_buffer = symm::decrypt(cipher, key, None, &block_cipher).unwrap();
        let xored = RepeatingKeyXor::xor_bytes(&plain_buffer, previous_block);

        full_plain_buffer.extend_from_slice(&xored);

        previous_block = block;
    }

    full_plain_buffer
}


fn encrypt_aes_128_cbc(plain_buffer: &[u8], key: &[u8]) -> Vec<u8>
{
    let cipher = Cipher::aes_128_ecb();
    let block_size = cipher.block_size();

    let mut full_cipher_buffer: Vec<u8> = vec![];
    let mut previous_block: Vec<u8> = vec![0; block_size]; // initialization vector

    let plain_buffer = plain_buffer.with_padding(block_size);
    for block in plain_buffer.chunks(block_size)
    {
        let xored = RepeatingKeyXor::xor_bytes(block, &previous_block);
        let mut cipher_buffer = symm::encrypt(cipher, key, None, &xored).unwrap();
        cipher_buffer.truncate(block_size);

        full_cipher_buffer.extend_from_slice(&cipher_buffer);
        previous_block = cipher_buffer;
    }

    full_cipher_buffer
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::utils::UnicodeUtils;

    use std::fs::read_to_string;

    #[test]
    fn test_challenge10_decrypt()
    {
        let key = "YELLOW SUBMARINE".as_bytes();
        let cipher_text = read_to_string("data/10.txt").expect("Unable to read file.");

        let cipher_buffer: Vec<_> = cipher_text.split('\n')
            .flat_map(|l| base64::decode(l).expect("Not valid base64."))
            .collect();

        let plain_text = cipher_buffer.decrypt_aes_128_cbc(key).to_string();
        assert_eq!(&plain_text[0..33], "I'm back and I'm ringin' the bell");
    }


    #[test]
    fn test_challenge10_encrypt()
    {
        let key = "YELLOW SUBMARINE".as_bytes();
        let cipher_text = read_to_string("data/10.txt").expect("Unable to read file.");
        let cipher_buffer = "I'm back and I'm ringin' the bell".as_bytes().encrypt_aes_128_cbc(key);

        // Padding starts at index 42
        assert_eq!(&cipher_text[0..42], &base64::encode(&cipher_buffer)[0..42]);
    }
}
