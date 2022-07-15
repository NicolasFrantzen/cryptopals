//! The CBC padding oracle
//! <https://cryptopals.com/sets/3/challenges/17>

//use crate::oracle::EncryptionOracle;
use crate::utils::{generate_random_bytes, UnicodeUtils};
use crate::aes::{AesEncryption, Aes128Cbc, AES_BLOCK_SIZE};
use crate::padding::Pkcs7Padding;

//use std::slice::Chunks;
//use itertools::Itertools;
use std::str;

#[derive(Clone)]
struct EncryptionOracle17
{
    key: Vec<u8>,
}

impl EncryptionOracle17
{
    pub fn new() -> Self
    {
        Self { key: generate_random_bytes(Some(AES_BLOCK_SIZE)) }
    }

    /// Encrypt a string with AES block size padding, under CBC
    /// Returns ciphertext and IV
    pub fn encrypt(&self, plain_text: &[u8], iv: &[u8]) -> Vec<u8>
    {
        Aes128Cbc::encrypt(plain_text.with_padding(AES_BLOCK_SIZE).as_slice(), &self.key, Some(iv))
    }

    /// Decrypts a string and checks its padding
    /// Returns Some(plain_text) if the padding was valid, None otherwise
    pub fn padding_oracle(&self, cipher_text: &[u8], iv: &[u8]) -> Option<Vec<u8>>
    {
        let plain_text = Aes128Cbc::decrypt(cipher_text, &self.key, Some(iv));

        //dbg!(&plain_text);

        plain_text.as_slice()
            .validate_padding()
            .map(|x| x.to_owned())
            .ok()
    }

    pub fn attack_block(&self, plain_text: &[u8], iv: &[u8]) -> Vec<u8>
    {
        let cipher_text = self.encrypt(plain_text, iv);

        let iv_length = iv.len();
        let mut zeroing_iv = iv.to_owned();

        let oracle_do = |i: usize|
        {
            // Create the new temporary iv by xoring the zeroing iv with the desired padding for the attack (i.e. the position)
            let mut temp_iv = zeroing_iv.xor(i as u8);
            let attack_position = iv_length - i;

            // Try all characters for the attack byte, the oracle will return a result if the padding is valid
            for c in 0..=255_u8
            {
                temp_iv[attack_position] = c;
                //dbg!(&temp_iv[..]);

                // Use the oracle
                if self.padding_oracle(&cipher_text, &temp_iv).is_some()
                {
                    // Apply the succesful byte to the zeroing iv
                    zeroing_iv[attack_position] = c ^ (i as u8);

                    //dbg!(&temp_iv[..]);
                    //dbg!(&zeroing_iv[..]);
                    return;
                }
            }
        };

        (1..iv_length + 1).for_each(oracle_do);

        zeroing_iv.to_owned()
    }

    pub fn full_attack(&self, plain_text: &str) -> String
    {
        // Choose the initial iv to be zeroes
        let mut iv = vec![0; AES_BLOCK_SIZE];

        // Attack a chunk at a time
        plain_text.as_bytes()
            .chunks(AES_BLOCK_SIZE)
            .fold(String::new(), |acc, x| {
                iv = self.attack_block(x, &iv);

                //dbg!(&iv);

                acc + x.to_str()
            })
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    const fn attackable_strings() -> [&'static str; 10]
    {
        [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ]
    }

    #[test]
    fn test_challenge17_padding_oracle()
    {
        let iv: [u8; AES_BLOCK_SIZE] = [0; AES_BLOCK_SIZE];
        let oracle = EncryptionOracle17::new();

        // Good padding
        let cipher_text = oracle.encrypt("YELLOW SUBMA\x04\x04\x04\x04".as_bytes(), &iv);
        assert!(oracle.padding_oracle(&cipher_text, &iv).is_some());

        // Bad padding
        let cipher_text = oracle.encrypt("YELLOW SUBMA\x01\x02\x03\x04".as_bytes(), &iv);
        assert!(oracle.padding_oracle(&cipher_text, &iv).is_none());
    }

    #[test]
    fn test_challenge17()
    {
        let test_attack = |plain_text: &str|
        {
            let oracle = EncryptionOracle17::new();
            let attacked_string = oracle.full_attack(plain_text);

            println!("Attacked string: {}", attacked_string);
            assert_eq!(oracle.full_attack(plain_text), plain_text);
        };

        // Attack a 32 char string
        test_attack("YELLOW SUBMARINEYELLOW SUBMARINE");

        // Attack all the provided strings and base64 decode them.
        attackable_strings().iter().for_each(|c| {
            println!("Base64 decode: {}", base64::decode(c).unwrap().to_str());
            test_attack(c);
        });
    }
}
