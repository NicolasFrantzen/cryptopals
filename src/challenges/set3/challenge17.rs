//! The CBC padding oracle
//! <https://cryptopals.com/sets/3/challenges/17>

//use crate::oracle::EncryptionOracle;
use crate::utils::{generate_random_bytes};
use crate::aes::{AesEncryption, Aes128Cbc, AES_BLOCK_SIZE};
use crate::padding::Pkcs7Padding;


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

    pub fn attack_block(&self, plain_text: &str)
    {
        let iv: [u8; AES_BLOCK_SIZE] = [0; AES_BLOCK_SIZE];
        let cipher_text = self.encrypt(plain_text.as_bytes(), &iv);

        let mut temp_iv = iv;

        for c in 0..=255_u8
        {
            let j = temp_iv.len() - 1;
            temp_iv[j] = c;

            if self.padding_oracle(&cipher_text, &temp_iv).is_some()
            {
                break;
            }
        }


        dbg!(&temp_iv);
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use rand::{thread_rng, prelude::SliceRandom};

    const fn get_10_strings() -> [&'static str; 10]
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
    fn test_challenge17_todo()
    {
        let oracle = EncryptionOracle17::new();

        let mut rng = thread_rng();
        let random_string = *get_10_strings().choose(&mut rng).unwrap();
        println!("{:?}", random_string);

        // TODO
        oracle.attack_block("YELLOW SUBMARINE");
    }
}
