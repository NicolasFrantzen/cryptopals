use openssl::{symm, symm::Cipher};

use crate::padding::Pkcs7Padding;
use crate::utils::UnicodeUtils;

pub const AES_BLOCK_SIZE: usize = 16_usize;

pub trait Aes128
{
    fn decrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>;
    fn encrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>;
    fn decrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>;
    fn encrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>;
    fn decrypt_aes_128_ctr(&self, key: &[u8]) -> Vec<u8>;
    fn encrypt_aes_128_ctr(&self, key: &[u8]) -> Vec<u8>;
}

impl Aes128 for [u8]
{
    fn decrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Ecb::decrypt(self, key, None)
    }

    fn encrypt_aes_128_ecb(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Ecb::encrypt(self, key, None)
    }

    fn decrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Cbc::decrypt(self, key, None)
    }

    fn encrypt_aes_128_cbc(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Cbc::encrypt(self, key, None)
    }

    fn decrypt_aes_128_ctr(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Ctr::decrypt(self, key, None)
    }

    fn encrypt_aes_128_ctr(&self, key: &[u8]) -> Vec<u8>
    {
        Aes128Ctr::encrypt(self, key, None)
    }
}

pub trait AesEncryption
{
    fn encrypt(plain_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>;
    fn decrypt(cipher_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>;
}

pub struct Aes128Cbc;
impl AesEncryption for Aes128Cbc
{
    fn encrypt(plain_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>
    {
        let cipher = Cipher::aes_128_ecb();
        let block_size = cipher.block_size();

        let mut full_cipher_buffer: Vec<u8> = vec![];
        let mut previous_block: Vec<u8> = match iv {
            Some(iv) => iv.to_owned(),
            None => vec![0; block_size],
        }; // initialization vector

        let plain_buffer = plain_buffer.with_padding(block_size);
        for block in plain_buffer.chunks(block_size)
        {
            let xored = &block.xor_repeating_key(&previous_block);
            let mut cipher_buffer = symm::encrypt(cipher, key, None, xored).unwrap();
            cipher_buffer.truncate(block_size);

            full_cipher_buffer.extend_from_slice(&cipher_buffer);
            previous_block = cipher_buffer;
        }

        full_cipher_buffer
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>
    {
        let cipher = Cipher::aes_128_ecb();
        let block_size = cipher.block_size();

        let mut full_plain_buffer: Vec<u8> = vec![];
        let mut previous_block: Vec<u8> = match iv {
            Some(iv) => iv.to_owned(),
            None => vec![0; block_size],
        }; // Initialization vector

        for block in cipher_buffer.chunks(block_size)
        {
            let mut padding = symm::encrypt(cipher, key, None, &[16_u8; 16]).unwrap();
            padding.truncate(block_size);

            let mut block_cipher = block.to_vec();
            block_cipher.extend_from_slice(&padding);

            let plain_buffer = symm::decrypt(cipher, key, None, &block_cipher).unwrap();
            let xored = &plain_buffer.xor_repeating_key(&previous_block);

            full_plain_buffer.extend_from_slice(xored);

            previous_block = block.to_owned();
        }

        full_plain_buffer
    }
}

pub struct Aes128Ecb;
impl AesEncryption for Aes128Ecb
{
    fn encrypt(plain_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>
    {
        symm::encrypt(Cipher::aes_128_ecb(), key, iv, plain_buffer).unwrap() // TODO: return Result
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>
    {
        symm::decrypt(Cipher::aes_128_ecb(), key, iv, cipher_buffer).unwrap() // TODO: return Result
    }
}

struct CtrCounter
{
    nonce: u64,
}

impl CtrCounter
{
    pub fn new(nonce: u64) -> Self
    {
        Self{ nonce }
    }

    fn iter(&self) -> CtrCounterIter
    {
        CtrCounterIter {
            count: 0,
            nonce: self.nonce
        }
    }
}

struct CtrCounterIter
{
    count: u64,
    nonce: u64,
}

impl Iterator for CtrCounterIter
{
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == u64::MAX {
            return None;
        }

        let mut iv = self.nonce.to_le_bytes().to_vec();
        iv.extend_from_slice(self.count.to_le_bytes().as_slice());

        self.count += 1;

        Some(iv)
    }
}

pub struct Aes128Ctr;

impl Aes128Ctr
{
    fn encode(buffer: &[u8], key: &[u8]) -> Vec<u8>
    {
        buffer.chunks(AES_BLOCK_SIZE)
            .zip(CtrCounter::new(0).iter())
            .flat_map(|(x, y)| x.xor_all(&Aes128Ecb::encrypt(&y, key, None)))
            .collect::<Vec<_>>()
    }
}

impl AesEncryption for Aes128Ctr
{

    fn encrypt(plain_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        Self::encode(plain_buffer, key)
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        Self::encode(cipher_buffer, key)
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_aes_ecb_encrypt_decrypt()
    {
        let plain_text = "HALLO LEGO!!".as_bytes();
        let key = "YELLOW SUBMARINE".as_bytes();
        assert_eq!(Aes128Ecb::decrypt(&Aes128Ecb::encrypt(plain_text, key, None), key, None), plain_text);
    }

    #[test]
    fn test_aes_ctr_counter()
    {
        let nonce = 0;
        let mut counter = CtrCounter::new(nonce).iter();

        assert_eq!(counter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()));
        assert_eq!(counter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0].to_vec()));
        assert_eq!(counter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0].to_vec()));
        assert_eq!(counter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0].to_vec()));

        assert_eq!(counter.next().map(|x| x.len()), Some(AES_BLOCK_SIZE));
    }

    #[test]
    fn test_aes_ctr_encrypt_decrypt()
    {
        let key = "YELLOW SUBMARINE";
        let plain_text = "\
            Rollin' in my 5.0\n\
            With my rag-top down so my hair can blow\n\
            The girlies on standby waving just to say hi\n\
            Did you stop? No, I just drove by\n";

        let cipher_buffer = Aes128Ctr::encrypt(plain_text.as_bytes(), key.as_bytes(), None);
        assert_eq!(Aes128Ctr::decrypt(&cipher_buffer, key.as_bytes(), None), plain_text.as_bytes());
    }
}