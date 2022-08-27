use crate::challenges::set2::challenge10::Aes128CbcT; // TODO: move here
use crate::challenges::set1::challenge7::Aes128EcbT; // TODO: move here

use crate::utils::UnicodeUtils;

pub const AES_BLOCK_SIZE: usize = 16_usize;


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
        plain_buffer.encrypt_aes_128_cbc(key, iv)
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8>
    {
        cipher_buffer.decrypt_aes_128_cbc(key, iv)
    }
}


pub struct Aes128Ecb;
impl AesEncryption for Aes128Ecb
{
    fn encrypt(plain_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        plain_buffer.encrypt_aes_128_ecb(key)
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        cipher_buffer.decrypt_aes_128_ecb(key)
    }
}


pub struct CtrCounter
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
            .flat_map(|(x, y)| x.xor_all(&y.encrypt_aes_128_ecb(key)))
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