use crate::challenges::set2::challenge10::Aes128CbcT; // TODO: move here
use crate::challenges::set1::challenge7::Aes128EcbT; // TODO: move here

pub const AES_BLOCK_SIZE: usize = 16_usize;


pub trait AesEncryption
{
    fn encrypt(plain_buffer: &[u8], key: &[u8]) -> Vec<u8>;
    fn decrypt(cipher_buffer: &[u8], key: &[u8]) -> Vec<u8>;
}

pub struct Aes128Cbc;

impl AesEncryption for Aes128Cbc
{
    fn encrypt(plain_buffer: &[u8], key: &[u8]) -> Vec<u8>
    {
        plain_buffer.encrypt_aes_128_cbc(key)
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8]) -> Vec<u8>
    {
        cipher_buffer.decrypt_aes_128_cbc(key)
    }
}


pub struct Aes128Ecb;

impl AesEncryption for Aes128Ecb
{
    fn encrypt(plain_buffer: &[u8], key: &[u8]) -> Vec<u8>
    {
        plain_buffer.encrypt_aes_128_ecb(key)
    }

    fn decrypt(cipher_buffer: &[u8], key: &[u8]) -> Vec<u8>
    {
        cipher_buffer.decrypt_aes_128_ecb(key)
    }
}
