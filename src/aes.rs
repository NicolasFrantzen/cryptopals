use crate::challenges::set2::challenge10::Aes128CbcT; // TODO: move here
use crate::challenges::set1::challenge7::Aes128EcbT; // TODO: move here

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


pub struct CtrCounter<'a>
{
    nonce: u64,
    key: &'a [u8],
    iv: Vec<u8>,
}

impl <'a> CtrCounter<'a>
{
    pub fn new(key: &'a [u8]) -> Self
    {
        Self{ nonce: 0, key, iv: vec![0; AES_BLOCK_SIZE] }
    }
}


pub struct Aes128Ctr;
impl AesEncryption for Aes128Ctr
{
    #[allow(unused)]
    fn encrypt(plain_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        //plain_buffer.encrypt_aes_128_ecb(key)
        todo!()
    }

    #[allow(unused)]
    fn decrypt(cipher_buffer: &[u8], key: &[u8], _iv: Option<&[u8]>) -> Vec<u8>
    {
        //cipher_buffer.decrypt_aes_128_ecb(key)
        todo!()
    }
}

impl Aes128Ctr
{
    #[allow(unused)]
    pub fn encrypt_with_counter(plain_buffer: &[u8], ctr_key: CtrCounter) -> Vec<u8>
    {
        todo!()
    }

    #[allow(unused)]
    pub fn decrypt_with_counter(cipher_buffer: &[u8], ctr_key: CtrCounter) -> Vec<u8>
    {
        todo!()
    }
}
