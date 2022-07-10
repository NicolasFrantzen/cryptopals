//! An ECB/CBC detection oracle
//! <https://cryptopals.com/sets/2/challenges/11>


use crate::padding::Pkcs7Padding;
use crate::aes::{AesEncryption, Aes128Cbc, Aes128Ecb, AES_BLOCK_SIZE};
use crate::utils::generate_random_bytes;

use rand::{thread_rng, Rng};


fn encrypt_with_random_key<T: AesEncryption>(plain_buffer: &[u8]) -> Vec<u8>
{
    let key = generate_random_bytes(Some(AES_BLOCK_SIZE));
    T::encrypt(plain_buffer, &key, None)
}


fn encryption_oracle(plain_buffer: &[u8]) -> (Vec<u8>, bool)
{
    let mut rng = thread_rng();

    let number_of_bytes = rng.gen_range(5..=10);
    let padding = || generate_random_bytes(Some(number_of_bytes)).with_padding(AES_BLOCK_SIZE);

    let data = padding().into_iter()
        .chain(plain_buffer.iter().cloned())
        .chain(padding().into_iter())
        .collect::<Vec<_>>();

    match rng.gen_range(0..=1) {
        0 => { (encrypt_with_random_key::<Aes128Cbc>(data.as_slice()), false) }, // TODO: we need to use a random IV
        _ => { (encrypt_with_random_key::<Aes128Ecb>(data.as_slice()), true) },
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    use crate::aes::{Aes128Cbc, Aes128Ecb, AES_BLOCK_SIZE};
    use crate::detect::DetectReps;


    #[test]
    fn test_challenge11_detect_ecb_or_cbc()
    {
        let plain_text = "YELLOW SUBMARINEYELLOW SUBMARINE".as_bytes();

        for _ in 0..10
        {
            let ecb = encrypt_with_random_key::<Aes128Ecb>(plain_text);
            assert!(ecb.detect_repetitions(AES_BLOCK_SIZE));

            let cbc = encrypt_with_random_key::<Aes128Cbc>(plain_text);
            assert!(!cbc.detect_repetitions(AES_BLOCK_SIZE));
        }
    }


    #[test]
    fn test_challenge11_encryption_oracle()
    {
        let plain_text = "YELLOW SUBMARINEYELLOW SUBMARINE".as_bytes();

        for _ in 0..10
        {
            let (cipher, is_ecb) = encryption_oracle(plain_text);
            assert_eq!(cipher.detect_repetitions(AES_BLOCK_SIZE), is_ecb);
        }
    }
}
