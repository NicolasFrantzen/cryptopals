//! Byte-at-a-time ECB decryption (Harder)
//! <https://cryptopals.com/sets/1/challenges/14>

use crate::detect::DetectReps;
use crate::padding::{Pkcs7Padding, padded_size};
use crate::aes::{AesEncryption, Aes128Ecb, AES_BLOCK_SIZE};
use crate::utils::{generate_random_bytes};


struct EncryptionOracle
{
    key: Vec<u8>,
    random_prefix: Vec<u8>,
}


impl EncryptionOracle
{
    pub fn new() -> Self
    {
        EncryptionOracle {
            key: generate_random_bytes(Some(AES_BLOCK_SIZE)),
            random_prefix: generate_random_bytes(None),
        }
    }

    const fn magic_string() -> &'static str
    {
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK"
    }

    fn encrypt<T: AesEncryption>(&self, plain_buffer: &[u8]) -> Vec<u8>
    {
        T::encrypt(plain_buffer, &self.key)
    }

    fn encryption_oracle(&self, plain_buffer: &[u8]) -> Vec<u8>
    {
        let magic_bytes = base64::decode(Self::magic_string()).unwrap();

        let data = self.random_prefix.iter()
            .cloned()
            .chain(plain_buffer.iter()
                .cloned())
            .chain(magic_bytes.iter()
                .cloned())
            .collect::<Vec<_>>();

        self.encrypt::<Aes128Ecb>(data.with_padding(AES_BLOCK_SIZE).as_slice())
    }
}

struct Oracle
{
    encryption_oracle: Box<EncryptionOracle>,
}


impl Oracle
{
    fn new() -> Self
    {
        Self
        {
            encryption_oracle: Box::new(EncryptionOracle::new()),
        }
    }

    fn detect_block_size(&self) -> Option<usize>
    {
        // Create encryption oracle iterator with repeating A's
        let mut a = vec![];
        let initial_length = self.encryption_oracle.encryption_oracle(&a).len();
        let encrypted_iter = std::iter::repeat_with(|| { a.push(b'A'); self.encryption_oracle.encryption_oracle(&a) });

        // Iterate until the encrypted size change. The difference between the new and initial should be the block size
        for a in encrypted_iter
        {
            let current_len = a.len();
            if initial_length != current_len
            {
                let offset = current_len-initial_length;
                return Some(offset);
            }
        }

        None
    }

    fn detect_prefix_size(&self) -> Option<usize>
    {
        let repetitions = 4;
        let repeated_block = "YELLOW SUBMARINE".repeat(repetitions);

        let mut buffer = repeated_block;

        for i in 0..AES_BLOCK_SIZE
        {
            let oracle_cipher = self.encryption_oracle.encryption_oracle(buffer.as_bytes());

            // Append one padding byte to align `random_prefix`
            buffer.insert_str(0, "\x04");

            if let Some(consecutive_index) = oracle_cipher.detect_consecutive_repetitions(AES_BLOCK_SIZE, repetitions)
            {
                // Remove count of padding bytes inserted from the index
                return Some(consecutive_index - i);
            }
        }

        None
    }

    fn detect_padded_prefix_size(&self) -> Option<usize>
    {
        Some(padded_size(self.detect_prefix_size()?, AES_BLOCK_SIZE))
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::detect::DetectReps;

    #[test]
    fn test_challenge14_check_block_size()
    {
        // Check blocksize
        let oracle = Oracle::new();
        let block_size = oracle.detect_block_size().unwrap();

        assert_eq!(block_size, 16);
    }

    #[test]
    fn test_challenge14_detect_ecb()
    {
        // Check for repetitions - we are indeed using ECB
        let oracle = EncryptionOracle::new();
        let s = b"YELLOW SUBMARINE".repeat(10);

        assert!(oracle.encryption_oracle(&s).detect_repetitions(16));
    }

    #[test]
    fn test_challenge14()
    {
        let oracle = Box::new(Oracle::new());
        assert_eq!(oracle.detect_prefix_size().unwrap(), oracle.encryption_oracle.random_prefix.len());

        println!("{:?}", oracle.detect_padded_prefix_size());
    }
}
