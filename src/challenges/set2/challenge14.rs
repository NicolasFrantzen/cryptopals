//! Byte-at-a-time ECB decryption (Harder)
//! <https://cryptopals.com/sets/2/challenges/14>

use crate::aes::{Aes128Ecb, AesEncryption, AES_BLOCK_SIZE};
use crate::oracle::EncryptionOracle;
use crate::padding::Pkcs7Padding;
use crate::utils::generate_random_bytes;

struct EncryptionOracle14 {
    key: Vec<u8>,
    random_prefix: Vec<u8>,
}

impl EncryptionOracle for EncryptionOracle14 {
    fn encryption_oracle(&self, plain_buffer: &[u8]) -> Vec<u8> {
        let magic_bytes = base64::decode(Self::magic_string()).unwrap();

        let data = self
            .random_prefix
            .iter()
            .cloned()
            .chain(plain_buffer.iter().cloned())
            .chain(magic_bytes.iter().cloned())
            .collect::<Vec<_>>();

        self.encrypt::<Aes128Ecb>(data.with_padding(AES_BLOCK_SIZE).as_slice())
    }
}

impl EncryptionOracle14 {
    pub fn new() -> Self {
        Self {
            key: generate_random_bytes(Some(AES_BLOCK_SIZE)),
            random_prefix: generate_random_bytes(None),
        }
    }

    const fn magic_string() -> &'static str {
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK"
    }

    fn encrypt<T: AesEncryption>(&self, plain_buffer: &[u8]) -> Vec<u8> {
        T::encrypt(plain_buffer, &self.key, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectReps;
    use crate::oracle::Oracle;

    #[test]
    fn test_challenge14_check_block_size() {
        // Check blocksize
        let mut oracle = Oracle::new(Box::new(EncryptionOracle14::new()));
        oracle.decipher();
        let block_size = oracle.detect_block_size().unwrap();

        assert_eq!(block_size, 16);
    }

    #[test]
    fn test_challenge14_detect_ecb() {
        // Check for repetitions - we are indeed using ECB
        let oracle = EncryptionOracle14::new();
        let s = b"YELLOW SUBMARINE".repeat(10);

        assert!(oracle.encryption_oracle(&s).detect_repetitions(16));
    }

    #[test]
    fn test_challenge14() {
        let mut oracle = Oracle::new(Box::new(EncryptionOracle14::new()));
        oracle.decipher();

        let expected_plain = "\
            Rollin' in my 5.0\n\
            With my rag-top down so my hair can blow\n\
            The girlies on standby waving just to say hi\n\
            Did you stop? No, I just drove by\n";

        assert_eq!(expected_plain, oracle.plain_text());
    }
}
