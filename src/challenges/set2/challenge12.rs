//! Byte-at-a-time ECB decryption (Simple)
//! <https://cryptopals.com/sets/1/challenges/12>

use crate::padding::Pkcs7Padding;
use crate::aes::{AesEncryption, Aes128Ecb, AES_BLOCK_SIZE};
use crate::utils::{generate_random_bytes, all_printable_chars};

use itertools::Itertools;


struct EncryptionOracle
{
    key: Vec<u8>,
}


impl EncryptionOracle
{
    pub fn new() -> Self
    {
        EncryptionOracle {
            key: generate_random_bytes(AES_BLOCK_SIZE),
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

        let data = plain_buffer.iter()
            .cloned()
            .chain(magic_bytes.iter().cloned())
            .collect::<Vec<_>>();

        self.encrypt::<Aes128Ecb>(data.with_padding(AES_BLOCK_SIZE).as_slice())
    }

    /// We can detect block size by continuously encrypting a growing string of identical symbols
    /// and detect when for n we get a repeating block
    fn detect_block_size(&self) -> Option<usize>
    {
        // Create encryption oracle iterator with repeating A's
        let mut a = vec![];
        let encrypted_iter = std::iter::repeat_with(|| { a.push(b'A'); self.encryption_oracle(&a) });

        // Iterate over overlapping pairs
        for (i, (a, b)) in encrypted_iter.tuple_windows().enumerate()
        {
            let n = i + 1;

            // If the current is equal to the next on the first nth bytes
            if a[0..n] == b[0..n]
            {
                return Some(n);
            }
        }

        None
    }
}


struct Oracle
{
    encryption_oracle: EncryptionOracle,
    plain_text_buffer: Vec<u8>,
    plain_text: String,
    block_size: Option<usize>,
    unknown_string_size: Option<usize>,
}


impl Oracle
{
    pub fn new() -> Self
    {
        let mut oracle = Self {
            encryption_oracle: EncryptionOracle::new(),
            plain_text_buffer: vec![],
            plain_text: String::new(),
            block_size: None,
            unknown_string_size: None,
        };

        oracle.calculate_block_size();
        oracle.initialize_plain_text();
        oracle.decipher();

        oracle
    }

    fn calculate_block_size(&mut self)
    {
        self.block_size = self.encryption_oracle.detect_block_size();
        self.unknown_string_size = self.detect_string_size();
    }

    fn detect_string_size(&self) -> Option<usize>
    {
        match self.block_size()
        {
            Some(block_size) => Some(block_size * 10_usize),
            None => None,
        }
    }

    fn initialize_plain_text(&mut self)
    {
        self.plain_text_buffer = b"A".repeat(self.unknown_string_size.expect("Approximate string size not calculated"));
    }

    pub fn block_size(&self) -> &Option<usize>
    {
        &self.block_size
    }

    fn add_new_character_to_buffer(&mut self, new_char: u8)
    {
        // Set the last element to the new char
        self.plain_text_buffer.pop();
        self.plain_text_buffer.push(new_char);

        // Move all chars to the left
        self.plain_text_buffer.remove(0);
        self.plain_text_buffer.push(b'A');

        // Add to plain text
        self.plain_text.push(new_char as char);
    }

    fn detect_new_char(&self, encrypted_target: &[u8]) -> Option<u8>
    {
        let mut buffer = self.plain_text_buffer.clone();
        let size = self.unknown_string_size.unwrap();

        for c in all_printable_chars()
        {
            // Replace last char in buffer and match with encryption (with one char short)
            buffer[size - 1] = c;
            let encrypted_dict_word = self.encryption_oracle.encryption_oracle(&buffer);

            // If the encryption matches, we have found the correct char
            if encrypted_dict_word[0..size] == encrypted_target[0..size]
            {
                return Some(c);
            }
        }

        None
    }

    fn decipher(&mut self)
    {
        let unknown_string_size = self.unknown_string_size.expect("Approximate string size not calculated");

        for i in 1..unknown_string_size
        {
            // Calculate the one short target encryption
            let n = unknown_string_size - i;
            let encrypted_target = self.encryption_oracle.encryption_oracle(&self.plain_text_buffer[0..n]);

            if let Some(new_char) = self.detect_new_char(&encrypted_target)
            {
                // New char detected. Add it to the internal buffer
                self.add_new_character_to_buffer(new_char);
            }
        }
    }

    pub fn get_plain_text(&self) -> &String
    {
        &self.plain_text
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::detect::DetectReps;

    #[test]
    fn test_challenge12_check_block_size()
    {
        // Check blocksize
        let oracle = EncryptionOracle::new();
        let block_size = oracle.detect_block_size().unwrap();

        assert_eq!(block_size, 16);
    }

    #[test]
    fn test_challenge12_detect_ecb()
    {
        // Check for repetitions - we are indeed using ECB
        let oracle = EncryptionOracle::new();
        let s = b"YELLOW SUBMARINE".repeat(10);

        assert!(oracle.encryption_oracle(&s).detect_repetitions(16));
    }

    #[test]
    fn test_challenge12()
    {
        let oracle = Oracle::new();
        let expected_plain = "\
            Rollin' in my 5.0\n\
            With my rag-top down so my hair can blow\n\
            The girlies on standby waving just to say hi\n\
            Did you stop? No, I just drove by\n";

        assert_eq!(expected_plain, oracle.get_plain_text());
    }
}
