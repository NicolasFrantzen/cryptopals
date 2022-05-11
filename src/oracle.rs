
use crate::aes::AES_BLOCK_SIZE;
use crate::detect::DetectReps;
use crate::utils::all_printable_chars;
use crate::padding::PADDING_CHAR;


pub trait EncryptionOracle
{
    fn encryption_oracle(&self, plain_buffer: &[u8]) -> Vec<u8>;
}


pub struct Oracle
{
    encryption_oracle: Box<dyn EncryptionOracle>,
    plain_text_buffer: Vec<u8>,
    plain_text: String,
    block_size: Option<usize>,
    unknown_string_size: Option<usize>,
    random_prefix_offset: Option<usize>,
}


impl Oracle
{
    pub fn new(encryption_oracle: Box<dyn EncryptionOracle>) -> Self
    {
        let mut oracle = Self {
            encryption_oracle,
            plain_text_buffer: vec![],
            plain_text: String::new(),
            block_size: None,
            unknown_string_size: None,
            random_prefix_offset: None,
        };

        oracle.calculate_block_size();
        oracle.initialize_plain_text();
        oracle.decipher();

        oracle
    }

    fn calculate_block_size(&mut self)
    {
        self.block_size = self.detect_block_size();
        self.unknown_string_size = self.detect_string_size();
        self.random_prefix_offset = self.detect_prefix_size();
    }

    fn detect_string_size(&self) -> Option<usize>
    {
        self.block_size().map(|block_size| block_size * 10_usize) // TODO: 10 should be calculated
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

    fn encryption_oracle_with_offset(&self, plain_buffer: &[u8]) -> Vec<u8>
    {
        if let Some(offset) = self.random_prefix_offset
        {
            // Calculate some extra padding to prepend our plain text
            let extra_padding_size = AES_BLOCK_SIZE - (offset % AES_BLOCK_SIZE);
            let mut new_buffer = vec![PADDING_CHAR; extra_padding_size];
            new_buffer.extend_from_slice(plain_buffer);

            // Return the encrypted buffer, but without the padded random prefix
            self.encryption_oracle.encryption_oracle(&new_buffer)[offset + extra_padding_size..].to_vec()
        }
        else
        {
            self.encryption_oracle.encryption_oracle(plain_buffer)
        }
    }

    fn detect_new_char(&self, encrypted_target: &[u8]) -> Option<u8>
    {
        let mut buffer = self.plain_text_buffer.clone();
        let size = self.unknown_string_size.unwrap();

        for c in all_printable_chars()
        {
            // Replace last char in buffer and match with encryption (with one char short)
            buffer[size - 1] = c;
            let encrypted_dict_word = self.encryption_oracle_with_offset(&buffer);

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
            let encrypted_target = self.encryption_oracle_with_offset(&self.plain_text_buffer[0..n]);

            if let Some(new_char) = self.detect_new_char(&encrypted_target)
            {
                // New char detected. Add it to the internal buffer
                self.add_new_character_to_buffer(new_char);
            }
        }
    }

    pub fn plain_text(&self) -> &String
    {
        &self.plain_text
    }

    pub fn detect_block_size(&self) -> Option<usize>
    {
        // Create encryption oracle iterator with repeating A's
        let mut a = vec![];
        let initial_length = self.encryption_oracle_with_offset(&a).len();
        let encrypted_iter = std::iter::repeat_with(|| { a.push(b'A'); self.encryption_oracle_with_offset(&a) });

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

    pub fn detect_prefix_size(&self) -> Option<usize>
    {
        let repetitions = 4;
        let repeated_block = "YELLOW SUBMARINE".repeat(repetitions);

        let mut buffer = repeated_block;

        for i in 0..AES_BLOCK_SIZE
        {
            let oracle_cipher = self.encryption_oracle.encryption_oracle(buffer.as_bytes());

            // Append one padding byte to align `random_prefix`
            buffer.insert(0, PADDING_CHAR as char);

            if let Some(consecutive_index) = oracle_cipher.detect_consecutive_repetitions(AES_BLOCK_SIZE, repetitions)
            {
                // Remove count of padding bytes inserted from the index
                return Some(consecutive_index - i);
            }
        }

        None
    }
}
