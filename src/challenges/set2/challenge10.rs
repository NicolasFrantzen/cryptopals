//! Implement CBC mode
//! <https://cryptopals.com/sets/2/challenges/10>

#[cfg(test)]
mod tests {
    //use super::*;

    use crate::aes::Aes128;
    use crate::utils::UnicodeUtils;

    use std::fs::read_to_string;

    #[test]
    fn test_challenge10_decrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let cipher_text = read_to_string("data/10.txt").expect("Unable to read file.");

        let cipher_buffer: Vec<_> = cipher_text
            .split('\n')
            .flat_map(|l| base64::decode(l).expect("Not valid base64."))
            .collect();

        let plain_text = cipher_buffer.decrypt_aes_128_cbc(key).to_string();
        assert_eq!(&plain_text[0..33], "I'm back and I'm ringin' the bell");
    }

    #[test]
    fn test_challenge10_encrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let cipher_text = read_to_string("data/10.txt").expect("Unable to read file.");
        let cipher_buffer = "I'm back and I'm ringin' the bell"
            .as_bytes()
            .encrypt_aes_128_cbc(key);

        // Padding starts at index 42
        assert_eq!(&cipher_text[0..42], &base64::encode(&cipher_buffer)[0..42]);
    }
}
