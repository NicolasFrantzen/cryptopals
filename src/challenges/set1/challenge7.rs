//! AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/7>

use crate::aes::Aes128;
use crate::utils::UnicodeUtils;

use std::fs::read_to_string;

fn decrypt_ecb_base64_from_file(file: &str, key: &str) -> String {
    let cipher_text = read_to_string(file).expect("Unable to read file.");
    let cipher_buffer = cipher_text
        .split('\n')
        .flat_map(|l| base64::decode(l).expect("Not valid base64."))
        .collect::<Vec<_>>();

    cipher_buffer
        .decrypt_aes_128_ecb(key.as_bytes())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge7() {
        let plain_text = decrypt_ecb_base64_from_file("data/7.txt", "YELLOW SUBMARINE");
        assert_eq!(&plain_text[0..33], "I'm back and I'm ringin' the bell");
    }
}
