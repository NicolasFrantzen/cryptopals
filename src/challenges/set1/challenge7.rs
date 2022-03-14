//! AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/7>

use openssl::{symm, symm::Cipher};

use std::fs::read_to_string;

fn decrypt(key: &str) -> String
{
    let cipher = Cipher::aes_128_ecb();
    let cipher_text = read_to_string("data/7.txt").expect("Unable to read file.");
    let cipher_buffer: Vec<_> = cipher_text.split('\n')
        .flat_map(|l| base64::decode(l).expect("Not valid base64."))
        .collect();

    let plaintext = symm::decrypt(cipher, key.as_bytes(), None, &cipher_buffer).unwrap();

    String::from_utf8_lossy(&plaintext).to_string()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge7()
    {
        let plaintext = decrypt("YELLOW SUBMARINE");
        assert_eq!(&plaintext[0..33], "I'm back and I'm ringin' the bell");
    }
}
