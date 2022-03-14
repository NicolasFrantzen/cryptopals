//! Detect AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/8>

use anyhow::{Result, anyhow};
use itertools::Itertools;

use std::{io::{BufReader, BufRead}, fs::File};

fn detect_ecb_in_ciphertext(file_path: &str) -> Option<String>
{
    let file = File::open(file_path).expect("Failed to open data file.");
    let reader = BufReader::new(file);

    for cipher_text in reader.lines()
    {
        if let Ok(cipher_text) = cipher_text
        {
            match check_repititions(&hex::decode(&cipher_text).ok()?)
            {
                Ok(()) => return Some(cipher_text),
                Err(_) => (),
            }
        }

    }

    None
}

fn check_repititions(cipher_bytes: &[u8]) -> Result<()>
{
    let unique_chunks = cipher_bytes
        .chunks(16)
        .unique();

    if cipher_bytes.chunks(16).eq(unique_chunks)
    {
        Err(anyhow!("No repetitions detected"))
    }
    else
    {
        Ok(())
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge8()
    {
        let expected_ecb_lines = "\
            d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d\
            69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70d\
            c06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(detect_ecb_in_ciphertext("data/8.txt"), Some(expected_ecb_lines.to_string()));
    }
}
