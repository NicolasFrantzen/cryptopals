//! Detect single-character XOR
//! <https://cryptopals.com/sets/1/challenges/4>

use anyhow::{Result, anyhow};

use std::{io::{BufReader, BufRead}, fs::File};
use std::rc::Rc;

use super::challenge3::{WordScorer, Deciphered, break_cipher};

fn find_xor_encryptet_string() -> Result<Deciphered>
{
    let dict = Rc::new(WordScorer::new());

    let file = File::open("data/4.txt").expect("Failed to open data file.");
    let reader = BufReader::new(file);

    let deciphered = reader.lines()
        .map(Result::unwrap)
        .map(|l| break_cipher(dict.clone(), &l))
        .filter(|f| f.is_ok())
        .max_by(|a, b| a.as_ref().unwrap().score.cmp(&b.as_ref().unwrap().score));

    match deciphered {
        Some(deciphered) => deciphered,
        None => Err(anyhow!("bpb"))
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test] #[ignore]
    fn test_challenge4()
    {
        let expected_deciphered = Deciphered {
            key: '5',
            score: 82,
            cipher: String::from("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"),
            deciphered: String::from("Now that the party is jumping\n"),
        };
        let deciphered = find_xor_encryptet_string().unwrap();

        assert_eq!(deciphered, expected_deciphered);
        println!("{:?}",  deciphered);
    }
}
