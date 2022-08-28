//! Single-byte XOR cipher
//! <https://cryptopals.com/sets/1/challenges/3>

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::{anyhow, Result};

use fst::automaton::Levenshtein;
use fst::{IntoStreamer, Set};

pub trait GetScore {
    fn get_score(&self, pattern: &str) -> Result<u16>;
}

pub struct WordScorer {
    set: Set<Vec<u8>>,
}

impl WordScorer {
    pub fn new() -> Self {
        let file =
            File::open("dictionary/american-english").expect("Failed to open dictionary file.");
        let buf = BufReader::new(file);
        let lines: Vec<String> = buf
            .lines()
            .map(|l| l.expect("Failed to parse line"))
            .collect();

        let set = Set::from_iter(lines).unwrap();

        Self { set }
    }

    fn get_word_score(&self, word: &str) -> Result<u16> {
        let is_dictionary_word = word.chars().all(|c| {
            (65..=90).contains(&(c as u8)) || (97..=122).contains(&(c as u8)) || c == '\''
        });

        if is_dictionary_word {
            // Build our fuzzy query.
            let lev = Levenshtein::new(word, 1)?;

            // Apply our fuzzy query to the set we built.
            let stream = self.set.search(lev).into_stream();

            let keys = stream.into_strs()?;

            Ok(keys.len() as u16)
        } else {
            // Most likely not a dictionary word, let's not score it
            Ok(0)
        }
    }

    pub fn get_score(&self, pattern: &str) -> Result<u16> {
        let score = pattern
            .split(' ')
            .map(|w| self.get_word_score(w))
            .sum::<Result<u16, _>>()?;

        Ok(score)
    }
}

impl GetScore for WordScorer {
    fn get_score(&self, pattern: &str) -> Result<u16> {
        self.get_score(pattern)
    }
}

impl GetScore for Arc<WordScorer> {
    fn get_score(&self, pattern: &str) -> Result<u16> {
        self.deref().get_score(pattern)
    }
}

fn decipher(cipher: &str, key: u8) -> Result<String> {
    let iter: Vec<u8> = hex::decode(cipher)?
        .iter()
        .cloned()
        .map(|c| c ^ key)
        .collect();

    Ok(String::from_utf8_lossy(&iter).into_owned())
}

pub fn break_cipher<T: GetScore>(dict: T, cipher: &str) -> Result<Deciphered> {
    let mut key_score = HashMap::new();

    for c in 32..=127u8
    // All printable chars
    {
        if let Ok(deciphered) = decipher(cipher, c) {
            if deciphered.is_ascii() {
                let score = dict.get_score(&deciphered).unwrap();

                key_score.insert(c as char, score);
            }
        }
    }

    //println!("Keyscores: {:?}", key_score);

    let max_score_key = key_score
        .iter()
        .max_by(|a, b| a.1.cmp(b.1))
        .map(|(k, _v)| *k);

    if let Some(max_score_key) = max_score_key {
        let max_score = key_score[&max_score_key];

        if let Ok(deciphered_msg) = decipher(cipher, max_score_key as u8) {
            if max_score > 0 {
                //println!("Key became: {:?}", max_score_key);

                return Ok(Deciphered {
                    key: max_score_key,
                    score: max_score,
                    cipher: String::from(cipher),
                    deciphered: deciphered_msg,
                });
            }
        }
    }

    Err(anyhow!("Unable to break the cipher."))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Deciphered {
    pub key: char,
    pub score: u16,
    pub cipher: String,
    pub deciphered: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge3() {
        let dict = WordScorer::new();

        let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let expected_deciphered = Deciphered {
            key: 'X',
            score: 136,
            cipher: String::from(cipher),
            deciphered: String::from("Cooking MC's like a pound of bacon"),
        };
        let deciphered = break_cipher(dict, cipher).unwrap();

        assert_eq!(deciphered, expected_deciphered);
        println!("{:?}", deciphered);
    }
}
