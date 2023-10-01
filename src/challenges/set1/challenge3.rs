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

pub trait PatternScorer {
    fn new() -> Self;
    fn get_score(&self, pattern: &str) -> Result<u16>;
}

pub struct DictionaryScorer {
    set: Set<Vec<u8>>,
}

impl DictionaryScorer {
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

impl PatternScorer for DictionaryScorer {
    fn new() -> Self
    {
        Self::new()
    }

    fn get_score(&self, pattern: &str) -> Result<u16> {
        self.get_score(pattern)
    }
}

impl PatternScorer for Arc<DictionaryScorer> {
    fn new() -> Self
    {
        Arc::new(DictionaryScorer::new())
    }

    fn get_score(&self, pattern: &str) -> Result<u16> {
        self.deref().get_score(pattern)
    }
}

pub struct FrequencyScorer;
impl FrequencyScorer
{
    pub fn new() -> Self { Self{} }

    pub fn get_score(pattern: &str) -> Result<u16>
    {
        let score = pattern
            .split(' ')
            .fold(0, |acc, x| acc + Self::get_word_score(x));

        Ok(score)
    }

    fn get_word_score(word: &str) -> u16
    {
        let score = word.to_lowercase()
            .as_bytes()
            .iter()
            .fold(0, |acc, x| acc + Self::get_letter_score(x));

        println!("Get score: {word} => {score}");
        score
    }

    fn get_letter_score(letter: &u8) -> u16
    {
        // English letter frequency count
        /*match letter
        {
            b'a' => 812,
            b'b' => 149,
            b'c' => 271,
            b'd' => 432,
            b'e' => 1202,
            b'f' => 230,
            b'g' => 203,
            b'h' => 592,
            b'i' => 731,
            b'j' => 10,
            b'k' => 69,
            b'l' => 398,
            b'm' => 261,
            b'n' => 695,
            b'o' => 768,
            b'p' => 182,
            b'q' => 11,
            b'r' => 602,
            b's' => 628,
            b't' => 910,
            b'u' => 288,
            b'v' => 111,
            b'w' => 209,
            b'x' => 17,
            b'y' => 211,
            b'z' => 7,
            // Special chars
            b'.' => 300,
            b',' => 400,
            b'\'' => 200,
            b'/' => 100,
            b'?' => 200,
            b'!' => 200,
            b' ' => 1217,
            _ => 0,
        }*/
        // Letter count from the 19.txt and 20.txt
        match letter
        {
            b' ' => 1135,
            b'!' => 15,
            b'"' => 82,
            b'\'' => 196,
            b',' => 93,
            b'-' => 22,
            b'.' => 15,
            b'/' => 61,
            b'4' => 1,
            b':' => 5,
            b';' => 6,
            b'?' => 7,
            b'\\' => 2,
            b'a' => 369,
            b'b' => 168,
            b'c' => 127,
            b'd' => 173,
            b'e' => 584,
            b'f' => 86,
            b'g' => 88,
            b'h' => 273,
            b'i' => 375,
            b'j' => 7,
            b'k' => 63,
            b'l' => 170,
            b'm' => 152,
            b'n' => 310,
            b'o' => 348,
            b'p' => 84,
            b'q' => 4,
            b'r' => 296,
            b's' => 303,
            b't' => 439,
            b'u' => 171,
            b'v' => 43,
            b'w' => 88,
            b'x' => 5,
            b'y' => 131,
            b'z' => 11,
            _ => 0,
        }
    }
}

impl PatternScorer for FrequencyScorer {
    fn new() -> Self
    {
        Self::new()
    }

    fn get_score(&self, pattern: &str) -> Result<u16> {
        Self::get_score(pattern)
    }
}

impl PatternScorer for Arc<FrequencyScorer> {
    fn new() -> Self
    {
        Arc::new(FrequencyScorer::new())
    }

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

pub fn break_cipher<T: PatternScorer>(dict: T, cipher: &str) -> Result<Deciphered> {
    let mut key_score = HashMap::new();

    for c in 32..=255_u8 // Needed to be from 0 for challenge 19 and 20
    // All printable chars
    {
        if let Ok(deciphered) = decipher(cipher, c) {
            if deciphered.is_ascii() {
                let score = dict.get_score(&deciphered).unwrap();

                key_score.insert(c, score);
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

        if let Ok(deciphered_msg) = decipher(cipher, max_score_key) {
            if max_score > 0 {
                println!("Key became: {:?}, {}", max_score_key, max_score);

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
    pub key: u8,
    pub score: u16,
    pub cipher: String,
    pub deciphered: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge3() {
        let dict = DictionaryScorer::new();

        let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let expected_deciphered = Deciphered {
            key: b'X',
            score: 136,
            cipher: String::from(cipher),
            deciphered: String::from("Cooking MC's like a pound of bacon"),
        };
        let deciphered = break_cipher(dict, cipher).unwrap();

        assert_eq!(deciphered, expected_deciphered);
        println!("{:?}", deciphered);
    }
}
