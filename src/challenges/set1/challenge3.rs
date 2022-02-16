#![allow(dead_code)]
#![allow(unused_variables)]


use std::{io::{BufReader, BufRead}, fs::File};
use std::collections::HashMap;

use anyhow::Result;

use fst::{IntoStreamer, Set};
use fst::automaton::Levenshtein;


struct WordScorer
{
    set: Set<Vec<u8>>,
}

impl WordScorer
{
    fn new() -> Self
    {
        let file = File::open("dictionary/american-english").expect("Failed to open dictionary file.");
        let buf = BufReader::new(file);
        let lines: Vec<String> = buf.lines()
            .map(|l| l.expect("Failed to parse line"))
            .collect();

        let set = Set::from_iter(lines).unwrap();

        Self{set}
    }

    fn get_word_score(&self, word: &str) -> Result<u16>
    {
        // Build our fuzzy query.
        let lev = Levenshtein::new(word, 1)?;

        // Apply our fuzzy query to the set we built.
        let stream = self.set.search(lev).into_stream();

        let keys = stream.into_strs()?;

        Ok(keys.len() as u16)
    }

    fn get_score(&self, pattern: &str) -> Result<u16>
    {
        let score = pattern.split(' ')
            .map(|w| self.get_word_score(w))
            .sum::<Result<u16,_>>()?;

        Ok(score)
    }
}

fn decipher(cipher: &str, key: &char) -> Result<String>
{
    let mut key_arr = [0, 1];
    key.encode_utf8(&mut key_arr);
    let key = key_arr[0];

    let iter: Vec<u8> = hex::decode(cipher)?
        .iter()
        .map(|c| c ^ key )
        .collect();

    Ok(String::from_utf8_lossy(&iter).into_owned())
}

fn break_cipher(cipher: &str) -> Option<char>
{
    let dict = WordScorer::new();
    let mut key_score = HashMap::new();

    for c in 'A'..='z'
    {
        if let Ok(deciphered) = decipher(cipher, &c)
        {
            let score = dict.get_score(&deciphered).unwrap();
            key_score.insert(c, score);
        }
    }

    let max_score_key = key_score.iter()
        .max_by(|a, b| a.1.cmp(b.1))
        .map(|(k, _v)| *k);

    if let Some(max_score_key) = max_score_key
    {
        let deciphered_msg = decipher(cipher, &max_score_key);
        println!("The deciphered phrase seems to be: \"{}\". With a score of {}", deciphered_msg.unwrap(), key_score[&max_score_key]);
    }

    max_score_key
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge()
    {
        // We are looking for the message "Cooking MC's like a pound of bacon"
        let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        assert_eq!(break_cipher(cipher), Some('X'));
    }
}
