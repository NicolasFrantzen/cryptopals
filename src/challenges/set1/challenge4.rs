//! Detect single-character XOR
//! <https://cryptopals.com/sets/1/challenges/4>

use anyhow::{anyhow, Result};
use threadpool::ThreadPool;

use std::sync::mpsc::channel;
use std::sync::Arc;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use super::challenge3::{break_cipher, Deciphered, WordScorer};

pub struct XorBreaker {
    file_path: String,
    dict: Arc<WordScorer>,
}

impl XorBreaker {
    fn new(file_path: &str) -> Self {
        let file_path = String::from(file_path);
        let dict = Arc::new(WordScorer::new());

        XorBreaker { file_path, dict }
    }

    pub fn break_it(&self) -> Result<Deciphered> {
        let (tx, rx) = channel();
        let pool = ThreadPool::new(8);

        let file = File::open(&self.file_path).expect("Failed to open data file.");
        let reader = BufReader::new(file);

        let mut lines_count = 0;
        for line in reader.lines() {
            let dict = self.dict.clone();
            let tx = tx.clone();

            pool.execute(move || {
                let deciphered = break_cipher(dict, &line.unwrap());
                tx.send(deciphered).expect("Unable to send wtf");
            });

            lines_count += 1;
        }

        let deciphered = rx
            .iter()
            .take(lines_count)
            .filter(|f| f.is_ok())
            .max_by(|a, b| a.as_ref().unwrap().score.cmp(&b.as_ref().unwrap().score));

        match deciphered {
            Some(deciphered) => deciphered,
            None => Err(anyhow!("Cannot decipher!")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge4() {
        let expected_deciphered = Deciphered {
            key: '5',
            score: 81,
            cipher: String::from("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"),
            deciphered: String::from("Now that the party is jumping\n"),
        };
        let deciphered = XorBreaker::new("data/4.txt").break_it().unwrap();

        assert_eq!(deciphered, expected_deciphered);
        println!("{:?}", deciphered);
    }
}
