//! Break repeating-key XOR
//! <https://cryptopals.com/sets/1/challenges/6>

use anyhow::Result;
use itertools::Itertools;
use ordered_float::OrderedFloat;
use threadpool::ThreadPool;

use std::fs::read_to_string;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::marker::{Send, Sync};

use crate::utils::{UnicodeUtils, Base64};

use super::challenge3::{break_cipher, PatternScorer};

fn normalize_hamming_distance(first: &[u8], second: &[u8]) -> Result<u64> {
    assert_eq!(first.len(), second.len());
    let hamming_distance = hamming::distance_fast(first, second)?;
    let normalized_hamming_distance = hamming_distance / (first.len() as u64);

    Ok(normalized_hamming_distance)
}

fn normalize_hamming_distance_on_slices(buffer: &[u8], keysize: usize) -> Result<f64> {
    let mut slices: Vec<&[u8]> = vec![];
    for i in 0..4 {
        let slice = &buffer[i * keysize..(i + 1) * keysize];
        slices.push(slice);
    }

    let combinations = slices.iter().tuple_combinations();
    let count = combinations.clone().count() as f64;

    let distance_sum = combinations
        .map(|(a, b)| normalize_hamming_distance(a, b))
        .map(Result::unwrap)
        .sum::<u64>();

    //println!("{:?}", distance_sum);

    Ok(distance_sum as f64 / count)
}

pub struct RepeatingKeyXorBreaker<Scorer: PatternScorer> {
    cipher_buffer: Vec<u8>,
    scorer: Arc<Scorer>,
}

impl<Scorer: PatternScorer + Send + Sync + 'static> RepeatingKeyXorBreaker<Scorer>
where Arc<Scorer>: PatternScorer {
    pub fn new(cipher_buffer: &[u8]) -> Self {
        Self {
            cipher_buffer: cipher_buffer.to_owned(),
            scorer: Arc::new(Scorer::new()),
        }
    }

    fn new_from_file(file_path: &str) -> Self {
        let cipher_text = read_to_string(file_path).expect("Unable to read file.");

        let cipher_buffer: Vec<_> = cipher_text
            .split('\n')
            .flat_map(|l| l.decode_base64().into_bytes())
            .collect();

        Self { cipher_buffer, scorer: Arc::new(Scorer::new()) }
    }

    fn get_smallest_average_keysize(&self) -> Option<usize> {
        (2..40).min_by_key(|i| {
            OrderedFloat(normalize_hamming_distance_on_slices(&self.cipher_buffer, *i).unwrap())
        })
    }

    fn get_blocks(&self, size: usize) -> Vec<&[u8]> {
        self.cipher_buffer.chunks(size).collect::<Vec<&[u8]>>()
    }

    fn get_transposed_blocks(&self) -> Vec<String> {
        /*let keysize = self
            .get_smallest_average_keysize()
            .expect("Key size could not be found.");*/
        let keysize = 53; // TODO

        let blocks = self.get_blocks(keysize);

        let mut transposed_blocks: Vec<String> = vec![];
        for i in 0..keysize {
            let mut new_block: Vec<u8> = vec![];

            for block in blocks.iter() {
                //println!("Block {:?}", block);

                if i < block.len() {
                    let val = block[i];
                    new_block.push(val);
                }
            }

            transposed_blocks.push(hex::encode(new_block));
        }

        transposed_blocks
    }

    pub fn break_blocks(&self) -> Vec<u8> {
        let (tx, rx) = channel();
        let pool = ThreadPool::new(8);

        let blocks = self.get_transposed_blocks();
        let blocks_num = blocks.len();
        //println!("Blocks num: {:?}", blocks_num);

        for (i, block) in blocks.into_iter().enumerate() {
            let scorer = self.scorer.clone();
            let tx = tx.clone();

            pool.execute(move || {
                let deciphered = break_cipher(scorer, &block);

                println!("Deciphered: {:?}", deciphered);

                tx.send((i, deciphered)).expect("Unable to send wtf");
            });
        }

        rx.iter()
            .take(blocks_num)
            .sorted_by(|a, b| Ord::cmp(&a.0, &b.0))
            .map(|k| k.1.unwrap().key)
            .collect::<Vec<_>>()
    }

    fn decrypt(&self, key: &[u8]) -> String {
        let xored_bytes = &self.cipher_buffer.xor_repeating_key(key);

        String::from_utf8_lossy(xored_bytes).into_owned()
    }

    pub fn break_it(&self) -> String {
        let key = self.break_blocks();

        println!("Keysize: {:?}", key.len());

        self.decrypt(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenges::set1::challenge3::DictionaryScorer;

    #[test]
    fn test_challenge6_hamming_distance() {
        // Make sure we using a correct implementation of hamming distance
        assert_eq!(
            hamming::distance_fast("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
                .unwrap(),
            37
        );
    }

    #[test]
    fn test_challenge6_normalized_hamming_distance() {
        assert_eq!(
            normalize_hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
                .unwrap(),
            2
        );
    }

    #[test]
    fn test_challenge6_normalized_hamming_distance_on_slices() {
        assert_eq!(
            normalize_hamming_distance_on_slices(
                "this is a testwokka wokka!!!this is a testwokka wokka!!!".as_bytes(),
                14
            )
            .unwrap(),
            1.3333333333333333
        );
        assert_eq!(
            normalize_hamming_distance_on_slices("hejhejhejhej".as_bytes(), 3).unwrap(),
            0.0
        );
    }

    #[test]
    fn test_challenge6_smallest_normalized_distance() {
        let breaker = RepeatingKeyXorBreaker::<DictionaryScorer>::new_from_file("data/6.txt");

        assert_eq!(breaker.get_smallest_average_keysize(), Some(29));
    }

    #[test]
    fn test_challenge6_get_transposed_blocks() {
        let breaker = RepeatingKeyXorBreaker::<DictionaryScorer>::new_from_file("data/6.txt");

        let _transposed_blocks = breaker.get_transposed_blocks();
        // TODO: write a test of something i dno
        //println!("{:?}", transposed_blocks);
    }

    #[test]
    fn test_challenge6_break_blocks() {
        let breaker = RepeatingKeyXorBreaker::<DictionaryScorer>::new_from_file("data/6.txt");
        assert_eq!(breaker.break_blocks(), "Terminator X: Bring the noise".as_bytes());
    }

    #[test]
    fn test_challenge6_decrypt() {
        let breaker = RepeatingKeyXorBreaker::<DictionaryScorer>::new_from_file("data/6.txt");
        let plaintext = breaker.decrypt("Terminator X: Bring the noise".as_bytes());

        println!("{:?}", plaintext);
        assert_eq!(&plaintext[..33], "I'm back and I'm ringin' the bell");
    }

    #[test]
    fn test_challenge6_break() {
        let breaker = RepeatingKeyXorBreaker::<DictionaryScorer>::new_from_file("data/6.txt");
        let plaintext = breaker.break_it();

        println!("{:?}", plaintext);
        assert_eq!(&plaintext[..33], "I'm back and I'm ringin' the bell");
    }
}
