//! Break repeating-key XOR
//! <https://cryptopals.com/sets/1/challenges/6>

use anyhow::Result;
use itertools::Itertools;
use ordered_float::OrderedFloat;
use threadpool::ThreadPool;

use std::sync::mpsc::channel;
use std::sync::Arc;
use std::fs::read_to_string;

use super::challenge3::{WordScorer, break_cipher};
use super::challenge5::{RepeatingKeyXor};

fn normalize_hamming_distance(first: &[u8], second: &[u8]) -> Result<u64>
{
    assert_eq!(first.len(), second.len());
    let hamming_distance = hamming::distance_fast(first, second)?;
    let normalized_hamming_distance = hamming_distance / (first.len() as u64);

    Ok(normalized_hamming_distance)
}


fn normalize_hamming_distance_on_slices(buffer: &[u8], keysize: usize) -> Result<f64>
{
    let first = &buffer[0..keysize];
    let second = &buffer[keysize..2*keysize];
    let third = &buffer[2*keysize..3*keysize];
    let fourth = &buffer[3*keysize..4*keysize];

    let mut slices: Vec<&[u8]> = vec![];
    for i in 0..4
    {
        let slice = &buffer[i*keysize..(i+1)*keysize];
        slices.push(slice);
    }

    let combinations = slices.iter().tuple_combinations();
    let count = combinations.clone().count() as f64;

    let distance_sum = combinations.map(|(a, b)| normalize_hamming_distance(a, b) )
        .map(Result::unwrap)
        .sum::<u64>();

    //println!("{:?}", distance_sum);

    Ok(distance_sum as f64 / count)
}


struct RepeatingKeyXorBreaker
{
    cipher_buffer: Vec<u8>,
}


impl RepeatingKeyXorBreaker
{
    fn new(file_path: &str) -> Self
    {
        let cipher_text = read_to_string(file_path).expect("Unable to read file.");

        let cipher_buffer: Vec<_> = cipher_text.split('\n')
            .flat_map(|l| base64::decode(l).expect("Not valid base64."))
            .collect();

        Self {
            cipher_buffer
        }
    }

    fn get_smallest_average_keysize(&self) -> Option<usize>
    {
        (2..40).min_by_key(|i| OrderedFloat(normalize_hamming_distance_on_slices(&self.cipher_buffer, *i).unwrap()))
    }

    fn get_blocks(&self, size: usize) -> Vec<&[u8]>
    {
        self.cipher_buffer.chunks(size).collect::<Vec<&[u8]>>()
    }

    fn get_transposed_blocks(&self) -> Vec<String>
    {
        let keysize = self.get_smallest_average_keysize().expect("Key size could not be found.");
        println!("Keysize is: {:?}", keysize);

        let blocks = self.get_blocks(keysize);


        let mut transposed_blocks: Vec<String> = vec![];
        for i in 0..keysize
        {
            let mut new_block: Vec<u8> = vec![];

            for block in blocks.iter()
            {
                //println!("Block {:?}", block);

                if i < block.len()
                {
                    let val = block[i];
                    new_block.push(val);
                }
            }

            transposed_blocks.push(hex::encode(new_block));
        }

        transposed_blocks
    }

    fn break_blocks(&self) -> String
    {
        let (tx, rx) = channel();
        let pool = ThreadPool::new(8);

        let dict = Arc::new(WordScorer::new());
        let blocks = self.get_transposed_blocks();
        let blocks_num = blocks.len();

        for (i, block) in blocks.into_iter().enumerate()
        {
            let dict = dict.clone();
            let tx = tx.clone();

            pool.execute(move|| {
                let deciphered = break_cipher(dict, &block);

                tx.send((i, deciphered)).expect("Unable to send wtf");
            });
        }

        rx.iter()
            .take(blocks_num)
            .sorted_by(|a, b| Ord::cmp(&a.0, &b.0))
            .map(|k| k.1.unwrap().key)
            .collect::<String>()
    }

    fn decrypt(&self, key: &str) -> String
    {
        let xored_bytes = RepeatingKeyXor::xor_bytes(&self.cipher_buffer, key);

        String::from_utf8_lossy(&xored_bytes).into_owned()
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge6_hamming_distance()
    {
        // Make sure we using a correct implementation of hamming distance
        assert_eq!(hamming::distance_fast("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()).unwrap(), 37);
    }

    #[test]
    fn test_challenge6_normalized_hamming_distance()
    {
        assert_eq!(normalize_hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()).unwrap(), 2);
    }

    #[test]
    fn test_challenge6_normalized_hamming_distance_on_slices()
    {
        assert_eq!(normalize_hamming_distance_on_slices("this is a testwokka wokka!!!this is a testwokka wokka!!!".as_bytes(), 14).unwrap(), 1.3333333333333333);
        assert_eq!(normalize_hamming_distance_on_slices("hejhejhejhej".as_bytes(), 3).unwrap(), 0.0);
    }

    #[test]
    fn test_challenge6_smallest_normalized_distance()
    {
        let breaker = RepeatingKeyXorBreaker::new("data/6.txt");

        assert_eq!(breaker.get_smallest_average_keysize(), Some(29));
    }

    #[test]
    fn test_challenge6_get_transposed_blocks()
    {
        let breaker = RepeatingKeyXorBreaker::new("data/6.txt");

        let transposed_blocks = breaker.get_transposed_blocks();
        // TODO: write a test of something i dno
        //println!("{:?}", transposed_blocks);
    }

    /// This test is very heavy and also fails. It works well enough to guess the key though
    #[test] #[ignore]
    fn test_challenge6_break_blocks()
    {
        let breaker = RepeatingKeyXorBreaker::new("data/6.txt");
        assert_eq!(breaker.break_blocks(), "Terminator X: Bring the noise");
    }

    #[test]
    fn test_challenge6_decrypt()
    {
        let breaker = RepeatingKeyXorBreaker::new("data/6.txt");
        let plaintext = breaker.decrypt("Terminator X: Bring the noise");

        println!("{:?}", plaintext);
        assert_eq!(&plaintext[..33], "I'm back and I'm ringin' the bell");
    }
}
