//! Break repeating-key XOR
//! <https://cryptopals.com/sets/1/challenges/6>

use anyhow::Result;

use std::fs::read_to_string;

fn normalize_hamming_distance(first: &[u8], second: &[u8]) -> Result<u64>
{
    assert_eq!(first.len(), second.len());
    let hamming_distance = hamming::distance_fast(first, second)?;
    let normalized_hamming_distance = hamming_distance / (first.len() as u64);

    Ok(normalized_hamming_distance)
}

struct RepeatingKeyXorBreaker
{
    cipher_text: String,
}
impl RepeatingKeyXorBreaker
{
    fn new(file_path: &str) -> Self
    {
        let cipher_text = read_to_string(file_path).expect("Unable to read file.");

        Self {
            cipher_text
        }
    }

    fn get_smallest_average_keysize(&self, keysize: u16)
    {
        todo!()
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
    fn test_challenge6_smallest_normalized_distance()
    {
        let breaker = RepeatingKeyXorBreaker::new("data/6.txt");
        // TODO
    }
}
