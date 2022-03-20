//! Implement PKCS#7 padding
//! <https://cryptopals.com/sets/1/challenges/9>

use itertools::EitherOrBoth::{Both, Right, Left};
use itertools::Itertools;


pub fn get_pkcs_7_padding(buffer: &[u8], width: usize) -> Vec<u8>
{
    let multiples: f32 = buffer.len() as f32 / width as f32;
    let width: usize = (multiples.ceil() as usize) * width;

    let padding = vec![0x04 as u8; width];

    buffer.iter()
        .clone()
        .zip_longest(padding.iter())
        .map(|x| match x { Both(&a, _) => a, Right(&b) => b, Left(&a) => a })
        .collect::<Vec<_>>()
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::utils::UnicodeVectors;

    #[test]
    fn test_challenge9()
    {
        assert_eq!(&get_pkcs_7_padding("YELLOW SUBMARINE".as_bytes(), 20).to_string(), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!(&get_pkcs_7_padding("HEJHEJHEJHEJHEJ".as_bytes(), 4).to_string(), "HEJHEJHEJHEJHEJ\x04");

        assert_eq!(&get_pkcs_7_padding("HEJHEJHEJHEJHEJ".as_bytes(), 4), "HEJHEJHEJHEJHEJ\x04".as_bytes());
    }
}
