use itertools::EitherOrBoth::{Both, Right, Left};
use itertools::Itertools;

use crate::utils::UnicodeUtils;

pub trait Pkcs7Padding<T>
{
    fn with_padding(&self, width: usize) -> T;
    fn without_padding(&self) -> T;
}


impl Pkcs7Padding<Vec<u8>> for [u8]
{
    /// Applies 0x04 padding bytes at end of buffer to fill size of width * N for some N
    fn with_padding(&self, width: usize) -> Vec<u8>
    {
        let multiples: f32 = self.len() as f32 / width as f32;
        let width: usize = (multiples.ceil() as usize) * width;

        self.iter()
            .zip_longest(std::iter::repeat(0x04_u8).take(width))
            .map(|x| match x { Both(&a, _) => a, Right(b) => b, Left(&a) => a })
            .collect::<Vec<_> >()
    }

    /// Removes padding from buffer. Currently not only trailing padding bytes will be removed,
    /// but any padding byte in the string.
    fn without_padding(&self) -> Vec<u8>
    {
        self.iter().cloned().take_while(|x| *x != 0x04_u8).collect::<Vec<_>>()
    }
}


impl Pkcs7Padding<String> for str
{
    fn with_padding(&self, width: usize) -> String
    {
        self.as_bytes().with_padding(width).to_string()
    }

    fn without_padding(&self) -> String
    {
        self.as_bytes().without_padding().to_string()
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::utils::UnicodeUtils;

    #[test]
    fn test_with_padding()
    {
        // Vec<u8>
        assert_eq!("YELLOW SUBMARINE".as_bytes().with_padding(20).to_string(), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4).to_string(), "HEJHEJHEJHEJHEJ\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4), "HEJHEJHEJHEJHEJ\x04".as_bytes());

        // String
        assert_eq!("YELLOW SUBMARINE".with_padding(20), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".with_padding(4), "HEJHEJHEJHEJHEJ\x04");
    }

    #[test]
    fn test_without_padding()
    {
        // Vec<u8>
        assert_eq!("YELLOW SUBMARINE".as_bytes(), "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes(), "HEJHEJHEJHEJHEJ\x04".as_bytes().without_padding());

        // String
        assert_eq!("YELLOW SUBMARINE", "YELLOW SUBMARINE\x04\x04\x04\x04".without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ", "HEJHEJHEJHEJHEJ\x04".without_padding());
    }
}
