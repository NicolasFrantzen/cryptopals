use itertools::EitherOrBoth::{Both, Right, Left};
use itertools::Itertools;
use anyhow::{Result, anyhow};

use crate::utils::{UnicodeUtils, all_printable_chars};


pub const PADDING_CHAR: u8 = 0x04_u8;


pub trait Pkcs7Padding
{
    type OwnedPaddingType;

    fn with_padding(&self, block_size: usize) -> Self::OwnedPaddingType;
    fn without_padding(&self) -> &Self;
    fn validate_padding(&self) -> Result<&Self>;
}


pub fn padded_size(length: usize, block_size: usize) -> usize
{
    let multiples: f32 = length as f32 / block_size as f32;

    (multiples.ceil() as usize) * block_size
}


impl Pkcs7Padding for [u8]
{
    type OwnedPaddingType = Vec<u8>;

    /// Applies chr(N) of N padding bytes at end of buffer to fill size of width * M for some M
    fn with_padding(&self, block_size: usize) -> Vec<u8>
    {
        let size = padded_size(self.len(), block_size);
        let padding = size - self.len();

        self.iter()
            .zip_longest(std::iter::repeat(padding as u8).take(size))
            .map(|x| match x { Both(&a, _) => a, Right(b) => b, Left(&a) => a })
            .collect::<Vec<_> >()
    }

    /// Return slice without padding on the right hand side
    fn without_padding(&self) -> &[u8]
    {
        match self.validate_padding()
        {
            Ok(buffer_without_padding) => buffer_without_padding,
            Err(_) => self,
        }
    }

    /// Set 2 Challenge 15
    /// Validate padding, i.e. accept bytes padded with 0x04, but not other unprintable chars.
    /// This function does not assume any buffer size
    fn validate_padding(&self) -> Result<&Self>
    {
        let padding = self[self.len()-1];

        if all_printable_chars().contains(&padding as &u8)
        {
            return Ok(self);
        }

        let padding_size = padding as usize;
        if padding_size < self.len()
        {
            let padding_start = self.len() - padding_size;

            if self.iter()
                .skip(padding_start)
                .all(|&c| c == padding)
            {
                return self[..padding_start].validate_padding();
            }
        }

        Err(anyhow!("Invalid padding!"))
    }
}


impl Pkcs7Padding for str
{
    type OwnedPaddingType = String;

    /// Applies 0x04 padding to end of string to fill size of width * N for some N
    fn with_padding(&self, width: usize) -> String
    {
        self.as_bytes().with_padding(width).to_string()
    }

    /// Trim padding on the right hand side
    fn without_padding(&self) -> &str
    {
        self.as_bytes().without_padding().to_str()
    }

    /// Validate padding
    fn validate_padding(&self) -> Result<&str>
    {
        self.as_bytes()
            .validate_padding()
            .map(|s| s.to_str())
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::utils::UnicodeUtils;

    #[test]
    fn test_padding_with()
    {
        // Vec<u8>
        assert_eq!("YELLOW SUBMARINE".as_bytes().with_padding(16).to_string(), "YELLOW SUBMARINE");
        assert_eq!("YELLOW SUBMARINE".as_bytes().with_padding(20).to_string(), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4).to_string(), "HEJHEJHEJHEJHEJ\x01");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4), "HEJHEJHEJHEJHEJ\x01".as_bytes());

        // String
        assert_eq!("YELLOW SUBMARINE".with_padding(16), "YELLOW SUBMARINE");
        assert_eq!("YELLOW SUBMARINE".with_padding(20), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".with_padding(4), "HEJHEJHEJHEJHEJ\x01");
    }

    #[test]
    fn test_padding_without()
    {
        // &[u8]
        assert_eq!("YELLOW SUBMARINE".as_bytes(), "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes(), "HEJHEJHEJHEJHEJ\x01".as_bytes().without_padding());
        assert_eq!("YELLOW\x04 SUBMARINE".as_bytes(), "YELLOW\x04 SUBMARINE\x04\x04\x04\x04".as_bytes().without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes(), "HEJHEJHEJHEJHEJ".as_bytes().without_padding());
        assert_eq!("YELLOW SUBMARINE\x04\x03\x02\x01".as_bytes(), "YELLOW SUBMARINE\x04\x03\x02\x01".as_bytes().without_padding());

        // &str
        assert_eq!("YELLOW SUBMARINE", "YELLOW SUBMARINE\x04\x04\x04\x04".without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ", "HEJHEJHEJHEJHEJ\x01".without_padding());
        assert_eq!("YELLOW\x04 SUBMARINE", "YELLOW\x04 SUBMARINE\x04\x04\x04\x04".without_padding());
        assert_eq!("HEJHEJHEJHEJHEJ", "HEJHEJHEJHEJHEJ".without_padding());
        assert_eq!("YELLOW SUBMARINE\x04\x03\x02\x01", "YELLOW SUBMARINE\x04\x03\x02\x01".without_padding());
    }

    #[test]
    fn test_padding_validate()
    {
        // Valid
        assert_eq!("ICE ICE BABY\x04\x04\x04\x04".as_bytes().validate_padding().unwrap(), "ICE ICE BABY".as_bytes());
        assert_eq!("ICE ICE BABY".as_bytes().validate_padding().unwrap(), "ICE ICE BABY".as_bytes());
        assert_eq!("ICE ICE BAB\x05\x05\x05\x05\x05".as_bytes().validate_padding().unwrap(), "ICE ICE BAB".as_bytes());
        assert_eq!("YELLOW SUBMARIN\x01".as_bytes().validate_padding().unwrap(), "YELLOW SUBMARIN".as_bytes());

        // Invalid
        assert!("ICE ICE BABY\x05\x05\x05\x05".as_bytes().validate_padding().is_err());
        assert!("ICE ICE BABY\x01\x02\x03\x04".as_bytes().validate_padding().is_err());
        assert!("YELLOW SUBMA\x04\x03\x02\x01".as_bytes().validate_padding().is_err());
    }
}
