use itertools::EitherOrBoth::{Both, Right, Left};
use itertools::Itertools;

pub trait Pkcs7Padding
{
    fn with_padding(&self, width: usize) -> Vec<u8>;
}


impl Pkcs7Padding for [u8]
{
    fn with_padding(&self, width: usize) -> Vec<u8>
    {
        let multiples: f32 = self.len() as f32 / width as f32;
        let width: usize = (multiples.ceil() as usize) * width;

        self.iter()
            .zip_longest(std::iter::repeat(0x04_u8).take(width))
            .map(|x| match x { Both(&a, _) => a, Right(b) => b, Left(&a) => a })
            .collect::<Vec<_> >()
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::utils::UnicodeUtils;

    #[test]
    fn test_get_padding()
    {
        assert_eq!("YELLOW SUBMARINE".as_bytes().with_padding(20).to_string(), "YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4).to_string(), "HEJHEJHEJHEJHEJ\x04");
        assert_eq!("HEJHEJHEJHEJHEJ".as_bytes().with_padding(4), "HEJHEJHEJHEJHEJ\x04".as_bytes());
    }
}
