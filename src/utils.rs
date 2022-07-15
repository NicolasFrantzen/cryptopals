use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand::distributions::Standard;


pub trait UnicodeUtils
{
    fn to_string(&self) -> String;
    fn to_str(&self) -> &str;
    fn append_char(&self, c: u8) -> Vec<u8>;
    fn xor(&self, c: u8) -> Vec<u8>;
}


impl UnicodeUtils for [u8]
{
    fn to_string(&self) -> String
    {
        String::from_utf8_lossy(self).to_string()
    }

    fn to_str(&self) -> &str
    {
        std::str::from_utf8(self).expect("Invalid UTF-8 string")
    }

    fn append_char(&self, c: u8) -> Vec<u8>
    {
        let mut new_vec = self.to_vec();
        new_vec.push(c);

        new_vec
    }

    fn xor(&self, c: u8) -> Vec<u8>
    {
        self.iter()
            .map(|x| x ^ c)
            .collect_vec()
    }
}


pub fn generate_random_bytes(size: Option<usize>) -> Vec<u8>
{
    let mut rng = thread_rng();

    let size = match size
    {
        Some(size) => size,
        None => rng.gen_range(0..256),
    };

    rng.sample_iter(Standard)
        .take(size)
        .collect::<Vec<u8>>()
}


pub fn all_printable_chars() -> impl Iterator<Item = u8>
{
    (32..=127_u8).chain(std::iter::once(b'\n'))
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_unicode_utils_xor()
    {
        assert_eq!(
            [0, 0, 68].xor(1),
            [1, 1, 69]
        );

        assert_eq!(
            [68, 68, 68].xor(1),
            [69, 69, 69]
        );
    }
}