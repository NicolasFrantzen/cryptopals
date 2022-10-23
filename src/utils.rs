use itertools::Itertools;
use rand::distributions::Standard;
use rand::{thread_rng, Rng};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

pub trait UnicodeUtils {
    fn to_string(&self) -> String;
    fn to_str(&self) -> &str;
    fn append_char(&self, c: u8) -> Vec<u8>;
    fn xor(&self, c: u8) -> Vec<u8>;
    fn xor_all<'a, I: IntoIterator<Item = &'a u8>>(&self, other: I) -> Vec<u8>;
    fn xor_repeating_key(&self, key: &[u8]) -> Vec<u8>;
}

pub trait Base64 {
    type ReturnType;
    fn decode_base64(&self) -> Self::ReturnType;
    fn encode_base64(&self) -> Self::ReturnType;
}

impl UnicodeUtils for [u8] {
    fn to_string(&self) -> String {
        String::from_utf8_lossy(self).to_string()
    }

    fn to_str(&self) -> &str {
        std::str::from_utf8(self).expect("Invalid UTF-8 string")
    }

    fn append_char(&self, c: u8) -> Vec<u8> {
        let mut new_vec = self.to_vec();
        new_vec.push(c);

        new_vec
    }

    fn xor(&self, c: u8) -> Vec<u8> {
        self.iter().map(|x| x ^ c).collect_vec()
    }

    fn xor_all<'a, I: IntoIterator<Item = &'a u8>>(&self, other: I) -> Vec<u8> {
        self.iter()
            .zip(other.into_iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>()
    }

    fn xor_repeating_key(&self, key: &[u8]) -> Vec<u8> {
        let num_repeat_to_fit: usize = (self.len() as f32 / key.len() as f32).ceil() as usize;
        let repeated_key = key.repeat(num_repeat_to_fit);

        self.xor_all(repeated_key.iter())
    }
}

impl Base64 for [u8] {
    type ReturnType = Vec<u8>;

    fn decode_base64(&self) -> Self::ReturnType {
        base64::decode(self).expect("Invalid base64 string.")
    }

    fn encode_base64(&self) -> Self::ReturnType {
        base64::encode(self).into_bytes()
    }
}

impl Base64 for str {
    type ReturnType = String;

    fn decode_base64(&self) -> Self::ReturnType {
        base64::decode(self).expect("Invalid base64 string.").to_string()
    }

    fn encode_base64(&self) -> Self::ReturnType {
        base64::encode(self)
    }
}

pub fn generate_random_bytes(size: Option<usize>) -> Vec<u8> {
    let mut rng = thread_rng();

    let size = match size {
        Some(size) => size,
        None => rng.gen_range(0..256),
    };

    rng.sample_iter(Standard).take(size).collect::<Vec<u8>>()
}

pub fn all_printable_chars() -> impl Iterator<Item = u8> {
    (32..=127_u8).chain(std::iter::once(b'\n'))
}

pub fn read_lines_from_file(file_path: &str) -> impl IntoIterator<Item = String> {
    let file = File::open(file_path).expect("Failed to open data file.");
    let reader = BufReader::new(file);

    reader.lines().flatten()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        assert_eq!([0, 0, 68].xor(1), [1, 1, 69]);

        assert_eq!([68, 68, 68].xor(1), [69, 69, 69]);
    }

    #[test]
    fn test_xor_all() {
        assert_eq!([0, 0, 68].xor_all(&[1, 1, 1]), [1, 1, 69]);

        assert_eq!([0, 0, 68].xor_all(&[1, 2, 3]), [1, 2, 71]);
    }

    #[test]
    fn test_base64_string() {
        assert_eq!("YELLOW SUBMARINE".encode_base64(), "WUVMTE9XIFNVQk1BUklORQ==");
        assert_eq!("WUVMTE9XIFNVQk1BUklORQ==".decode_base64(), "YELLOW SUBMARINE");
    }

    #[test]
    fn test_base64_bytes() {
        assert_eq!("YELLOW SUBMARINE".as_bytes().encode_base64(), "WUVMTE9XIFNVQk1BUklORQ==".to_owned().into_bytes());
        assert_eq!("WUVMTE9XIFNVQk1BUklORQ==".as_bytes().decode_base64(), "YELLOW SUBMARINE".to_owned().into_bytes());
    }
}
