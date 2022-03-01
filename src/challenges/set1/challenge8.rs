//! Detect AES in ECB mode
//! <https://cryptopals.com/sets/1/challenges/8>

use openssl::{symm, symm::Cipher};

use std::fs::read_to_string;



#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge8()
    {

    }
}
