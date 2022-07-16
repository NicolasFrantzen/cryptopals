//! Implement CTR, the stream cipher mode
//! <https://cryptopals.com/sets/3/challenges/18>



#[cfg(test)]
mod tests
{
    use crate::aes::{Aes128Ctr, CtrCounter};

    use super::*;

    #[ignore]
    #[test]
    fn test_challenge18()
    {
        const CIPHER_TEXT: &'static str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

        let counter = CtrCounter::new("YELLOW SUBMARINE".as_bytes());
        let plain_text = Aes128Ctr::decrypt_with_counter(CIPHER_TEXT.as_bytes(), counter);

        assert_eq!(plain_text, "HEJ".as_bytes());
    }
}
