//! Implement CTR, the stream cipher mode
//! <https://cryptopals.com/sets/3/challenges/18>


#[cfg(test)]
mod tests
{
    use crate::aes::{Aes128Ctr, AesEncryption};

    #[test]
    fn test_challenge18()
    {
        let cipher_text = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let plain_text = Aes128Ctr::decrypt(&base64::decode(cipher_text).unwrap(), "YELLOW SUBMARINE".as_bytes(), None);

        assert_eq!(plain_text, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_bytes());
    }
}
