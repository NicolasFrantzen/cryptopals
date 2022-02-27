//! Implement repeating-key XOR
//! <https://cryptopals.com/sets/1/challenges/5>

use anyhow::Result;

pub struct RepeatingKeyXor;
impl RepeatingKeyXor
{
    pub fn encrypt(plaintext: &str, key: &str) -> String
    {
        hex::encode(Self::xor_bytes(plaintext.as_bytes(), key))
    }

    /*fn decrypt(cipher: &str, key: &str) -> Result<String>
    {
        let bytes = hex::decode(cipher)?;
        let xored_bytes = Self::xor_bytes(bytes, key);

        String::from_utf8_lossy().into_owned()
    }*/

    pub fn xor_bytes(buffer: &[u8], key: &str) -> Vec<u8>
    {
        let num_repeat_to_fit: usize = (buffer.len() as f32 / key.len() as f32).ceil() as usize;
        let repeated_key = key.repeat(num_repeat_to_fit);

        buffer.into_iter()
            .zip(repeated_key.bytes().into_iter())
            .map(|(r, h)| r ^ h)
            .collect::<Vec<_>>()
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    use indoc::indoc;

    #[test]
    fn test_challenge5()
    {

        let plaintext = indoc! {"
            Burning 'em, if you ain't quick and nimble
            I go crazy when I hear a cymbal"};

        let cipher = indoc! {"
            0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"};

        assert_eq!(RepeatingKeyXor::encrypt(plaintext, "ICE"), cipher.replace('\n', ""));

        println!("{plaintext}");
        println!("{cipher}");
    }
}
