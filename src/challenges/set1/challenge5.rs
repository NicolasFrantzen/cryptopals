//! Implement repeating-key XOR
//! <https://cryptopals.com/sets/1/challenges/5>


struct RepeatingKeyXor;
impl RepeatingKeyXor
{
    fn encrypt(plaintext: &str, key: &str) -> String
    {
        let num_repeat_to_fit: usize = (plaintext.len() as f32 / key.len() as f32).ceil() as usize;
        let repeated_key = key.repeat(num_repeat_to_fit);

        let encrypted_bytes: Vec<u8> = plaintext.bytes()
            .into_iter()
            .zip(repeated_key.bytes().into_iter())
            .map(|(r, h)| r ^ h)
            .collect();

        hex::encode(encrypted_bytes)
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
