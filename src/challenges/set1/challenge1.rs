/// Convert hex to base64
/// https://cryptopals.com/sets/1/challenges/1

use anyhow::Result;

fn hex_to_base64(arg: &str) -> Result<String>
{
    let hex = hex::decode(arg)?;
    Ok(base64::encode(hex))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge()
    {
        // "I'm killing your brain like a poisonous mushroom"
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_base64(hex_str).unwrap(), base64_str);
    }
}
