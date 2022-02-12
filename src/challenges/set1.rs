#[allow(dead_code)]

/// Convert hex to base64
mod challenge1
{
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
}

/// Fixed XOR
mod challenge2
{
    use anyhow::Result;

    fn xor_hex_str(left: &str, right: &str) -> Result<String>
    {
        let iter: Vec<u8> = hex::decode(left)?
            .iter()
            .zip(hex::decode(right)?.iter())
            .map(|(r, h)| r ^ h)
            .collect();

        Ok(hex::encode(String::from_utf8_lossy(&iter).into_owned()))
    }

    #[cfg(test)]
    mod tests
    {
        use super::*;

        #[test]
        fn test_challenge()
        {
            let left = "1c0111001f010100061a024b53535009181c";
            let right = "686974207468652062756c6c277320657965";

            assert_eq!(xor_hex_str(left, right).unwrap(), "746865206b696420646f6e277420706c6179");
        }
    }
}
