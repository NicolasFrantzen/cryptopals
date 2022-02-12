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


mod challenge3
{
    use anyhow::Result;

    fn decipher(cipher: &str, key: &char) -> Result<String>
    {
        let mut key_arr = [0, 1];
        key.encode_utf8(&mut key_arr);
        let key = key_arr[0];

        let iter: Vec<u8> = hex::decode(cipher)?
            .iter()
            .map(|c| c ^ key )
            .collect();

            Ok(String::from_utf8_lossy(&iter).into_owned())
    }


    #[cfg(test)]
    mod tests
    {
        use super::*;

        const SECRET: &str = "Cooking MC's like a pound of bacon";

        fn break_cipher(cipher: &str) -> Option<char>
        {
            for c in 'A'..='Z'
            {
                match decipher(cipher, &c) {
                    Ok(deciphered) if deciphered == SECRET => { return Some(c) },
                    Ok(_) => (),
                    Err(_) => (),
                }
            }

            None
        }

        #[test]
        fn test_challenge()
        {
            let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            assert_eq!(break_cipher(cipher), Some('X'));
        }
    }
}
