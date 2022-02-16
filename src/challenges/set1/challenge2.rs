/// Fixed XOR
/// https://cryptopals.com/sets/1/challenges/2

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
