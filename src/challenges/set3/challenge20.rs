//! Break fixed-nonce CTR statistically
//! <https://cryptopals.com/sets/3/challenges/20>

use crate::aes::{CtrCounter, AES_BLOCK_SIZE};
use crate::utils::UnicodeUtils;

#[derive(PartialEq, Debug)]
struct PlainText(Vec<u8>);

/// XOR with keystream
/// `CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE`
/// So that,
/// `CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE`
fn xor_with_keystream(cipher_buffer: &[u8]) -> PlainText
{
    let keystream = CtrCounter::new(0);
    let plaintext = cipher_buffer
        .chunks(AES_BLOCK_SIZE)
        .zip(keystream.iter())
        .flat_map(|(x, y)| x.xor_all(&y))
        .collect::<Vec<_>>();

    PlainText(plaintext)
}


#[cfg(test)]
mod tests {
    use crate::utils::{Base64, generate_random_bytes, read_lines_from_file};
    use crate::aes::{Aes128, AES_BLOCK_SIZE};

    use crate::challenges::set1::challenge3::{FrequencyScorer};
    use crate::challenges::set1::challenge6::RepeatingKeyXorBreaker;

    use super::*;

    #[test]
    fn test_challenge20_xor_with_keystream() {

        let xored_key_stream = xor_with_keystream(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(xored_key_stream, PlainText([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1].to_vec()));
    }

    #[test]
    fn test_challenge20() {
        let key = generate_random_bytes(Some(AES_BLOCK_SIZE));
        let lines = read_lines_from_file("data/20.txt");

        let encrypted_bytes_vec = lines
             .into_iter()
             .map(|s| s.decode_base64())
             .inspect(|x| println!("{:?}", x))
             .map(|s| s
                 .into_bytes()
                 .encrypt_aes_128_ctr(&key))
             .collect::<Vec<_>>();

        // Debug
        encrypted_bytes_vec.iter().for_each(|l| {
            println!("{:?}", l);
        });

        let min_len = encrypted_bytes_vec
            .iter()
            .map(|x| x.len())
            .min()
            .unwrap();

        println!("Min length: {:?}", min_len);

        let concatenated_ciphers = encrypted_bytes_vec
            .iter()
            .map(|x| xor_with_keystream(&x))
            //.inspect(|PlainText(x)| println!("HEJ: {:?}", x.len()))
            .flat_map(|x| (&x.0[..min_len]).to_vec())
            .collect::<Vec<u8>>();

        let breaker = RepeatingKeyXorBreaker::<FrequencyScorer>::new(&concatenated_ciphers); // TODO: Break with size specified?

        println!("WAT: {:?}", concatenated_ciphers.len());
        let key_break = breaker.break_it();

        println!("Decipher: {:?}", key_break);

        //println!("{:?}", concatenated_ciphers.encrypt_aes_128_ctr(&key_break));
    }
}
