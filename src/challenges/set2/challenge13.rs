//! ECB cut-and-paste
//! <https://cryptopals.com/sets/1/challenges/13>

use crate::aes::{AesEncryption, Aes128Ecb, AES_BLOCK_SIZE};
use crate::padding::Pkcs7Padding;
use crate::utils::UnicodeUtils;

use serde_qs as qs;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Error, bail};


#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Profile
{
    email: String,
    uid: u32,
    role: String,
}


impl Profile
{
    fn new(email: &str, uid: u32, role: &str) -> Self
    {
        Self {
            email: email.to_string(),
            uid,
            role: role.to_string(),
        }
    }

    pub fn profile_for(email: &str) -> Result<Self>
    {
        if email.contains('=') || email.contains('&')
        {
            bail!("Invalid character detected!");
        }

        Ok(Self::new(email, 10, "user"))
    }

    pub fn encrypt(&self, key: &[u8]) -> Vec<u8>
    {
        let profile_str = String::try_from(self).expect("Invalid profile");

        Aes128Ecb::encrypt(&profile_str.as_bytes().with_padding(AES_BLOCK_SIZE), key)
    }

    pub fn decrypt(cipher_buffer: &[u8], key: &[u8]) -> Result<Self>
    {
        let profile_str = Aes128Ecb::decrypt(cipher_buffer, key)
            .without_padding()
            .to_string();

        println!("{:?}", profile_str);

        Profile::try_from(profile_str.as_str())
    }
}


impl TryFrom<&str> for Profile
{
    type Error = Error;

    fn try_from(from_str: &str) -> Result<Self>
    {
        let profile: Profile = qs::from_str(from_str)?;

        Ok(profile)
    }
}


impl TryFrom<&Profile> for String
{
    type Error = Error;

    fn try_from(profile: &Profile) -> Result<String>
    {
        let profile_str = qs::to_string(profile)?
            // Apparently unicode characters are converted in serde, hack some back
            .replace("%40", "@")
            .replace("%04", "\u{4}");

        Ok(profile_str)
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_challenge13_from()
    {
        let profile_object = Profile::profile_for("foo@bar.com").unwrap();
        let profile_qs = Profile::try_from("email=foo@bar.com&uid=10&role=user").unwrap();

        assert_eq!(profile_object, profile_qs);
    }

    #[test]
    fn test_challenge13_invalid_email()
    {
        let profile = Profile::profile_for("foo@bar.com&role=admin");
        assert!(profile.is_err());

        let profile = Profile::profile_for("foo@bar.com&");
        assert!(profile.is_err());

        let profile = Profile::profile_for("foo@bar.com=");
        assert!(profile.is_err());
    }

    #[test]
    fn test_challenge13_into()
    {
        let profile_object = Profile::profile_for("foo@bar.com").unwrap();
        let profile_qs = String::try_from(&profile_object).unwrap(); //profile_object.try_into().unwrap();

        assert_eq!(profile_qs, "email=foo@bar.com&uid=10&role=user");
    }

    #[test]
    fn test_challenge13_ecb()
    {
        let profile_object = Profile::profile_for("foo@bar.com").unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();
        let profile_encrypted = profile_object.encrypt(key);

        assert_eq!(profile_object, Profile::decrypt(&profile_encrypted, key).unwrap());
    }

    #[test]
    fn test_challenge13_admin()
    {
        let key = "YELLOW SUBMARINE".as_bytes();

        // We first create a normal user profile
        // |"email=aafoo@bar."|"com&uid=10&role="|"user\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"|
        let user_profile = Profile::profile_for("aafoo@bar.com").unwrap().encrypt(key);

        // We then create a malicious profile with admin injected and align it with the "role" block
        // |"email=AAAAAAAAAA"|"AAAAAAAAAAAAAAAA"|"admin\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"|"@bar.com&uid=10&"|"role=user\x04\x04\x04\x04\x04\x04\x04"|
        let admin = "admin".with_padding(16);
        let email = "A".repeat(26) + &admin + "@bar.com";
        let malicious_profile = Profile::profile_for(&email).unwrap().encrypt(key);

        // Then cut and paste, we take the first two blocks |"email=aafoo@bar."|"com&uid=10&role="|
        let mut admin_profile = user_profile[..32].to_owned();

        // Paste with |"admin\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"|
        admin_profile.extend_from_slice(&malicious_profile[32..48]);

        // Finalize with last encryption block
        admin_profile.extend_from_slice(&malicious_profile[80..]);

        let admin_profile_decrypted = Profile::decrypt(&admin_profile, key).unwrap();

        println!("Decrypted: {:?}", admin_profile_decrypted);
        assert_eq!(admin_profile_decrypted, Profile::new("aafoo@bar.com", 10, "admin"));
    }
}
