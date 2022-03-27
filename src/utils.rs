use rand::{thread_rng, Rng};
use rand::distributions::Standard;


pub trait UnicodeToString
{
    fn to_string(&self) -> String;
}


impl UnicodeToString for [u8]
{
    fn to_string(&self) -> String
    {
        String::from_utf8_lossy(self).to_string()
    }
}


pub fn generate_random_bytes(size: usize) -> Vec<u8>
{
    thread_rng().sample_iter(Standard)
        .take(size)
        .collect::<Vec<u8>>()
}
