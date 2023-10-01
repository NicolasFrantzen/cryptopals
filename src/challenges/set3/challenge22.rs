//! Crack an MT19937 seed
//! <https://cryptopals.com/sets/3/challenges/22>

use crate::random::MT19937_64;

use std::{thread, time::{Duration, SystemTime}};
use rand::{thread_rng, Rng};

fn get_random_int() -> u64 {
    let mut rng = thread_rng();
    thread::sleep(Duration::from_secs(rng.gen_range(40..1000)));

    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let mut mt1 = MT19937_64::from_seed(seed);

    thread::sleep(Duration::from_secs(rng.gen_range(40..1000)));

    mt1.next_u64()
}

fn exploit() -> Option<u64> {
    let random_int = get_random_int();

    let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

    ((current_time-2000)..current_time).find(|&seed| MT19937_64::from_seed(seed).next_u64() == random_int)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_challenge22() {
        let exploited_seed = exploit();
        assert!(exploited_seed.is_some());
        println!("Exploited seed: {}", &exploited_seed.unwrap());
    }
}
