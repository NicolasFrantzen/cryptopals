//! Implementation of MT19937 algorithm
//! https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode

use rand_core::SeedableRng;

pub(crate) const DEFAULT_SEED: u64 = 5489;

// Constants for MT19937-64
pub(crate) const W: u64 = 64;
pub(crate) const N: usize = 312;
pub(crate) const M: usize = 156;
pub(crate) const R: u64 = 31;
pub(crate) const A: u64 = 0xB502_6F5A_A966_19E9;
pub(crate) const U: u64 = 29;
pub(crate) const D: u64 = 0x5555_5555_5555_5555;
pub(crate) const S: u64 = 17;
pub(crate) const B: u64 = 0x71D6_7FFF_EDA6_0000;
pub(crate) const T: u64 = 37;
pub(crate) const C: u64 = 0xFFF7_EEE0_0000_0000;
pub(crate) const L: u64 = 43;
pub(crate) const F: u128 = 6364136223846793005;

const LOWEST_W_MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF;
const LOWER_MASK: u64 = (1 << R) - 1; // The binary number of r 1's
const UPPER_MASK: u64 = ((!LOWER_MASK as u128) & LOWEST_W_MASK) as u64; // lowest W bits of LOWER_MASK

pub struct MT19937_64
{
    mt: [u64; N],
    index: usize,
}

impl MT19937_64 {
    pub fn new() -> Self {
        Self::new_with_state([0; N])
    }

    pub fn new_with_state(mt: [u64; N]) -> Self {
        Self {
            mt,
            index: N+1,
        }
    }

    pub fn from_seed(seed: u64) -> Self {
        let mut mt = Self::new();
        mt.seed_mt(seed);

        mt
    }

    fn twist(&mut self) {
        for i in 0..N-1 {
            let x = (self.mt[i] & UPPER_MASK)
                | (self.mt[(i + 1) % N] & LOWER_MASK);

            let mut x_a = x >> 1;

            if x % 2 != 0 {
                x_a ^= A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ x_a;
        }

        self.index = 0;
    }

    fn seed_mt(&mut self, seed: u64) {
        self.index = N;
        self.mt[0] = seed;

        for i in 1..N-1 {
            self.mt[i] = (LOWEST_W_MASK &
                (
                    (F * (self.mt[i-1] ^ (self.mt[i-1] >> (W - 2))) as u128) + (i as u128)
                )) as u64;
        }
    }

    fn extract_number(&mut self) -> u64 {
        debug_assert!(self.index != 0);

        if self.index >= N {
            if self.index > N {
                self.seed_mt(DEFAULT_SEED);
            }

            self.twist();
        }

        let mut y: u64 = self.mt[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;

        y // & LOWEST_W_MASK
    }

    pub fn next_u64(&mut self) -> u64 {
        self.extract_number()
    }
}

impl SeedableRng for MT19937_64 {
    type Seed = [u8; 8];
    fn from_seed(seed: Self::Seed) -> Self {
        Self::from_seed(u64::from_le_bytes(seed))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_64() {
        let seed = DEFAULT_SEED;
        let mut rng = MT19937_64::from_seed(seed);

        // values are taked from C++ std::mt19937_64 in <random>
        const CPP_NUMS: [u64; 20] = [14514284786278117030, 4620546740167642908, 13109570281517897720, 17462938647148434322,
            355488278567739596, 7469126240319926998, 4635995468481642529, 418970542659199878, 9604170989252516556,
            6358044926049913402, 5058016125798318033, 10349215569089701407, 2583272014892537200, 10032373690199166667,
            9627645531742285868, 15810285301089087632, 9219209713614924562, 7736011505917826031, 13729552270962724157,
            4596340717661012313];

        CPP_NUMS.iter().for_each(|&i| {
            assert_eq!(rng.next_u64(), i);
        });
    }
}