//! Implementation of MT19937 algorithm
//! https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode

pub const DEFAULT_SEED: u64 = 5489;

// Constants for MT19937-64
const W: u64 = 64;
const N: usize = 312;
const M: u64 = 156;
const R: u64 = 31;
const A: u64 = 0xB502_6F5A_A966_19E9;
const U: u64 = 29;
const D: u64 = 0x5555_5555_5555_5555;
const S: u64 = 17;
const B: u64 = 0x71D6_7FFF_EDA6_0000;
const T: u64 = 37;
const C: u64 = 0xFFF7_EEE0_0000_0000;
const L: u64 = 43;
const F: u128 = 6364136223846793005;

const LOWEST_W_MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF;
const LOWER_MASK: u64 = (1 << R) - 1; // The binary number of r 1's
const UPPER_MASK: u64 = (LOWER_MASK as u128 & LOWEST_W_MASK) as u64; // lowest W bits of LOWER_MASK


pub trait RandomNumberGenerator {
    type ReturnType;
    fn seed(&self, seed: usize);
    fn rand(&self) -> Self::ReturnType;
}

pub struct MT19937_64
{
    mt: [u64; N],
    index: usize,
}

impl MT19937_64 {
    fn new() -> Self
    {
        Self {
            mt: [0; N],
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
                | (self.mt[(i+1) % N] & LOWER_MASK);

            let mut x_a = x >> 1;

            if x % 2 != 0 {
                x_a ^= A;
            }
            self.mt[i] = self.mt[(i + (M as usize)) % N] ^ x_a;
        }

        self.index = 0;
    }

    fn seed_mt(&mut self, seed: u64) {
        self.index = N;
        self.mt[0] = seed;

        (1..N-1).for_each(|i| {
            self.mt[i] = (LOWEST_W_MASK as u128 & (F * (self.mt[i-1] as u128 ^ (self.mt[i-1] as u128 >> (W - 2))))) as u64;
        });
    }

    fn extract_number(&mut self) -> u64 {
        if self.index >= N {
            if self.index > N {
                self.seed_mt(DEFAULT_SEED);
            }

            self.twist();
        }

        let mut y: u64 = self.mt[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        self.index += 1;

        (y as u128 & LOWEST_W_MASK) as u64
    }

    pub fn next_u64(&mut self) -> u64 {
        self.extract_number()
    }
}

impl RandomNumberGenerator for MT19937_64 {
    type ReturnType = u64;

    fn rand(&self) -> Self::ReturnType {
        todo!()
    }

    fn seed(&self, _seed: usize) {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand_mt::Mt64;

    #[ignore]
    #[test]
    fn test_compare() {
        let seed = DEFAULT_SEED;
        let mut a = Mt64::new(seed);

        let mut b = MT19937_64::from_seed(seed);

        a.next_u64();
        b.next_u64();

        assert_eq!(a.next_u64(), b.next_u64());
    }
}