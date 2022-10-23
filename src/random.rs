//! Implementation of MT19937 algorithm
//! https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode

const W: usize = 64;
const N: usize = 312;
const M: usize = 156;
const R: usize = 31;

const F: usize = 6364136223846793005;

const LOWEST_W_MASK: usize = 0xffff_ffff_ffff_ffff;
const LOWER_MASK: usize = (1 << R) - 1; // The binary number of r 1's
const UPPER_MASK: usize = LOWER_MASK & LOWEST_W_MASK; // lowest W bits of LOWER_MASK

type Int = u64;

pub trait RandomNumberGenerator {
    type ReturnType;
    fn seed(&self, seed: Int);
    fn rand(&self) -> Self::ReturnType;
}

struct MT19937
{
    mt: [Int; N],
    index: usize,
}

impl MT19937 {
    pub fn new() -> Self
    {
        Self {
            mt: [0; N],
            index: N+1,
        }
    }

    fn twist(&self) {
        todo!()
    }

    fn seed_mt(&mut self, seed: Int) {
        self.index = N;
        self.mt[0] = seed;

        // TODO: Could this be written as iter_mut?
        (1..N-1).for_each(|i| {
            self.mt[i] = (LOWEST_W_MASK as u64 & (F as u64 * (self.mt[i-1] ^ (self.mt[i-1] >> (W as Int - 2))))) as Int;
        });
    }

    fn extract_number(&self) -> Int {
        todo!()
    }
}

impl RandomNumberGenerator for MT19937 {
    type ReturnType = Int; // FIX?

    fn rand(&self) -> Self::ReturnType {
        todo!()
    }

    fn seed(&self, _seed: Int) {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_with() {

    }
}