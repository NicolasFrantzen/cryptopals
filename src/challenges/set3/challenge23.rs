//! Clone an MT19937 RNG from its output
//! <https://cryptopals.com/sets/3/challenges/23>

use crate::mersenne_twister::{MT19937_64, U, D, S, B, T, C, L, N};

fn temper(y: u64) -> u64 {
    let mut y = y;
    y ^= (y >> U) & D;
    y ^= (y << S) & B;
    y ^= (y << T) & C;
    y ^= y >> L;

    y
}

fn inv_rs(u: u64, k: u64) -> u64 {
    assert!(k >= 1);
    let mut u = u;
    let mut v = u;

    for _ in 0..=64 / k {
        u >>= k;
        v ^= u
    }
    v
}

fn inv_lsa(u: u64, k: u64, c: u64) -> u64 {
    assert!(k >= 1);
    let mut v = u;

    for _ in 0..64 / k {
        v = u ^ (v << k & c);
    }
    v
}

fn inv_lsa2(u: u64, k: u64, c: u64) -> u64 {
    assert!(k >= 1);
    let mut v = u;

    for _ in 0..64 / k {
        v = u ^ (v >> k & c);
    }
    v
}

fn untemper(y: u64) -> u64 {
    inv_lsa2(inv_lsa(inv_lsa(inv_rs(y, L), T, C), S, B), U, D)
}

fn get_state(mt: &mut MT19937_64) -> [u64; N] {
    let mut state: [u64; N] = [0; N];

    state.iter_mut().for_each(|s| *s = (*mt).next_u64());

    state
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge23_untemper() {
        assert_eq!(14514284786278117030, temper(untemper(14514284786278117030)));
    }

    #[test]
    fn test_challenge23_splice() {
        let mut mt = MT19937_64::new();
        let state = get_state(&mut mt);

        let mut mt_cloned = MT19937_64::new_with_state(state);

        for _ in 0..N-1 {
            assert_ne!(mt_cloned.next_u64(), mt.next_u64());
        }
    }
}
