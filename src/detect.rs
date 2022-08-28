use itertools::Itertools;

pub trait DetectReps {
    fn detect_repetitions(&self, block_size: usize) -> bool;
    fn detect_consecutive_repetitions(
        &self,
        block_size: usize,
        repetitions: usize,
    ) -> Option<usize>;
}

impl DetectReps for [u8] {
    fn detect_repetitions(&self, block_size: usize) -> bool {
        let unique_chunks = self.chunks(block_size).unique();

        self.chunks(block_size).ne(unique_chunks)
    }

    /// Detects consecutive blocks of `block_size` with count `repetitions`. Returns index for first the first repeated item.
    fn detect_consecutive_repetitions(
        &self,
        block_size: usize,
        repetitions: usize,
    ) -> Option<usize> {
        let mut chunks_rep_count = self.chunks(block_size).dedup_with_count();

        if let Some(item) = chunks_rep_count.find(|x| x.0 == repetitions) {
            let position_of_repeated = self.chunks(block_size).position(|x| x == item.1);
            if let Some(position_of_repeated) = position_of_repeated {
                return Some(position_of_repeated * block_size);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_repetitions() {
        let input = "hejhej".as_bytes();
        assert!(input.detect_repetitions(3));

        let input = "hejheh".as_bytes();
        assert!(!input.detect_repetitions(3));
    }
}
