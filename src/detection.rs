use itertools::Itertools;


pub trait DetectReps
{
    fn detect_repetitions(&self, block_size: usize) -> bool;
}


impl DetectReps for [u8]
{
    fn detect_repetitions(&self, block_size: usize) -> bool
    {
        let unique_chunks = self
            .chunks(block_size)
            .unique();

        self.chunks(block_size).ne(unique_chunks)
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_detect_repetitions()
    {
        let input = "hejhej".as_bytes();
        assert!(input.detect_repetitions(3));

        let input = "hejheh".as_bytes();
        assert!(!input.detect_repetitions(3));
    }
}