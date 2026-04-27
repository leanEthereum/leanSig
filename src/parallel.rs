#[cfg(feature = "parallel-rayon")]
use rayon::prelude::*;

pub(crate) fn map_range<T, F>(range: std::ops::Range<usize>, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync + Send,
{
    #[cfg(feature = "parallel-rayon")]
    {
        range.into_par_iter().map(f).collect()
    }

    #[cfg(not(feature = "parallel-rayon"))]
    {
        range.map(f).collect()
    }
}

pub(crate) fn map_chunks_exact<T, U, F>(items: &[T], chunk_size: usize, f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(usize, &[T]) -> U + Sync + Send,
{
    assert!(chunk_size > 0, "chunk_size must be non-zero");
    assert!(
        items.len().is_multiple_of(chunk_size),
        "items length must be divisible by chunk_size"
    );

    #[cfg(feature = "parallel-rayon")]
    {
        items
            .par_chunks_exact(chunk_size)
            .enumerate()
            .map(|(index, chunk)| f(index, chunk))
            .collect()
    }

    #[cfg(not(feature = "parallel-rayon"))]
    {
        items
            .chunks_exact(chunk_size)
            .enumerate()
            .map(|(index, chunk)| f(index, chunk))
            .collect()
    }
}

pub(crate) fn for_each_zipped_chunks_exact_mut<A, B, F>(
    left: &mut [A],
    left_chunk_size: usize,
    right: &[B],
    right_chunk_size: usize,
    f: F,
) where
    A: Send,
    B: Sync,
    F: Fn(usize, &mut [A], &[B]) + Sync + Send,
{
    assert!(left_chunk_size > 0, "left_chunk_size must be non-zero");
    assert!(right_chunk_size > 0, "right_chunk_size must be non-zero");
    assert!(
        left.len().is_multiple_of(left_chunk_size),
        "left length must be divisible by left_chunk_size"
    );
    assert!(
        right.len().is_multiple_of(right_chunk_size),
        "right length must be divisible by right_chunk_size"
    );
    assert_eq!(
        left.len() / left_chunk_size,
        right.len() / right_chunk_size,
        "left/right chunk counts must match"
    );

    #[cfg(feature = "parallel-rayon")]
    {
        left.par_chunks_exact_mut(left_chunk_size)
            .zip(right.par_chunks_exact(right_chunk_size))
            .enumerate()
            .for_each(|(index, (left_chunk, right_chunk))| f(index, left_chunk, right_chunk));
    }

    #[cfg(not(feature = "parallel-rayon"))]
    {
        for (index, (left_chunk, right_chunk)) in left
            .chunks_exact_mut(left_chunk_size)
            .zip(right.chunks_exact(right_chunk_size))
            .enumerate()
        {
            f(index, left_chunk, right_chunk);
        }
    }
}
