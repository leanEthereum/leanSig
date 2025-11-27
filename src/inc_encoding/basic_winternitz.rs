use crate::{
    MESSAGE_LENGTH,
    symmetric::message_hash::{MessageHash, bytes_to_chunks},
};

use super::IncomparableEncoding;

/// Incomparable Encoding Scheme based on the basic Winternitz scheme, implemented from a given message hash.
/// CHUNK_SIZE must be 1, 2, 4, or 8 and MH::BASE must be 2^CHUNK_SIZE.
/// NUM_CHUNKS_CHECKSUM is the precomputed number of checksum chunks (see original Winternitz description).
pub struct WinternitzEncoding<
    MH: MessageHash,
    const CHUNK_SIZE: usize,
    const NUM_CHUNKS_CHECKSUM: usize,
> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const CHUNK_SIZE: usize, const NUM_CHUNKS_CHECKSUM: usize>
    IncomparableEncoding for WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    type Error = ();

    const DIMENSION: usize = MH::DIMENSION + NUM_CHUNKS_CHECKSUM;

    const MAX_TRIES: usize = 1;

    const BASE: usize = MH::BASE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        // apply the message hash to get chunks
        let mut chunks_message = MH::apply(parameter, epoch, randomness, message);

        // compute checksum and split into chunks in little endian
        let checksum: u64 = chunks_message
            .iter()
            .map(|&x| Self::BASE as u64 - 1 - x as u64)
            .sum();
        let checksum_bytes = checksum.to_le_bytes();
        let chunks_checksum = bytes_to_chunks(&checksum_bytes, CHUNK_SIZE);

        // append checksum chunks (truncate to the expected number)
        chunks_message.extend_from_slice(&chunks_checksum[..NUM_CHUNKS_CHECKSUM]);

        Ok(chunks_message)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            [1, 2, 4, 8].contains(&CHUNK_SIZE),
            "Winternitz Encoding: Chunk Size must be 1, 2, 4, or 8"
        );
        assert!(
            CHUNK_SIZE <= 8,
            "Winternitz Encoding: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "Winternitz Encoding: Dimension must be at most 2^8"
        );
        assert!(
            MH::BASE == Self::BASE && MH::BASE == 1 << CHUNK_SIZE,
            "Winternitz Encoding: Base and chunk size not consistent with message hash"
        );

        MH::internal_consistency_check();
    }
}
