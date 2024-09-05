use alloy_primitives::U256;
use ark_bn254::Fq as F;
use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, BigInteger256};
use ark_ff::{Field, One, PrimeField};
use std::ops::Neg;

pub fn map_to_curve(digest: &[u8; 32]) -> G1Projective {
    let one = F::one();
    let three = F::from(3u64);
    let mut x = F::from_be_bytes_mod_order(digest.as_slice());

    loop {
        let x_cubed = x.pow([3]);
        let y = x_cubed + three;

        if y.legendre().is_qr() {
            let y = y.sqrt().unwrap();
            let point = G1Affine::new(x, y);

            if point.is_on_curve() {
                return G1Projective::new(point.x, point.y, F::one());
            }
        }

        x += one;
    }
}

/// Helper for converting a PrimeField to its U256 representation for Ethereum compatibility
pub fn u256_to_point<F: PrimeField>(point: U256) -> F {
    let le: [u8; 32] = point.to_le_bytes();
    F::from_le_bytes_mod_order(&le[..])
}

/// Helper for converting a PrimeField to its U256 representation for Ethereum compatibility
/// (U256 reads data as big endian)
pub fn point_to_u256<F: PrimeField>(point: F) -> U256 {
    let point = point.into_bigint();
    let point_bytes = point.to_bytes_be();
    U256::from_be_slice(&point_bytes[..])
}

/// Converts [U256] to [BigInteger256]
pub fn u256_to_bigint256(value: U256) -> BigInteger256 {
    // Convert U256 to a big-endian byte array
    let bytes: [u8; 32] = value.to_be_bytes();

    // BigInteger256 expects a 4-element array of 64-bit values in little-endian order
    let mut data = [0u64; 4];

    // Iterate over the bytes in chunks of 8 bytes and convert to u64
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut chunk_array = [0u8; 8];
        chunk_array.copy_from_slice(chunk);
        data[3 - i] = u64::from_be_bytes(chunk_array);
    }

    BigInteger256::new(data)
}

pub fn biginteger256_to_u256(bi: BigInteger256) -> U256 {
    let s = bi.to_bytes_be();
    U256::from_be_slice(&s)
}

pub fn get_g1_generator() -> G1Affine {
    G1Affine::new(ark_bn254::g1::G1_GENERATOR_X, ark_bn254::g1::G1_GENERATOR_Y)
}

pub fn get_g2_generator() -> G2Affine {
    G2Affine::new(ark_bn254::g2::G2_GENERATOR_X, ark_bn254::g2::G2_GENERATOR_Y)
}

pub fn get_g2_generator_neg() -> G2Affine {
    let g2_gen = get_g2_generator();
    g2_gen.neg()
}

pub fn mul_by_generator_g1(pvt_key: Fr) -> G1Projective {
    let g1_gen = get_g1_generator();
    g1_gen.mul_bigint(pvt_key.0)
}

pub fn mul_by_generator_g2(pvt_key: Fr) -> G2Projective {
    let g2_gen = get_g2_generator();
    g2_gen.mul_bigint(pvt_key.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_u256_to_bigint256() {
        let u256 = U256::from(123456789);
        let result = u256_to_bigint256(u256);
        assert_eq!(result, BigInteger256::from(123456789u32));
    }

    #[tokio::test]
    async fn test_bigint256_to_u256() {
        let bi = BigInteger256::from(123456789u32);
        let result = biginteger256_to_u256(bi);
        assert_eq!(result, U256::from(123456789));
    }
}
