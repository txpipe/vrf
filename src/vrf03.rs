//! VRF implementation following
//! [version 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03)
//! of the draft.
use curve25519_dalek_fork::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};

use super::constants::*;
use super::errors::VrfError;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::fmt::Debug;
use std::ops::Neg;
use std::{iter, ptr};

/// Byte size of the proof
pub const PROOF_SIZE: usize = 80;

/// Secret key, which is formed by `SEED_SIZE` bytes.
pub struct SecretKey03([u8; SEED_SIZE]);

impl SecretKey03 {
    /// View `SecretKey` as byte array
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert a `SecretKey` into its byte representation
    pub fn to_bytes(&self) -> [u8; SEED_SIZE] {
        self.0
    }

    /// Convert a `SecretKey` from a byte array
    pub fn from_bytes(bytes: &[u8; SEED_SIZE]) -> Self {
        SecretKey03(*bytes)
    }

    /// Given a cryptographically secure random number generator `csrng`, this function returns
    /// a random `SecretKey`
    pub fn generate<R>(csrng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut seed = [0u8; SEED_SIZE];

        csrng.fill_bytes(&mut seed);
        Self::from_bytes(&seed)
    }

    /// Given a `SecretKey`, the `extend` function hashes the secret bytes to an output of 64 bytes,
    /// and then uses the first 32 bytes to generate a secret
    /// scalar. The function returns the secret scalar and the remaining 32 bytes
    /// (named the `SecretKey` extension).
    pub fn extend(&self) -> (Scalar, [u8; 32]) {
        let mut h: Sha512 = Sha512::new();
        let mut extended = [0u8; 64];
        let mut secret_key_bytes = [0u8; 32];
        let mut extension = [0u8; 32];

        h.update(self.as_bytes());
        extended.copy_from_slice(&h.finalize().as_slice()[..64]);

        secret_key_bytes.copy_from_slice(&extended[..32]);
        extension.copy_from_slice(&extended[32..]);

        secret_key_bytes[0] &= 248;
        secret_key_bytes[31] &= 127;
        secret_key_bytes[31] |= 64;

        (Scalar::from_bits(secret_key_bytes), extension)
    }
}

impl Drop for SecretKey03 {
    #[inline(never)]
    fn drop(&mut self) {
        unsafe {
            let ptr = self.0.as_mut_ptr();
            for i in 0..SEED_SIZE {
                ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

/// VRF Public key, which is formed by an Edwards point (in compressed form).
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey03(CompressedEdwardsY);

impl Debug for PublicKey03 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}))", self.0)
    }
}

impl PublicKey03 {
    /// View the `PublicKey` as bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Convert a `PublicKey` into its byte representation.
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Generate a `PublicKey` from an array of `PUBLIC_KEY_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey03(CompressedEdwardsY::from_slice(bytes))
    }
}

impl From<&SecretKey03> for PublicKey03 {
    /// Derive a public key from a `SecretKey03`.
    fn from(sk: &SecretKey03) -> PublicKey03 {
        let (scalar, _) = sk.extend();
        let point = scalar * ED25519_BASEPOINT_POINT;
        PublicKey03(point.compress())
    }
}

/// VRF proof, which is formed by an `EdwardsPoint`, and two `Scalar`s
#[derive(Clone, Debug)]
pub struct VrfProof03 {
    gamma: EdwardsPoint,
    challenge: Scalar,
    response: Scalar,
}

impl VrfProof03 {
    /// Hash to curve function, following the 03 specification.
    // Note that in order to be compatible with the implementation over libsodium, we rely on using
    // a fork of curve25519-dalek.
    fn hash_to_curve(public_key: &PublicKey03, alpha_string: &[u8]) -> EdwardsPoint {
        let mut hash_input = Vec::with_capacity(2 + PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(SUITE);
        hash_input.extend_from_slice(ONE);
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input)
    }

    /// Nonce generation function, following the 03 specification.
    fn nonce_generation03(secret_extension: [u8; 32], compressed_h: CompressedEdwardsY) -> Scalar {
        let mut nonce_gen_input = [0u8; 64];
        let h_bytes = compressed_h.to_bytes();

        nonce_gen_input[..32].copy_from_slice(&secret_extension);
        nonce_gen_input[32..].copy_from_slice(&h_bytes);

        Scalar::hash_from_bytes::<Sha512>(&nonce_gen_input)
    }

    /// Hash points function, following the 03 specification.
    fn compute_challenge(
        compressed_h: &CompressedEdwardsY,
        gamma: &EdwardsPoint,
        announcement_1: &EdwardsPoint,
        announcement_2: &EdwardsPoint,
    ) -> Scalar {
        // we use a scalar of 16 bytes (instead of 32), but store it in 32 bits, as that is what
        // `Scalar::from_bits()` expects.
        let mut scalar_bytes = [0u8; 32];
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(SUITE);
        challenge_hash.update(TWO);
        challenge_hash.update(compressed_h.to_bytes());
        challenge_hash.update(gamma.compress().as_bytes());
        challenge_hash.update(announcement_1.compress().as_bytes());
        challenge_hash.update(announcement_2.compress().as_bytes());

        scalar_bytes[..16].copy_from_slice(&challenge_hash.finalize().as_slice()[..16]);

        Scalar::from_bits(scalar_bytes)
    }

    /// Generate a `VrfProof` from an array of bytes with the correct size. This function does not
    /// check the validity of the proof.
    pub fn from_bytes(bytes: &[u8; PROOF_SIZE]) -> Result<Self, VrfError> {
        let gamma = CompressedEdwardsY::from_slice(&bytes[..32])
            .decompress()
            .ok_or(VrfError::DecompressionFailed)?;

        let mut challenge_bytes = [0u8; 32];
        challenge_bytes[..16].copy_from_slice(&bytes[32..48]);
        let challenge = Scalar::from_bits(challenge_bytes);

        let mut response_bytes = [0u8; 32];
        response_bytes.copy_from_slice(&bytes[48..]);
        let response = Scalar::from_bytes_mod_order(response_bytes);

        Ok(Self {
            gamma,
            challenge,
            response,
        })
    }

    /// Convert the proof into its byte representation. As specified in the 03 specification, the
    /// challenge can be represented using only 16 bytes, and therefore use only the first 16
    /// bytes of the `Scalar`.
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut proof = [0u8; PROOF_SIZE];
        proof[..32].copy_from_slice(self.gamma.compress().as_bytes());
        proof[32..48].copy_from_slice(&self.challenge.to_bytes()[..16]);
        proof[48..].copy_from_slice(self.response.as_bytes());

        proof
    }

    /// `proof_to_hash` function, following the 03 specification. This computes the output of the VRF
    /// function. In particular, this function computes
    /// SHA512(SUITE || THREE || Gamma)
    pub fn proof_to_hash(&self) -> [u8; OUTPUT_SIZE] {
        let mut output = [0u8; OUTPUT_SIZE];
        let gamma_cofac = self.gamma.mul_by_cofactor();
        let mut hash = Sha512::new();
        hash.update(SUITE);
        hash.update(THREE);
        hash.update(gamma_cofac.compress().as_bytes());

        output.copy_from_slice(hash.finalize().as_slice());
        output
    }

    /// Generate a new VRF proof following the 03 standard. It proceeds as follows:
    /// - Extend the secret key, into a `secret_scalar` and the `secret_extension`
    /// - Evaluate `hash_to_curve` over PK || alpha_string to get `H`
    /// - Compute `Gamma = secret_scalar *  H`
    /// - Generate a proof of discrete logarithm equality between `PK` and `Gamma` with
    ///   bases `generator` and `H` respectively.
    pub fn generate(
        public_key: &PublicKey03,
        secret_key: &SecretKey03,
        alpha_string: &[u8],
    ) -> Self {
        let (secret_scalar, secret_extension) = secret_key.extend();

        let h = Self::hash_to_curve(public_key, alpha_string);
        let compressed_h = h.compress();
        let gamma = secret_scalar * h;

        // Now we generate the nonce
        let k = Self::nonce_generation03(secret_extension, compressed_h);

        let announcement_base = k * ED25519_BASEPOINT_POINT;
        let announcement_h = k * h;

        // Now we compute the challenge
        let challenge =
            Self::compute_challenge(&compressed_h, &gamma, &announcement_base, &announcement_h);

        // And finally the response of the sigma protocol
        let response = k + challenge * secret_scalar;
        Self {
            gamma,
            challenge,
            response,
        }
    }

    /// Verify VRF function, following the 03 specification.
    pub fn verify(
        &self,
        public_key: &PublicKey03,
        alpha_string: &[u8],
    ) -> Result<[u8; OUTPUT_SIZE], VrfError> {
        let h = Self::hash_to_curve(public_key, alpha_string);
        let compressed_h = h.compress();

        let decompressed_pk = public_key
            .0
            .decompress()
            .ok_or(VrfError::DecompressionFailed)?;

        if decompressed_pk.is_small_order() {
            return Err(VrfError::PkSmallOrder);
        }

        let U = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &self.challenge.neg(),
            &decompressed_pk,
            &self.response,
        );
        let V = EdwardsPoint::vartime_multiscalar_mul(
            iter::once(self.response).chain(iter::once(self.challenge.neg())),
            iter::once(h).chain(iter::once(self.gamma)),
        );

        // Now we compute the challenge
        let challenge = Self::compute_challenge(&compressed_h, &self.gamma, &U, &V);

        if challenge.to_bytes()[..16] == self.challenge.to_bytes()[..16] {
            Ok(self.proof_to_hash())
        } else {
            Err(VrfError::VerificationFailed)
        }
    }
}
