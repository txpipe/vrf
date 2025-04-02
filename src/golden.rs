//! Golden test reusable data
use serde::{Deserialize, Deserializer};

/// Location of test vectors
pub static CARDANO_BASE_TEST_VECTORS: [&'static str; 7] = [
    "./tests/test_vectors/vrf_ver03_generated_1",
    "./tests/test_vectors/vrf_ver03_generated_2",
    "./tests/test_vectors/vrf_ver03_generated_3",
    "./tests/test_vectors/vrf_ver03_generated_4",
    "./tests/test_vectors/vrf_ver03_standard_10",
    "./tests/test_vectors/vrf_ver03_standard_11",
    "./tests/test_vectors/vrf_ver03_standard_12",
];

/// Expected golden test data structure of each golden test file
#[derive(PartialEq, Debug, Clone, Deserialize)]
pub struct GoldenTestVector {
    /// VRF version name, like Praos
    #[serde(alias = "vrf")]
    pub vrf_name: String,

    /// draft version
    #[serde(alias = "ver")]
    pub standard_version: String,

    /// `cipher_suite` of `ECVRF-ED25519-SHA512-Elligator2`
    #[serde(alias = "ciphersuite")]
    pub cipher_suite: String,

    /// Secret key used
    #[serde(deserialize_with = "deserialize_hex", alias = "sk")]
    pub secret_key: Vec<u8>,

    /// Public key derived from the secret key
    #[serde(deserialize_with = "deserialize_hex", alias = "pk")]
    pub public_key: Vec<u8>,

    /// Message being the input
    #[serde(deserialize_with = "deserialize_hex", alias = "alpha")]
    pub message: Vec<u8>,

    #[serde(deserialize_with = "deserialize_hex", alias = "pi")]
    /// Proof calculated based on the message and the secret key
    pub proof_expected: Vec<u8>,

    #[serde(deserialize_with = "deserialize_hex", alias = "beta")]
    /// Hash calculated based on the message and the secret key
    pub output_expected: Vec<u8>,
}

fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <String>::deserialize(deserializer)?;
    let bytes = hex::decode(buf).map_err(serde::de::Error::custom)?;
    Ok(bytes)
}
