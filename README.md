# Verifiable Random Function

The repo contains two implementations of draft VRF preceding the ratified standard
[rfc9381](https://datatracker.ietf.org/doc/rfc9381/).
(a) implementation of the verifiable random function presented in
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2
(b) implementation of the verifiable random function presented in
[draft-irtf-cfrg-vrf-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10) using
Edwards25519, SHA512, and Elligator2.

The implementation [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) implementation is
used as a VRF in haskell node, ie., [Praos](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-praos/src/Cardano/Crypto/VRF/Praos.hs).
The current implementation to be used, aka **VRF-03** is tested against both draft standard test vectors and test vectors generated in cardano-base.
As a consequence the crate is compatible with
the **VRF-03** [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium) that is FFIed in cardano-base.

The **VRF-10** implementation is the batch-compatible
version of the VRF, as presented in this [technical spec](https://iohk.io/en/research/library/papers/on-uc-secure-range-extension-and-batch-verification-for-ecvrf/).
This version is **NOT** used in production. It is possible to the next VRF version is going to be RFC-9381 compatible. In that case
the repo is going to support it. Some more technical information about VRF-10 can be found [here](VRF-03.md)

**DISCLAIMER**: this crate is still under active development and could be used at own risk.
