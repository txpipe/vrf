# Verifiable Random Function

The repo contains two implementations of draft VRF preceding the ratified standard
[rfc9381](https://datatracker.ietf.org/doc/rfc9381/). Namely,
(a) implementation of the verifiable random function presented in
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2
(b) implementation of the verifiable random function presented in
[draft-irtf-cfrg-vrf-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10) using
Edwards25519, SHA512, and Elligator2.

The implementation [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) is
used as a VRF solution in haskell node, ie., [Praos](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-praos/src/Cardano/Crypto/VRF/Praos.hs).
The current implementation to be used, aka **VRF-03**, is tested against both draft standard test vectors and test vectors generated in cardano-base.
As a consequence the crate is compatible with
the **VRF-03** [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium) that is FFIed in cardano-base.

The **VRF-10** implementation is the batch-compatible
version of the VRF, as presented in this [technical spec](https://iohk.io/en/research/library/papers/on-uc-secure-range-extension-and-batch-verification-for-ecvrf/).
This version is **NOT** used in production in cardano ecosystem. Some more technical information about VRF-10 can be found [here](VRF-10.md)

It is possible that the next VRF version is going to be RFC-9381 compatible.
At the moment the next VRF version in haskell node, not at this moment used in production and not decided to be used in production, is [PraosBatchCompat](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-praos/src/Cardano/Crypto/VRF/PraosBatchCompat.hs).
It follows, although not strictly, [draft-irtf-cfrg-vrf-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13).
If the next VRF is chosen to be deployed as the next VRF the repo is going to support and be strictly compatible with it.

**DISCLAIMER**: this crate is still under active development and could be used at own risk.

## Command-Line

`vrf_dalek` comes with a command-line interface for Linux. The command-line is self explanatory by using `--help` on various commands and sub-commands.

### How to randomly generate a valid secret key (<strong>sk.prv</strong>)

```console
$ cargo run --quiet -- -g ; echo
79b589b94ba935eca61d4fb83245be1208788d329255645df3e5aab9c7deef8c
$ cargo run --quiet -- -g ; echo
d70bd72e77e4425ea46e92c85dc8f42d14afc88daf74196a1ec6225f6b1f412b
```

### How to derive a public key from a valid secret key (<strong>pk.pub</strong>)

```console
$ cargo run --quiet -- --generate ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ echo -n "a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7" | cargo run --quiet -- -d ; echo
2929eeeaa6366fd2577fd1e4e0c5bcf1729ddfd51fd6cbb7fe9840a39c7b300e

//too short secret key
$ echo "a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17" | cargo run --quiet -- --derive
failed to fill whole buffer

//reading from file also works
$ cargo run --quiet -- --generate > sk.prv
$ cat sk.prv ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ cargo run --quiet -- --derive sk.prv ; echo
2929eeeaa6366fd2577fd1e4e0c5bcf1729ddfd51fd6cbb7fe9840a39c7b300e
```
