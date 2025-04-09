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

//reading the secret key from file also works
$ cargo run --quiet -- --generate > sk.prv
$ cat sk.prv ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ cargo run --quiet -- --derive sk.prv ; echo
2929eeeaa6366fd2577fd1e4e0c5bcf1729ddfd51fd6cbb7fe9840a39c7b300e
```

### How to create a proof for stdin message using a valid secret key (<strong>proof</strong>)

```console
$ cat sk.prv ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ echo "msg" | cargo run --quiet -- -p sk.prv ; echo
e654752ea43ba215e37ab17fdd99d678bd4844266cb0a944afa4e6878790a43bc4b3adced6fec2df3b55ac97c3e827e5d1d9b63a36000278200dea7009882a97387102bc226053073c32f64be6c47d04
$ echo "" | cargo run --quiet -- -p sk.prv ; echo
5934560de918aa1b3318dd1c34480dc7df5f2e6f109c9a1b6ebdb3cb247c14a4b591b0b6077755ca7686cded69568197f09d88aa9b785ee6b07b236ffb0bdaf1298d7e74ec6e8796bc612dafff535606
$ echo "" -n | cargo run --quiet -- -p sk.prv ; echo
41a4f54948b99ea3c45fe419641a010fd82a90416144d0a755661ecf762ea7133e1cc5aa6b640311e99aff2e018affa259bdfa413a351c47906cea1ae525d5d1c2babf3ade313b6125740ef01781980e
```

### How to create an output hash from a proof (<strong>output</strong>)

```console
$ cat sk.prv ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ echo "msg" | cargo run --quiet -- -p sk.prv > proof
$ cat proof ; echo
e654752ea43ba215e37ab17fdd99d678bd4844266cb0a944afa4e6878790a43bc4b3adced6fec2df3b55ac97c3e827e5d1d9b63a36000278200dea7009882a97387102bc226053073c32f64be6c47d04
$ cat proof | cargo run --quiet -- -o ; echo
4c10b27c0ba84c7298801d223090092faa946d459e6768048c27f3683dadaa2165bc51d1f23846febae0965b184fd3dce9bfaa4d60919f7b37a8613c212e19a8

//reading proof from file also works
$ cargo run --quiet -- -o proof ; echo
4c10b27c0ba84c7298801d223090092faa946d459e6768048c27f3683dadaa2165bc51d1f23846febae0965b184fd3dce9bfaa4d60919f7b37a8613c212e19a8
```

### How to verify a proof for a given message using a public key (<strong>output</strong>)

```console
$ cat sk.prv ; echo
a1419b6db73a2eefe4d62fd67022ab5a2b5c310e2323a494cd0ace76d12a17c7
$ cargo run --quiet -- --derive sk.prv > pk.pub
$ cat pk.pub
2929eeeaa6366fd2577fd1e4e0c5bcf1729ddfd51fd6cbb7fe9840a39c7b300e
$ echo "msg" | cargo run --quiet -- -p sk.prv > proof
$ cat proof ; echo
e654752ea43ba215e37ab17fdd99d678bd4844266cb0a944afa4e6878790a43bc4b3adced6fec2df3b55ac97c3e827e5d1d9b63a36000278200dea7009882a97387102bc226053073c32f64be6c47d04
$ cat proof | cargo run --quiet -- -o ; echo
4c10b27c0ba84c7298801d223090092faa946d459e6768048c27f3683dadaa2165bc51d1f23846febae0965b184fd3dce9bfaa4d60919f7b37a8613c212e19a8

//verifying using public key that the proof is created for the same msg
$ echo "msg" | cargo run --quiet -- --verify $(cat proof) pk.pub ; echo
4c10b27c0ba84c7298801d223090092faa946d459e6768048c27f3683dadaa2165bc51d1f23846febae0965b184fd3dce9bfaa4d60919f7b37a8613c212e19a8
```
