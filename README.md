# Verifiable Random Function (VRF)

The repo contains the implementations of draft VRF preceding the ratified standard
[rfc9381](https://datatracker.ietf.org/doc/rfc9381/). Namely,
the implementation of the verifiable random function presented in
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2.

The implementation [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) is
used as a VRF solution in haskell node, ie., [Praos](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-praos/src/Cardano/Crypto/VRF/Praos.hs).
The current implementation to be used, aka **VRF-03**, is tested against both draft standard test vectors and test vectors generated in cardano-base.
As a consequence the crate is compatible with
the **VRF-03** [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium) that is FFIed in cardano-base.

It is possible that the next VRF version is going to be RFC-9381 compatible.
If the next VRF is chosen to be deployed as the next VRF the repo is going to support and be strictly compatible with it.

**DISCLAIMER**: this crate is still under active development and could be used at own risk.

## What is VRF?

VRF is the public-key pseudorandom function that provides a proof, in a non-interactive manner, for the correctness of its output.
Only the holder of the private VRF key is able to compute the output, along with the proof of its correctness.
The proof convinces the verifier, the party that has access to the public key of the VRF, that the output is indeed correct.

The idea was invented by [Micali, Rabin, Vadhan](https://ieeexplore.ieee.org/document/814584/) and was aimed to provide deterministic pre-commitments for low entropy inputs which
must be resistant to brute-force pre-image attacks. The VRF can be used for defense against offline enumeration attacks (such as dictionary attacks) on data stored in hash-based data structures.
See [Goldberg, Vcelak, Papadopoulos, Reyzin](https://open.bu.edu/server/api/core/bitstreams/7a1c4233-d789-4790-90a8-35ff39aea26a/content).
The initial constructions were having significant drawbacks, for example, proofs and keys of VRFs were linear in the input size.
[Dodis and Yampolskiy](https://eprint.iacr.org/2004/310.pdf) introduced technique that allowed the usage of constant size proofs and keys.
The [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) relies on this breakthrough.

It's a crucial cryptographic primitive for various applications, such as generating random numbers for lotteries and
ensuring secure and unpredictable leader selection in proof-of-stake blockchain networks.

## VRF in cardano

The rationale behind using it in Cardano is presented in [Ouroboros Praos paper](https://iohk.io/en/research/library/papers/ouroboros-praos-an-adaptively-secure-semi-synchronous-proof-of-stake-protocol/)
and later refined in [Consensus specification](https://ouroboros-consensus.cardano.intersectmbo.org/assets/files/consensus-spec-7378c9844defdc1b18f69b89206e3a9b.pdf).

The VRF is used in two paticular contexts:
1. Leader Election, where a VRF output/proof is used to verify that a party is selected to generate a block
2. Random Beacon, where a VRF output/proof is used to generate randomness for leader election in the next epoch

### Technical details of VRF usage in cardano

It is worth mentioning, in a nutshell, how exactly VRF is used in the cardano consensus.
It is succintly presented in Fig. 2 of [Ouroboros Praos paper](https://iohk.io/en/research/library/papers/ouroboros-praos-an-adaptively-secure-semi-synchronous-proof-of-stake-protocol/).

VRF is used as the core randomness generating scheme in Praos.
Having a VRF secret key and an input, one is able to output a pseudorandom number and the proof of the correctness of this output generation.
Anyone with the corresponding public key and the proof can verify that the number was produced with the expected input.
On the another hand, the holder of public key cannot do it before that time.

In Praos, each block **B** has an agreed **nounce** that must be used as an input for each participant, **P**, to his VRF.
For a slot number **sl**, each participant **P** uses his VRF and the **nounce** and generate
random number. If the random number is smaller than a threshold value computed from his relative stake, then they are the leader of a given slot.
As the VRF computation is independent between participants, we can have multiple leaders or none.
The following code snippet embodies this stage:

```code
let t = threshold_compute(pool_stake);

for sl in slots_in_epoch {
    let input = nounce ++ sl ++ "TEST";
    let (output, proof) = VRF.prove(SK, input);
    if y < t then {
        prepare_for_generating_block(sl, output, proof)
    }
}
```

If the participant, **P**, is chosen to generate the block, VRF.prove is run like above, but with _NOUNCE_ instead of _TEST_.
The resultant **output** and **proof** are put into the block header.

When the epoch is coming to an end, from **16k** slots (out of **24k** that make each epoch, **k** is security parameter) **outputs** are extracted,
concatenated along with the **nounce**. Then the hash of that concatenated payload is taken and the next epoch **nounce** is determined that way.
Each participant also updates his threshold value to be valid in the next epoch.

## Command-Line

`pallas_vrf` comes with a command-line interface for Linux. The command-line is self explanatory by using `--help` on various commands and sub-commands.

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

## Performance

### Benchmarks

We ran our benchmarks using `RUSTFLAGS='-C target-cpu=native` cargo bench with an `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` cpu.
The results are following:

```text
   VRF03 aka Praos/Generation              time:   [175.17 us 175.76 us 176.60 us]
   VRF10 aka Praos//Verification           time:   [128.33 us 128.60 us 128.91 us]
```
