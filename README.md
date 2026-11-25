# GRFP Archive Format

GRFP stores lossless recipes with global16 Reed–Solomon parity. It can recover single files or directory trees when enough frames survive. Regrow-8 uses the format to protect circuit recipes. [Regrow-8 protection experiments](https://github.com/quietmaintainer/Regrow-8/blob/main/examples/file_recipe/PROTECTION.md)

## Recovery after damage to both inputs

![Paired damage test at 50% parity. GRFP recovered the original file, inner recipe, and protected archive byte for byte after zeroing 75% of the original and removing 75% of recipe data blocks. The frame deletions removed 49.7% of the whole archive. Recovery succeeded with 16 blocks missing from both and stopped at 17.](docs/images/paired-damage.gif)

With all recipe data blocks erased, GRFP also rebuilt both files from half of the original and 16 surviving parity rows. The test matrix shows how much paired damage was recoverable at each parity setting. [Damage tests and recovery limits](docs/performance.md#damage-to-both-inputs)

## Build and use

```sh
cargo install --path . --locked
grfp pack input.bin archive.grfp --parity 5
grfp recover archive.grfp recovered
```

`pack` creates a global16 archive with 5% parity by default. The percentage counts recipe **frames**, with the budget pooled across the entire archive, including its catalog. `recover` verifies the original and writes `restored.bin`, `recipe.grf`, and a consolidated `protected.grfp` to a new directory. Supply a surviving original with `--damaged path/to/file` to help recover missing groups in an unencrypted single-file archive. [Format details](docs/format.md)

Use `recover-original` to write one file. It verifies the original length and SHA-256 before publishing the output. It uses surviving parity when needed and skips generating the inner recipe file and a new parity archive.

```sh
grfp recover-original archive.grfp output.bin
grfp recover-original archive.grfp output.bin --damaged damaged.bin
```

With `--damaged`, a whole group that matches the archived hash can supply original bytes directly, even if its recipe frame is gone.

## Recovery volumes and block sizes

```sh
grfp pack input.bin archive.grfp --block-size 64KiB --parity 25 --recovery-volumes 1
grfp recover-original archive.grfp restored.bin --volume archive.grfp.rec.001
```

`--block-size` accepts byte counts or sizes such as `64KiB`. Choose a power of two from 4 KiB to 256 KiB. The default is 256 KiB. Smaller blocks can localize damage to less source data, at the cost of more framing and a lower maximum archive size under the GF16 coordinate limit.

`--recovery-volumes N` places all parity rows in numbered companions, up to 64 volumes and one or more rows per volume. Each volume carries a catalog copy. Store volumes on separate drives or locations to reduce shared failure risk. Supply each surviving path with a separate `--volume` on `recover`, `recover-original`, `extract`, `verify`, or `inspect`. With 100% parity and all parity rows available, a volume can serve as the first input when the main archive is gone. Use `reprotect --recovery-volumes N` to split the parity of an existing intact archive.

Each surviving volume covered two missing data blocks in a 24-block test with parity split evenly across three volumes. [Volume-loss test](docs/performance.md#recovery-with-missing-volumes)

## Folders, encryption, and signatures

```sh
grfp keygen-encryption archive.key
grfp keygen-signing signer.key signer.pub
grfp pack project project.grfp --encrypt-key archive.key --sign-key signer.key
grfp verify project.grfp --key archive.key --trusted-key signer.pub
grfp extract project.grfp restored --key archive.key --trusted-key signer.pub
```

A directory input stores its root name, nested UTF-8 filenames, empty directories, modification times, read-only flags, and ordinary Unix permissions where available. Use `--bundle` on a single file to save its name and metadata too. `extract` creates a new directory and restores the saved root inside it, such as `restored/project`. Full `recover` writes the verified bundle stream to `restored.bin`.

Encryption and signing can be enabled separately. Encryption covers the encoded file data and bundle metadata, including filenames. The same secret key file unlocks the archive. Keep it and the signing private key separate from the archive and distribute the signer's public key through a trusted channel. Supply that public key with `--trusted-key` to require a signature from that signer. A valid embedded signature is reported as untrusted until matched against your supplied key.

| Command | Use |
| --- | --- |
| `grfp inspect archive.grfp` | Read the catalog and see which frames survived. |
| `grfp reprotect archive.grfp new.grfp --parity 10` | Change the parity budget of an intact archive while keeping its encoded groups. |
| `grfp protect recipe.grf new.grfp --parity 5` | Add global16 parity to an extracted unencrypted inner recipe. Pass the original encoder options. |
| `grfp restore recipe.grf output.bin` | Restore from the verified inner recipe. |
| `grfp repair recipe.grf damaged.bin output.bin` | Restore from the inner recipe and reuse hash-verified pages from the damaged file. |

The reader supports the GRF1 archives used by Regrow-8 and the newer layouts described in the format reference. When rebuilding a missing wire group from the original alone, GRFP verifies that the encoder reproduces the expected wire checksum. [Format details](docs/format.md)

## Test and benchmark

```sh
cargo test --release --locked
cargo run --release --locked --example benchmark
```

The compatibility tests erase frames from the published Regrow-8 CPU and ALU archives and verify the recovered bytes. The suite also tests recovery from separate volumes, encrypted bundles, signature verification, and metadata restoration. The benchmark checks parity and exact file recovery on matched fixtures. [Performance](docs/performance.md)

## Origin and license

GRFP came from the Automaton Worm file-recipe experiments via Automaton Swarm. The repository carries the original MIT notice crediting Automaton Worm contributors. [License](LICENSE)
