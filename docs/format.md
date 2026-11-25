# GRP1 wire format

`.grfp` wraps encoded recipe groups in the GRP1 frame format. The Rust implementation uses the `global16` layout.

## Frame header

Every frame starts with an 81-byte header. Integer fields are unsigned little-endian.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | Sync marker `47 52 50 31 0d 0a 1a 0a` |
| 8 | 1 | Frame type |
| 9 | 4 | Index or packed coordinate |
| 13 | 4 | Payload size in bytes |
| 17 | 32 | Archive ID, the SHA-256 of the exact catalog JSON bytes |
| 49 | 32 | SHA-256 of header bytes 8–48 followed by the payload |
| 81 | Variable | Payload |

The reader accepts a frame after verifying its header, length, and digest. After corrupt bytes, it searches for the next sync marker and checks the candidate frame. Frame coordinates let recovery find surviving pieces after deletions or reordering. SHA-256 provides integrity checks for accidental damage.

## Catalog and inner recipe

The UTF-8 JSON catalog describes the original length, the inner recipe's footer digest, the `global16` layout, the parity percentage, and the encoder profile. In plaintext archives it includes the original SHA-256. Each group entry records its wire length, original-group SHA-256, and wire SHA-256. The inner group encoding is `grf1-group-v1`.

The optional `blockSize` field gives the number of original bytes per recipe group, with a 256 KiB default. Allowed values are powers of two from 4 KiB through 256 KiB. A GRF1 inner header is `GRF1` followed by the eight-byte original length. A GRF2 header uses `GRF2`, the original length, and a four-byte block size for a non-default block size. Both are followed by recipe groups and a 32-byte SHA-256 of the header and encoded groups.

The systematic shards are the length-prefixed catalog, split into 64 KiB pieces, followed by the recipe groups. The catalog length prefix is a four-byte little-endian integer. The index packs the total systematic count `d` in the high 16 bits and the shard or parity ordinal in the low 16 bits. A single-file archive stores type-3 systematic frames, then type-4 parity frames, then a type-0 catalog copy with index zero.

## Separate recovery volumes

Split archives keep their systematic frames and type-0 catalog in the primary file. Volume `v`, numbered from one, holds parity rows whose zero-based ordinal modulo the volume count equals `v - 1`. Each volume has its own type-0 copy of the same catalog. Distribution leaves frame coordinates and the archive ID intact. A reader can assemble frames from all supplied paths that match that ID. Full recovery emits the consolidated layout.

For split archives, the reported `protectedBytes` and `protectedSha256` cover the primary file. `parityFrames` and `parityPayloadBytes` cover all recovery volumes together.

## GF16 recovery

The code uses systematic Cauchy Reed–Solomon over GF(2¹⁶), with field polynomial `0x1100b` and coefficient `1 / ((d + p) XOR i)` for parity row `p` and data coordinate `i`. Adjacent bytes form a little-endian symbol. The high byte of an odd tail is zero. The parity width is the largest systematic shard length rounded up to an even byte count. Short shards are zero-extended for arithmetic and stored at their true length.

For `k` recipe groups, the parity row count is `r = ceil(k × percent / 100)`, with `d + r ≤ 65,535`. The parity percentage is a whole number from 0 to 100. An archive with `r` rows covers any `r` complete frame erasures, including losses that affect the catalog. A single damaged byte can invalidate an entire frame. A verified surviving original group can supply an extra equation when the encoder reproduces the expected wire checksum.

Full recovery verifies group hashes, the inner recipe footer, and the full original SHA-256 before publishing results. It retains the exact catalog bytes and regenerates the parity and frames. Original-only recovery and extraction verify the reconstructed payload and use parity for missing groups. [Frame reader](../src/frames.rs) · [GF16 kernel](../src/gf16.rs) · [Recovery](../src/archive.rs)

## Directory and named-file bundles

The catalog sets `bundle` to true when the original payload is a GRB1 bundle. A bundle starts with `GRB1` and a four-byte manifest length. The UTF-8 JSON manifest lists the root entry and its descendants in parent-first order. Each entry gives a slash-delimited portable path, its file or directory kind, its byte count, modification time as Unix seconds and nanoseconds, its read-only flag, and optional ordinary Unix permission bits. File contents follow in manifest order. Extraction validates the paths and lengths and restores permissions and timestamps before placing the tree in a fresh destination.

## Encryption

An encrypted archive uses the `GRFE` inner header with the original length and block size. The catalog's `encryption.salt` is 32 random bytes in hexadecimal. HKDF-SHA256 derives a content key from the 32-byte secret file using that salt and the byte string `GRFP ChaCha20-Poly1305 key v1\0` as HKDF info. Each encoded recipe group uses ChaCha20-Poly1305 with its 16-byte tag appended. The 12-byte nonce is four zero bytes followed by the eight-byte zero-based group index. Associated data is the eight-byte original length, four-byte block size, and one byte for the bundle flag. Integers are little-endian. [Authenticated encryption](https://www.rfc-editor.org/rfc/rfc8439.html) · [HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)

The archive seals the 32-byte original SHA-256 with nonce index `2^64 - 1` and stores it in `encryption.originalDigest` as a byte array. The public `originalSha256` field is omitted and the group entries carry `null` in place of raw group SHA-256. Parity covers the ciphertext and its tags. The public catalog still exposes the payload length, encoded block lengths, and recovery geometry. Use a GRFP archive and its key to restore GRFE content.

## Signatures

The optional `signature` field stores a hex-encoded 32-byte Ed25519 public key and a 64-byte signature array. The signed message is the byte string `GRFP Ed25519 catalog v1\0` followed by the SHA-256 of the exact canonical catalog JSON with its `signature` field omitted. The signed catalog binds the indexed wire checksums, payload identity, and recovery settings. `inspect --trusted-key` checks the signature against an independently supplied key. `verify` also reconstructs and checks the entire payload, using the encryption key when applicable. Changing a signed archive's parity percentage requires signing a fresh catalog. [Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html) · [Implementation](../src/security.rs)
