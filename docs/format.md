# GRP1 wire format

`.grfp` files wrap the exact encoded groups of a GRF1 or compatible GRL recipe. GRP1 identifies the outer frame format.

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

The UTF-8 JSON catalog describes the original length and SHA-256, the inner recipe's footer digest, the parity layout and percentage, and the encoder profile. For each group it records the wire length, the original-group identifier, and the wire SHA-256. The GRF1 group identifier is its original SHA-256. In protected GRL it is the SHA-256 of the ordered page hashes, and the catalog also carries the exact inner header.

GRF1 groups cover up to 256 KiB of original data. A protected GRL group is a checkpoint record, including its length prefix. `grl-checkpoint-v1` covers the independent 256/256 GRL1 layout and restartable GRL2–GRL4. `grf1-group-v1` carries the GRF1 encoding profile.

## Parity layouts

Both layouts use systematic Cauchy Reed–Solomon parity. A short shard is zero-extended for arithmetic and stored at its true length. A tail catalog is stored as a type-0 frame with index zero.

- **Local GF(2⁸).** The catalog's `stripe` field is 100. A type-0 catalog precedes the data as well. For each stripe, type-1 frames carry groups at their absolute indexes, followed by type-2 parity frames at the first index of the stripe plus the parity ordinal. A stripe of `k` groups gets `ceil(k × percent / 100)` parity frames, each as long as the largest wire in that stripe. The field polynomial is `0x11d` and the coefficient for local group `i` and parity row `p` is `1 / ((100 + p) XOR i)`.
- **Global GF(2¹⁶).** The catalog's `stripe` field is `global16`. The systematic shards are the length-prefixed catalog, split into 64 KiB pieces, followed by the recipe groups. The catalog length is a four-byte little-endian integer. Type-3 systematic frames precede type-4 parity frames. The index packs the total systematic count `d` in the high 16 bits and the shard or parity ordinal in the low 16 bits. For `k` recipe groups, `r = ceil(k × percent / 100)`, with `d + r ≤ 65,535`. The field polynomial is `0x1100b` and the coefficient is `1 / ((d + p) XOR i)`. Adjacent bytes form a little-endian symbol, with a zero high byte for an odd tail. The global symbol interval is the largest systematic shard length rounded up to an even byte count.

Both layouts accept a whole-number parity percentage from 0 to 100. A global archive with `r` parity rows covers any `r` complete frame erasures, including losses that affect the catalog. With local parity, each stripe must have enough parity for its own losses and a catalog copy must survive. A verified surviving original group can supply an extra equation if its encoder reproduces the exact wire.

The reader verifies rebuilt group digests, the inner recipe footer, and the full original SHA-256 before publishing recovered outputs. See the frame types, bounds, and codec rules in the reference source. [Frame reader](../src/frames.mjs) · [Protection and recovery](../src/protected.mjs)
